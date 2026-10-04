"""One-request live M7.2 orchestration over existing Gauntlet proof gates."""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from time import monotonic
from typing import Any, Protocol
from uuid import uuid4

import httpx
from pydantic import Field, model_validator

from gauntlet.attacks.indirect_prompt_injection import IndirectPromptInjectionAttack
from gauntlet.llm.nebius import KIMI_K27_CODE_MODEL
from gauntlet.remediation.candidate_artifact import (
    candidate_identity, persist_candidate_artifact,
)
from gauntlet.remediation.context import build_source_context
from gauntlet.remediation.models import (
    GeneratedRepairCandidate, RemediationRequest, RepairContext, RepairFailure,
    StrictModel,
)
from gauntlet.remediation.parsing import parse_generated_repair_candidate
from gauntlet.remediation.retry_models import SafeProviderCompletion
from gauntlet.remediation.validation import validate_candidate
from gauntlet.sandbox.m4_executor import M41RepairExecutor
from gauntlet.sandbox.m4_models import PatchAssessment
from gauntlet.sandbox.m5_executor import M51MutationExecutor
from gauntlet.sandbox.m5_models import AttackMutationAssessment, MutationPatchInput
from gauntlet.sandbox.workspace import repository_digest
from gauntlet.tracing.models import AttackTrace
from victims.customer_support.app import create_app


LIVE_EVIDENCE_VERSION = "gauntlet.m7-live-run.v1"
StageCallback = Callable[[str, str, dict[str, object]], None]
_SECRET = re.compile(
    r"(?i)((?:api[_-]?key|authorization|access[_-]?token|password|secret)"
    r"\s*[=:]\s*['\"]?)[^\s'\"]+"
)


class LiveCandidateProvider(Protocol):
    provider_name: str
    model_name: str

    async def generate_live_demo_candidate(self, request: RemediationRequest) -> str: ...
    def safe_completion_metadata(self) -> SafeProviderCompletion | None: ...


class LiveRunEvidence(StrictModel):
    schema_version: str = LIVE_EVIDENCE_VERSION
    run_id: str
    timestamp: datetime
    provider: str
    model: str
    provider_request_count: int = Field(ge=0, le=1)
    provider_completion: SafeProviderCompletion | None = None
    trace_id: str | None = None
    boundary_id: str | None = None
    candidate_id: str | None = None
    candidate_artifact: str | None = None
    candidate_digest: str | None = None
    source_hash: str | None = None
    patch: str | None = None
    patch_digest: str | None = None
    attack_result: str
    candidate_validation: str
    patch_assessment: PatchAssessment | None = None
    mutation_assessment: AttackMutationAssessment | None = None
    final_verdict: str
    failure_stage: str | None = None
    failure_message: str | None = None
    repository_immutability: str
    duration_seconds: float = Field(ge=0)
    integrity_digest: str

    @model_validator(mode="after")
    def valid_integrity(self) -> "LiveRunEvidence":
        if self.schema_version != LIVE_EVIDENCE_VERSION:
            raise ValueError("Unsupported M7.2 evidence schema")
        if self.integrity_digest != _evidence_digest(self):
            raise ValueError("M7.2 live evidence integrity failed")
        return self


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _evidence_digest(evidence: LiveRunEvidence) -> str:
    payload = evidence.model_dump(mode="json", exclude={"integrity_digest"})
    return _digest(json.dumps(payload, ensure_ascii=True, sort_keys=True,
                              separators=(",", ":")))


def safe_live_message(value: object) -> str:
    text = _SECRET.sub(r"\1[REDACTED]", str(value))
    text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+",
                  "Bearer [REDACTED]", text)
    return text[:1_000]


def _request(serialized_trace: str, root: Path,
             provider: LiveCandidateProvider) -> RemediationRequest:
    trace = AttackTrace.model_validate_json(serialized_trace)
    source = build_source_context(serialized_trace, root)
    context = RepairContext(
        trace_id=source.trace_id, boundary_id=source.boundary_id,
        evidence_ids=source.evidence_ids, provider=provider.provider_name,
        model=provider.model_name, target_path=source.repository_relative_path,
        target_symbol=source.target_symbol, source_hash=source.source_hash,
        failure_type="indirect_prompt_injection",
    )
    return RemediationRequest(
        source_context=source, repair_context=context,
        evidence_summary={
            "verdict": trace.verdict,
            "boundary_type": trace.failure_boundary.boundary_type,
            "evidence_strength": trace.evidence.get("strength", "UNKNOWN"),
        },
    )


def _emit(callback: StageCallback | None, stage: str, status: str,
          **details: object) -> None:
    if callback is not None:
        callback(stage, status, details)


class M72LiveOrchestrator:
    """Run one model request, then delegate every decision to M3/M4/M5 gates."""

    def __init__(self, repository_root: Path, provider: LiveCandidateProvider, *,
                 m4_factory: Callable[[Path], M41RepairExecutor] = M41RepairExecutor,
                 m5_factory: Callable[[Path], M51MutationExecutor] = M51MutationExecutor):
        self.root = repository_root.resolve(strict=True)
        self.provider = provider
        if provider.provider_name != "nebius_token_factory":
            raise ValueError("M7.2 live mode requires the Nebius provider path")
        if provider.model_name != KIMI_K27_CODE_MODEL:
            raise ValueError("M7.2 live mode requires Kimi K2.7 Code")
        self.m4_factory = m4_factory
        self.m5_factory = m5_factory

    async def run(self, *, evidence_path: Path,
                  on_stage: StageCallback | None = None) -> LiveRunEvidence:
        run_id = str(uuid4())
        started = monotonic()
        before_digest = repository_digest(self.root)
        request_count = 0
        request: RemediationRequest | None = None
        candidate: GeneratedRepairCandidate | None = None
        candidate_id: str | None = None
        candidate_digest: str | None = None
        patch: str | None = None
        patch_digest: str | None = None
        artifact_relative: str | None = None
        assessment: PatchAssessment | None = None
        mutations: AttackMutationAssessment | None = None
        attack_result = "NOT_RUN"
        validation = "NOT_RUN"
        verdict = "NOT_VERIFIED"
        failure_stage: str | None = None
        failure_message: str | None = None

        try:
            _emit(on_stage, "ATTACK", "RUNNING")
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=create_app()),
                base_url="http://m7-local",
            ) as client:
                before = await IndirectPromptInjectionAttack(client).run()
            if before.trace is None or not before.succeeded:
                attack_result = "FAILED"
                failure_stage = "ATTACK"
                failure_message = "Vulnerable P100 did not reproduce."
                _emit(on_stage, "ATTACK", "FAILED")
                return self._persist(evidence_path, run_id, started, before_digest,
                                     request_count, request, candidate_id,
                                     candidate_digest, artifact_relative, patch,
                                     patch_digest, attack_result, validation,
                                     assessment, mutations, verdict, failure_stage,
                                     failure_message)
            attack_result = "REPRODUCED"
            _emit(on_stage, "ATTACK", "REPRODUCED")
            request = _request(before.trace.model_dump_json(), self.root, self.provider)
            _emit(on_stage, "DIAGNOSE", "COMPLETE",
                  trace_id=request.repair_context.trace_id,
                  boundary_id=request.repair_context.boundary_id)

            _emit(on_stage, "AI_PATCH", "REQUESTING_MODEL")
            request_count = 1
            provider_started = monotonic()
            raw = await self.provider.generate_live_demo_candidate(request)
            provider_latency_seconds = monotonic() - provider_started
            try:
                candidate = parse_generated_repair_candidate(raw)
            except Exception as exc:
                validation = "FAIL"
                failure_stage = "VALIDATE"
                failure_message = "Candidate rejected: " + safe_live_message(exc)
                _emit(
                    on_stage, "AI_PATCH", "CANDIDATE_RECEIVED",
                    provider_latency_seconds=provider_latency_seconds,
                )
                _emit(on_stage, "VALIDATE", "FAIL")
                return self._persist(
                    evidence_path, run_id, started, before_digest, request_count,
                    request, candidate_id, candidate_digest, artifact_relative,
                    patch, patch_digest, attack_result, validation, assessment,
                    mutations, verdict, failure_stage, failure_message,
                )
            candidate_id = str(uuid4())
            candidate_digest, field_digests = candidate_identity(candidate)
            _emit(
                on_stage, "AI_PATCH", "CANDIDATE_RECEIVED",
                provider_latency_seconds=provider_latency_seconds,
            )

            _emit(on_stage, "VALIDATE", "RUNNING")
            materialized: dict[str, object] = {}
            proposal = validate_candidate(candidate, request.repair_context, self.root,
                                          materialized_output=materialized)
            if isinstance(proposal, RepairFailure):
                validation = "FAIL"
                failure_stage = "VALIDATE"
                failure_message = proposal.message
                _emit(
                    on_stage, "VALIDATE", "FAIL",
                    failure_stage=proposal.failure_stage,
                    failure_code=proposal.failure_code,
                    message=proposal.message,
                )
            else:
                validation = "PASS"
                patch = proposal.patch
                patch_digest = _digest(patch)
                regression = proposal.regression_test
                candidate_path = evidence_path.parent / (
                    f"{evidence_path.stem}.candidates/{candidate_id}.json"
                )
                artifact = persist_candidate_artifact(
                    candidate, path=candidate_path, candidate_id=candidate_id,
                    run_id=run_id, attempt_number=1,
                    provider=self.provider.provider_name, model=self.provider.model_name,
                    trace_id=request.repair_context.trace_id,
                    boundary_id=request.repair_context.boundary_id,
                    evidence_ids=request.repair_context.evidence_ids,
                    target_path=request.repair_context.target_path,
                    target_symbol=request.repair_context.target_symbol,
                    source_hash=request.repair_context.source_hash,
                    derived_patch=patch, derived_regression_test=regression,
                )
                artifact_relative = candidate_path.relative_to(
                    evidence_path.parent).as_posix()
                _emit(on_stage, "VALIDATE", "PASS", patch=patch,
                      patch_digest=patch_digest)
                _emit(on_stage, "SANDBOX", "APPLYING")
                assessment_or_failure = await self.m4_factory(self.root).run(
                    proposal, candidate_id=candidate_id,
                    candidate_digest=candidate_digest,
                    candidate_field_digests=field_digests,
                    expected_patch_digest=artifact.derived_patch_digest,
                    expected_regression_test_digest=artifact.derived_regression_test_digest,
                )
                if isinstance(assessment_or_failure, RepairFailure):
                    failure_stage = "SANDBOX"
                    failure_message = assessment_or_failure.message
                    _emit(on_stage, "SANDBOX", "FAIL")
                else:
                    assessment = assessment_or_failure
                    if (assessment.candidate_id != candidate_id
                            or assessment.candidate_digest != candidate_digest
                            or assessment.patch_digest != patch_digest):
                        raise ValueError("M4 assessment identity differs from live candidate")
                    _emit(on_stage, "SANDBOX",
                          "PASS" if assessment.build_integrity.status == "PASS" else "FAIL")
                    _emit(on_stage, "RE_ATTACK",
                          "BLOCKED" if assessment.p100_security.status == "PASS"
                          else "LEAKED" if assessment.p100_security.status == "FAIL"
                          else "ERROR")
                    if assessment.build_integrity.status == "PASS":
                        _emit(on_stage, "MUTATE", "RUNNING")
                        mutations = await self.m5_factory(self.root).run(MutationPatchInput(
                            candidate_schema_version=artifact.schema_version,
                            candidate_id=artifact.candidate_id,
                            candidate_digest=artifact.candidate_digest,
                            target_path=artifact.target_path,
                            target_symbol=artifact.target_symbol,
                            source_hash=artifact.source_hash,
                            patch=artifact.derived_patch or "",
                            patch_digest=artifact.derived_patch_digest or "",
                        ))
                        _emit(on_stage, "MUTATE",
                              f"{mutations.blocked_mutation_count}/4 BLOCKED")
                    _emit(on_stage, "UTILITY", assessment.p200_utility.status)
                    verified = bool(
                        assessment.full_candidate_verified
                        and mutations is not None and mutations.verified
                    )
                    verdict = "VERIFIED" if verified else "NOT_VERIFIED"
                    if not verified:
                        failure_stage, failure_message = self._failed_gate(
                            assessment, mutations)
                    _emit(on_stage, "PROVE", verdict)
        except Exception as exc:
            failure_stage = failure_stage or (
                "AI_PATCH" if request_count else "ATTACK"
            )
            failure_message = safe_live_message(exc)
            _emit(on_stage, failure_stage, "FAILED", message=failure_message)

        return self._persist(evidence_path, run_id, started, before_digest,
                             request_count, request, candidate_id, candidate_digest,
                             artifact_relative, patch, patch_digest, attack_result,
                             validation, assessment, mutations, verdict,
                             failure_stage, failure_message)

    @staticmethod
    def _failed_gate(assessment: PatchAssessment,
                     mutations: AttackMutationAssessment | None) -> tuple[str, str]:
        checks = (
            (assessment.build_integrity.status, "SANDBOX", "sandbox validation failed"),
            (assessment.p100_security.status, "RE_ATTACK", "original attack still succeeds"),
            (assessment.p200_utility.status, "UTILITY", "legitimate utility regressed"),
            (assessment.compatibility.status, "UTILITY", "compatibility regressed"),
            (assessment.generated_regression.status, "VALIDATE", "generated regression failed"),
        )
        for status, stage, message in checks:
            if status != "PASS":
                return stage, message
        if mutations is None or not mutations.verified:
            return "MUTATE", "mutation bypass detected"
        return "PROVE", "candidate did not satisfy every verification condition"

    def _persist(self, path: Path, run_id: str, started: float,
                 original_digest: str, request_count: int,
                 request: RemediationRequest | None, candidate_id: str | None,
                 candidate_digest: str | None, artifact: str | None,
                 patch: str | None, patch_digest: str | None,
                 attack: str, validation: str,
                 assessment: PatchAssessment | None,
                 mutations: AttackMutationAssessment | None, verdict: str,
                 failure_stage: str | None,
                 failure_message: str | None) -> LiveRunEvidence:
        unchanged = repository_digest(self.root) == original_digest
        values: dict[str, Any] = {
            "run_id": run_id, "timestamp": datetime.now(timezone.utc),
            "provider": self.provider.provider_name,
            "model": self.provider.model_name,
            "provider_request_count": request_count,
            "provider_completion": self.provider.safe_completion_metadata(),
            "trace_id": request.repair_context.trace_id if request else None,
            "boundary_id": request.repair_context.boundary_id if request else None,
            "candidate_id": candidate_id, "candidate_artifact": artifact,
            "candidate_digest": candidate_digest,
            "source_hash": request.repair_context.source_hash if request else None,
            "patch": patch, "patch_digest": patch_digest,
            "attack_result": attack, "candidate_validation": validation,
            "patch_assessment": assessment, "mutation_assessment": mutations,
            "final_verdict": verdict, "failure_stage": failure_stage,
            "failure_message": failure_message,
            "repository_immutability": "PASS" if unchanged else "FAIL",
            "duration_seconds": monotonic() - started,
        }
        provisional = LiveRunEvidence.model_construct(
            **values, integrity_digest="0" * 64,
            schema_version=LIVE_EVIDENCE_VERSION,
        )
        evidence = LiveRunEvidence(
            **values, integrity_digest=_evidence_digest(provisional),
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(evidence.model_dump_json(indent=2) + "\n")
        return evidence
