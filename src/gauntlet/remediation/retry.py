"""M4.2 bounded provider feedback and M4.1 proof orchestration."""
import hashlib
import json
from pathlib import Path
import re
from time import monotonic
from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4

from gauntlet.llm.nebius import NEMOTRON_LIGHTNING_MODEL, QWEN_35_MODEL
from gauntlet.remediation.candidate_artifact import (
    CANDIDATE_ARTIFACT_SCHEMA_VERSION, CandidateArtifactReference,
    candidate_artifact_location, persist_candidate_artifact,
)
from gauntlet.remediation.context import build_source_context
from gauntlet.remediation.models import (
    GeneratedRepairCandidate, RemediationRequest, RepairContext, RepairFailure,
    RepairProposal,
)
from gauntlet.remediation.parsing import parse_generated_repair_candidate
from gauntlet.remediation.provider import RetryRemediationProvider
from gauntlet.remediation.retry_models import (
    RepairAttempt, RepairRunFailed, RepairRunResult, RepairRunSucceeded,
    SafeProviderCompletion,
)
from gauntlet.remediation.run_evidence import persist_repair_run
from gauntlet.remediation.validation import validate_candidate
from gauntlet.sandbox.m4_executor import M41RepairExecutor
from gauntlet.sandbox.m4_models import PatchProof
from gauntlet.sandbox.workspace import repository_digest
from gauntlet.tracing.models import AttackTrace


MAX_PROVIDER_ATTEMPTS = 3
FEEDBACK_FIELD_LIMIT = 8_000
APPROVED_LIVE_REMEDIATION_MODELS = frozenset({
    NEMOTRON_LIGHTNING_MODEL,
    QWEN_35_MODEL,
})
_SECRET = re.compile(
    r"(?i)((?:api[_-]?key|authorization|access[_-]?token|password|secret)"
    r"\s*[=:]\s*['\"]?)[^\s'\"]+"
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _safe_text(value: object, limit: int = FEEDBACK_FIELD_LIMIT) -> str:
    text = str(value)
    text = _SECRET.sub(r"\1[REDACTED]", text)
    text = re.sub(
        r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text
    )
    return text[:limit]


def _candidate_identity(
    candidate: GeneratedRepairCandidate,
) -> tuple[str, dict[str, str], dict[str, int]]:
    fields = candidate.model_dump(mode="json")
    return (
        _digest(candidate.model_dump_json()),
        {
            name: _digest(json.dumps(value, ensure_ascii=True))
            for name, value in fields.items()
        },
        {
            name: len(value) if isinstance(value, str) else len(
                json.dumps(value, ensure_ascii=True, separators=(",", ":"))
            )
            for name, value in fields.items()
        },
    )


def _safe_value(value: object) -> object:
    if isinstance(value, str):
        return _safe_text(value)
    if isinstance(value, list):
        return [_safe_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _safe_value(item) for key, item in value.items()}
    return value


def _safe_candidate(candidate: GeneratedRepairCandidate | None) -> dict[str, object]:
    if candidate is None:
        return {
            "rationale": None, "source_edit": None, "regression_test": None,
            "optional_policy_artifact": None,
        }
    return _safe_value(candidate.model_dump(mode="json"))


_STAGE_GUIDANCE = {
    "candidate_validation": "Previous candidate content failed deterministic validation.",
    "regression_syntax": "Previous regression test failed Python parsing.",
    "regression_structure": "Previous regression test lacked the required test structure.",
    "patch_format": "Previous patch was not a valid authorized unified diff.",
    "patch_authorization": "Previous patch exceeded or failed the authorized target scope.",
    "source_identity": "Proposal did not match the trusted source revision.",
    "patch_apply": "Previous patch could not be applied to the authorized source revision.",
    "compile": "Previous patch caused compilation failure.",
    "regression_execution": "Generated regression test failed when executed.",
    "security_test": "Patched system still failed the P100 security verification.",
    "utility_test": "Patch broke legitimate P200 behavior.",
    "existing_suite": "Patch caused existing compatible tests to fail.",
}


def build_failure_feedback(
    request: RemediationRequest,
    failure: RepairFailure,
    *,
    attempt: int,
    candidate_digest: str,
) -> dict[str, object]:
    """Create bounded redacted feedback suitable for another model call."""
    diagnostics = {
        key: (_safe_text(value, 2_000) if isinstance(value, str) else value)
        for key, value in failure.diagnostics.items()
    }
    return {
        "security_objective": (
            "Prevent indirect prompt injection across the recorded untrusted "
            "tool-data boundary while preserving legitimate P200 behavior."
        ),
        "authorized_target": request.repair_context.target_path,
        "authorized_symbol": request.repair_context.target_symbol,
        "source_hash": request.repair_context.source_hash,
        "previous_attempt": attempt,
        "previous_candidate_digest": candidate_digest,
        "failure_id": failure.failure_id,
        "failure_stage": failure.failure_stage,
        "failure_code": failure.failure_code,
        "failure_summary": _STAGE_GUIDANCE[failure.failure_stage],
        "message": _safe_text(failure.message, 500),
        "diagnostics": diagnostics,
    }


def _provider_metadata(provider: RetryRemediationProvider) -> SafeProviderCompletion | None:
    getter = getattr(provider, "safe_completion_metadata", None)
    if not callable(getter):
        return None
    value = getter()
    if value is None or isinstance(value, SafeProviderCompletion):
        return value
    return SafeProviderCompletion.model_validate(value)


class M42RepairOrchestrator:
    def __init__(
        self,
        repository_root: Path,
        provider: RetryRemediationProvider,
        *,
        executor_factory: Callable[[Path], M41RepairExecutor] | None = None,
    ):
        self.repository_root = repository_root.resolve(strict=True)
        if provider.model_name not in APPROVED_LIVE_REMEDIATION_MODELS:
            raise ValueError(
                "M4.2 requires an explicitly approved live remediation model"
            )
        self.provider = provider
        self.executor_factory = executor_factory or M41RepairExecutor

    def _request(self, serialized_trace: str) -> RemediationRequest:
        trace = AttackTrace.model_validate_json(serialized_trace)
        source = build_source_context(serialized_trace, self.repository_root)
        context = RepairContext(
            trace_id=source.trace_id,
            boundary_id=source.boundary_id,
            evidence_ids=source.evidence_ids,
            provider=self.provider.provider_name,
            model=self.provider.model_name,
            target_path=source.repository_relative_path,
            target_symbol=source.target_symbol,
            source_hash=source.source_hash,
            failure_type="indirect_prompt_injection",
        )
        return RemediationRequest(
            source_context=source,
            repair_context=context,
            evidence_summary={
                "verdict": trace.verdict,
                "boundary_type": trace.failure_boundary.boundary_type,
                "evidence_strength": trace.evidence.get("strength", "UNKNOWN"),
            },
        )

    def _synthetic_failure(
        self,
        request: RemediationRequest,
        *,
        attempt: int,
        raw: str,
        code: str,
        message: str,
        error: Exception,
    ) -> RepairFailure:
        return RepairFailure(
            candidate_digest=_digest(raw),
            candidate_field_digests={},
            candidate_field_lengths={},
            trace_id=request.repair_context.trace_id,
            boundary_id=request.repair_context.boundary_id,
            evidence_ids=request.repair_context.evidence_ids,
            provider=request.repair_context.provider,
            model=request.repair_context.model,
            target_path=request.repair_context.target_path,
            target_symbol=request.repair_context.target_symbol,
            source_hash=request.repair_context.source_hash,
            failure_type=request.repair_context.failure_type,
            failure_stage="candidate_validation",
            failure_code=code,
            message=message,
            diagnostics={
                "error_type": type(error).__name__,
                "detail": _safe_text(error, 2_000),
            },
            attempt=attempt,
        )

    def _duplicate_candidate_failure(
        self,
        request: RemediationRequest,
        candidate: GeneratedRepairCandidate,
        *,
        attempt: int,
    ) -> RepairFailure:
        candidate_digest, field_digests, field_lengths = _candidate_identity(candidate)
        return RepairFailure(
            candidate_digest=candidate_digest,
            candidate_field_digests=field_digests,
            candidate_field_lengths=field_lengths,
            trace_id=request.repair_context.trace_id,
            boundary_id=request.repair_context.boundary_id,
            evidence_ids=request.repair_context.evidence_ids,
            provider=request.repair_context.provider,
            model=request.repair_context.model,
            target_path=request.repair_context.target_path,
            target_symbol=request.repair_context.target_symbol,
            source_hash=request.repair_context.source_hash,
            failure_type=request.repair_context.failure_type,
            failure_stage="candidate_validation",
            failure_code="duplicate_candidate",
            message="Retry returned a previously observed candidate unchanged.",
            diagnostics={"candidate_digest": candidate_digest},
            attempt=attempt,
        )

    async def run(
        self,
        serialized_trace: str,
        *,
        evidence_path: Path | None = None,
    ) -> RepairRunResult:
        run_id = str(uuid4())
        started_at = datetime.now(timezone.utc)
        started = monotonic()
        original_digest = repository_digest(self.repository_root)
        request = self._request(serialized_trace)
        attempts: list[RepairAttempt] = []
        previous_failure: RepairFailure | None = None
        previous_candidate: GeneratedRepairCandidate | None = None

        for attempt_number in range(1, MAX_PROVIDER_ATTEMPTS + 1):
            attempt_started_at = datetime.now(timezone.utc)
            attempt_started = monotonic()
            raw = ""
            candidate: GeneratedRepairCandidate | None = None
            proposal: RepairProposal | None = None
            proof: PatchProof | None = None
            failure: RepairFailure | None = None
            provider_call = "PASS"
            candidate_decode = "NOT_RUN"
            candidate_validation = "NOT_RUN"
            proposal_execution = "NOT_RUN"
            patch_proof = "NOT_RUN"
            materialized: dict[str, str] = {}

            try:
                if attempt_number == 1:
                    raw = await self.provider.generate(request)
                else:
                    feedback = build_failure_feedback(
                        request, previous_failure,
                        attempt=attempt_number - 1,
                        candidate_digest=attempts[-1].candidate_digest,
                    )
                    raw = await self.provider.generate_revision(
                        request,
                        previous_candidate=_safe_candidate(previous_candidate),
                        failure_feedback=feedback,
                    )
            except Exception as exc:
                provider_call = "FAIL"
                failure = self._synthetic_failure(
                    request, attempt=attempt_number, raw=raw,
                    code="provider_call_failed",
                    message="The remediation provider call failed safely.", error=exc,
                )
            else:
                try:
                    candidate = parse_generated_repair_candidate(raw)
                    candidate_decode = "PASS"
                except Exception as exc:
                    candidate_decode = "FAIL"
                    failure = self._synthetic_failure(
                        request, attempt=attempt_number, raw=raw,
                        code="candidate_decode_failed",
                        message="Provider content did not decode as a repair candidate.",
                        error=exc,
                    )

            if candidate is not None:
                current_digest, _, _ = _candidate_identity(candidate)
                if any(
                    item.candidate_digest == current_digest for item in attempts
                ):
                    candidate_validation = "FAIL"
                    failure = self._duplicate_candidate_failure(
                        request, candidate, attempt=attempt_number
                    )
                else:
                    validated = validate_candidate(
                        candidate, request.repair_context, self.repository_root,
                        attempt=attempt_number,
                        materialized_output=materialized,
                    )
                    if isinstance(validated, RepairFailure):
                        candidate_validation = "FAIL"
                        failure = validated
                    else:
                        candidate_validation = "PASS"
                        proposal = validated
                        execution = await self.executor_factory(self.repository_root).run(
                            proposal
                        )
                        if isinstance(execution, RepairFailure):
                            candidate_digest, field_digests, field_lengths = (
                                _candidate_identity(candidate)
                            )
                            failure = execution.model_copy(update={
                                "candidate_id": str(uuid4()),
                                "candidate_digest": candidate_digest,
                                "candidate_field_digests": field_digests,
                                "candidate_field_lengths": field_lengths,
                                "attempt": attempt_number,
                            })
                            proposal_execution = "FAIL"
                            patch_proof = "FAIL"
                        else:
                            proof = execution
                            proposal_execution = "PASS"
                            patch_proof = "VERIFIED"

            if candidate is not None:
                candidate_digest, field_digests, field_lengths = _candidate_identity(
                    candidate
                )
            else:
                candidate_digest = failure.candidate_digest
                field_digests = failure.candidate_field_digests
                field_lengths = failure.candidate_field_lengths
            candidate_id = failure.candidate_id if failure else str(uuid4())
            candidate_artifact = None
            if candidate is not None and evidence_path is not None:
                artifact_path, relative_artifact_path = candidate_artifact_location(
                    evidence_path, attempt_number, candidate_id
                )
                artifact = persist_candidate_artifact(
                    candidate,
                    path=artifact_path,
                    candidate_id=candidate_id,
                    run_id=run_id,
                    attempt_number=attempt_number,
                    provider=self.provider.provider_name,
                    model=self.provider.model_name,
                    trace_id=request.repair_context.trace_id,
                    boundary_id=request.repair_context.boundary_id,
                    evidence_ids=request.repair_context.evidence_ids,
                    target_path=request.repair_context.target_path,
                    target_symbol=request.repair_context.target_symbol,
                    source_hash=request.repair_context.source_hash,
                    derived_patch=materialized.get("patch"),
                    derived_regression_test=(
                        materialized.get("regression_test")
                    ),
                )
                candidate_artifact = CandidateArtifactReference(
                    schema_version=CANDIDATE_ARTIFACT_SCHEMA_VERSION,
                    candidate_id=candidate_id,
                    attempt_number=attempt_number,
                    path=relative_artifact_path,
                    candidate_digest=artifact.candidate_digest,
                    integrity_digest=artifact.integrity_digest,
                )
            workspace_id = (
                proof.workspace_id if proof else
                failure.diagnostics.get("workspace_id") if failure else None
            )
            completed_at = datetime.now(timezone.utc)
            attempts.append(RepairAttempt(
                attempt=attempt_number,
                candidate_id=candidate_id,
                previous_failure_id=(
                    previous_failure.failure_id if previous_failure else None
                ),
                provider=self.provider.provider_name,
                model=self.provider.model_name,
                candidate_digest=candidate_digest,
                candidate_field_digests=field_digests,
                candidate_field_lengths=field_lengths,
                candidate_artifact=candidate_artifact,
                provider_call=provider_call,
                candidate_decode=candidate_decode,
                candidate_validation=candidate_validation,
                proposal_execution=proposal_execution,
                patch_proof=patch_proof,
                repair_id=proposal.repair_id if proposal else None,
                failure=failure,
                proof_id=proof.proof_id if proof else None,
                workspace_id=str(workspace_id) if workspace_id else None,
                provider_completion=(
                    _provider_metadata(self.provider)
                    if provider_call == "PASS" else None
                ),
                started_at=attempt_started_at,
                completed_at=completed_at,
                duration_seconds=monotonic() - attempt_started,
            ))

            unchanged = repository_digest(self.repository_root) == original_digest
            if proof is not None and unchanged:
                result: RepairRunResult = RepairRunSucceeded(
                    run_id=run_id,
                    trace_id=request.repair_context.trace_id,
                    boundary_id=request.repair_context.boundary_id,
                    evidence_ids=request.repair_context.evidence_ids,
                    provider=self.provider.provider_name,
                    model=self.provider.model_name,
                    total_attempts=attempt_number,
                    successful_attempt=attempt_number,
                    attempts=attempts,
                    final_proposal=proposal,
                    patch_proof=proof,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_seconds=monotonic() - started,
                    original_repository_unchanged=True,
                )
                if evidence_path is not None:
                    persist_repair_run(result, evidence_path)
                return result

            previous_failure = failure
            previous_candidate = candidate

        completed_at = datetime.now(timezone.utc)
        result = RepairRunFailed(
            run_id=run_id,
            trace_id=request.repair_context.trace_id,
            boundary_id=request.repair_context.boundary_id,
            evidence_ids=request.repair_context.evidence_ids,
            provider=self.provider.provider_name,
            model=self.provider.model_name,
            total_attempts=MAX_PROVIDER_ATTEMPTS,
            attempts=attempts,
            final_failure=previous_failure,
            safe_failure_summary=(
                f"{previous_failure.failure_stage}: "
                f"{_safe_text(previous_failure.message, 800)}"
            ),
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=monotonic() - started,
            original_repository_unchanged=(
                repository_digest(self.repository_root) == original_digest
            ),
        )
        if evidence_path is not None:
            persist_repair_run(result, evidence_path)
        return result
