"""Three-stage P400 live experiment with deterministic final authority."""

import hashlib
import importlib.util
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Protocol
from uuid import uuid4

from pydantic import Field, model_validator

from gauntlet.contracts.models import (
    ContractEvaluation,
    ContractStatus,
    NormalizedEventType,
    StrictModel,
)
from gauntlet.contracts.p400 import evaluate_p400, p400_contract
from gauntlet.contracts.p400_live import (
    P400_LIVE_MAX_TOKENS,
    P400_LIVE_SYSTEM_PROMPT,
    P400LiveMessage,
    P400LiveProviderReceipt,
)
from gauntlet.contracts.p400_live_repair import (
    P400LiveRepairEvidence,
    verify_all_p400_families,
)
from gauntlet.llm.nebius import (
    NEMOTRON_REASONING_DISABLED,
    NEMOTRON_SUPER_MODEL,
    NebiusTokenFactoryClient,
)
from gauntlet.remediation.context import read_authorized_source_text
from gauntlet.remediation.contract_verification import ContractReverification
from gauntlet.sandbox.m4_runner import M41CommandRunner
from gauntlet.sandbox.workspace import SandboxWorkspace, repository_digest
from victims.personalization.agent import (
    PersonalContextItem,
    PersonalizationExecution,
)
from victims.personalization.fixtures import (
    APP_NAME_PURPOSE,
    CURRENT_USER,
    GENERIC_APP_NAME_REQUEST,
    GENERIC_APP_NAME_REQUEST_ID,
    TAMIL_CULTURAL_CONTEXT,
    TAMIL_CULTURAL_GRANT,
)


P400_NEMOTRON_MODEL = NEMOTRON_SUPER_MODEL
P400_NEMOTRON_BASE_URL = (
    "https://api.tokenfactory.us-central1.nebius.com/v1/"
)
P400_LIVE_PROOF_VERSION = "gauntlet.p400-live-proof.v1"


class P400NemotronProvider:
    """Single-call non-thinking Nemotron adapter for victim execution."""

    provider_name = "nebius_token_factory"

    def __init__(self, client: NebiusTokenFactoryClient) -> None:
        if client.config.model != P400_NEMOTRON_MODEL:
            raise ValueError(f"P400 live attack/proof requires {P400_NEMOTRON_MODEL}")
        if client.config.base_url != P400_NEMOTRON_BASE_URL:
            raise ValueError("P400 Nemotron requires the us-central1 endpoint")
        self.client = client
        self.model_name = client.config.model

    async def generate_response(self, envelope) -> str:
        return await self.client.complete(
            [message.model_dump() for message in envelope.messages],
            reasoning_directive=NEMOTRON_REASONING_DISABLED,
            max_tokens=P400_LIVE_MAX_TOKENS,
        )

    def completion_metadata(self) -> dict[str, Any] | None:
        metadata = self.client.last_response_metadata
        return metadata.as_dict() if metadata is not None else None


class P400LiveProofProvider(Protocol):
    provider_name: str
    model_name: str

    async def generate_response(self, envelope) -> str: ...

    def completion_metadata(self) -> dict[str, Any] | None: ...


class P400ProofContextDecision(StrictModel):
    context_id: str
    decision: Literal["INCLUDED", "EXCLUDED"]
    decided_by: Literal["patched_personalization_agent"]


class P400LiveProofEnvelope(StrictModel):
    run_id: str
    user_request: str
    principal: str
    active_purpose: str
    activated_personalization_dimensions: list[str]
    candidate_context_items: list[PersonalContextItem]
    transmitted_context_items: list[PersonalContextItem]
    inclusion_decisions: list[P400ProofContextDecision]
    messages: list[P400LiveMessage] = Field(min_length=2, max_length=2)

    @model_validator(mode="after")
    def decisions_cover_candidates(self) -> "P400LiveProofEnvelope":
        if [item.context_id for item in self.candidate_context_items] != [
            item.context_id for item in self.inclusion_decisions
        ]:
            raise ValueError("P400 proof decisions must cover candidate context")
        included = [
            item.context_id for item in self.inclusion_decisions
            if item.decision == "INCLUDED"
        ]
        if included != [
            item.context_id for item in self.transmitted_context_items
        ]:
            raise ValueError("P400 proof decisions must match transmitted context")
        return self


class P400LiveProofEvidence(StrictModel):
    schema_version: Literal["gauntlet.p400-live-proof.v1"]
    run_id: str
    created_at: datetime
    execution_mode: Literal["LIVE_PROOF"]
    source_live_repair_run_id: str
    source_patch_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider: str
    model: str
    provider_request_count: Literal[1]
    automatic_retries: Literal[0]
    model_switches: Literal[0]
    model_envelope: P400LiveProofEnvelope
    provider_receipt: P400LiveProviderReceipt
    provider_status: Literal["PASS", "FAIL"]
    provider_error_type: str | None = None
    provider_error: str | None = None
    model_response: str | None = None
    execution: PersonalizationExecution | None = None
    evaluation: ContractEvaluation | None = None
    live_post_repair: Literal["PASS", "FAIL", "NOT_RUN"]
    deterministic_matrix: ContractReverification | None = None
    deterministic_matrix_status: Literal["PASS", "FAIL", "NOT_RUN"]
    final_status: Literal["VERIFIED", "NOT_VERIFIED", "PROVIDER_FAILED"]
    patch_application: Literal["PASS"]
    compilation: Literal["PASS"]
    workspace_cleanup: Literal["PASS", "FAIL"]
    repository_digest_before: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository_digest_after: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository_immutability: Literal["PASS", "FAIL"]
    credential_scan: Literal["PASS"]
    integrity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def coherent_and_integrity_bound(self) -> "P400LiveProofEvidence":
        unchanged = self.repository_digest_before == self.repository_digest_after
        if (self.repository_immutability == "PASS") != unchanged:
            raise ValueError("P400 live proof repository immutability mismatch")
        if self.provider_status == "FAIL":
            if (
                self.final_status != "PROVIDER_FAILED"
                or self.model_response is not None
                or self.live_post_repair != "NOT_RUN"
                or self.deterministic_matrix_status != "NOT_RUN"
                or not self.provider_error_type
            ):
                raise ValueError("provider failure cannot claim P400 proof")
        else:
            if (
                self.model_response is None
                or self.execution is None
                or self.evaluation is None
                or self.deterministic_matrix is None
            ):
                raise ValueError("successful P400 proof requires complete evidence")
            verified = (
                self.live_post_repair == "PASS"
                and self.deterministic_matrix_status == "PASS"
            )
            if (self.final_status == "VERIFIED") != verified:
                raise ValueError("P400 final verdict must bind live and matrix proof")
        if self.integrity_digest != _integrity_digest(self):
            raise ValueError("P400 live proof integrity failed")
        return self


def repair_is_eligible_for_live_proof(evidence: P400LiveRepairEvidence) -> bool:
    assessment = evidence.sandbox_assessment
    return bool(
        evidence.candidate_validation == "PASS"
        and evidence.derived_patch
        and evidence.derived_patch_digest
        and assessment is not None
        and assessment.source_identity == "PASS"
        and assessment.patch_application is not None
        and assessment.patch_application.passed
        and assessment.compilation is not None
        and assessment.compilation.passed
        and evidence.repository_immutability == "PASS"
    )


async def run_live_p400_proof(
    *,
    repair_evidence: P400LiveRepairEvidence,
    provider: P400LiveProofProvider,
    repository_root: Path,
    evidence_directory: Path,
    credential_values: tuple[str, ...] = (),
) -> tuple[P400LiveProofEvidence, Path]:
    """Apply the exact accepted patch, call Nemotron once, then grade it."""
    if provider.model_name != P400_NEMOTRON_MODEL:
        raise ValueError(f"P400 live proof requires {P400_NEMOTRON_MODEL}")
    if not repair_is_eligible_for_live_proof(repair_evidence):
        raise ValueError("P400 live proof requires an accepted compiled live patch")
    assert repair_evidence.derived_patch is not None
    assert repair_evidence.derived_patch_digest is not None

    root = repository_root.resolve(strict=True)
    before = repository_digest(root)
    run_id = str(uuid4())
    workspace = SandboxWorkspace(root)
    provider_status: Literal["PASS", "FAIL"] = "FAIL"
    provider_error_type = provider_error = None
    response = None
    execution = None
    evaluation = None
    matrix = None
    envelope = None
    receipt = P400LiveProviderReceipt(latency_seconds=0)
    application_status = compilation_status = "PASS"

    try:
        with workspace:
            assert workspace.path is not None
            source_contexts = getattr(
                repair_evidence.contract_request, "source_contexts", None
            ) or [repair_evidence.contract_request.source_context]
            for source_context in source_contexts:
                _, source = read_authorized_source_text(
                    workspace.path,
                    target_path=source_context.repository_relative_path,
                    target_symbol=source_context.target_symbol,
                )
                if (
                    hashlib.sha256(source.encode()).hexdigest()
                    != source_context.source_hash
                ):
                    raise ValueError("P400 proof source identity mismatch")
            patch_path = workspace.resolve_relative(".gauntlet/p400-live-proof.patch")
            patch_path.parent.mkdir(parents=True, exist_ok=True)
            patch_path.write_text(repair_evidence.derived_patch)
            runner = M41CommandRunner()
            applied = await runner.apply_patch(workspace, patch_path)
            if not applied.passed:
                raise ValueError("P400 accepted patch no longer applies")
            compiled = await runner.compile(workspace)
            if not compiled.passed:
                raise ValueError("P400 accepted patch no longer compiles")

            agent_class = _load_patched_agent(workspace.path)
            preview = _execute_patched(agent_class, run_id, "pending live response")
            included_ids = _context_ids_reaching_output(preview)
            transmitted = [
                item for item in (TAMIL_CULTURAL_CONTEXT,)
                if item.context_id in included_ids
            ]
            envelope = _proof_envelope(
                run_id=run_id, transmitted=transmitted,
            )
            started = time.perf_counter()
            try:
                response = await provider.generate_response(envelope)
            except Exception as error:
                receipt = _provider_receipt(provider, time.perf_counter() - started)
                provider_error_type = type(error).__name__
                provider_error = _safe_error(error, credential_values)
            else:
                receipt = _provider_receipt(provider, time.perf_counter() - started)
                provider_status = "PASS"
                execution = _execute_patched(agent_class, run_id, response)
                if _context_ids_reaching_output(execution) != [
                    item.context_id for item in transmitted
                ]:
                    raise ValueError("P400 repaired trace differs from live envelope")
                evaluation = evaluate_p400(
                    execution.trace, p400_contract(active_purpose=APP_NAME_PURPOSE)
                )
                matrix = await verify_all_p400_families(
                    workspace.path,
                    contract=p400_contract(active_purpose=APP_NAME_PURPOSE),
                    require_ingress_rejection=(
                        repair_evidence.schema_version
                        == "gauntlet.p400-live-repair.v2"
                    ),
                )
    finally:
        cleanup = (
            "PASS" if workspace.path is not None and not workspace.path.exists()
            else "FAIL"
        )

    assert envelope is not None
    after = repository_digest(root)
    live_pass = bool(
        provider_status == "PASS"
        and evaluation is not None
        and evaluation.status == ContractStatus.PASS
        and not envelope.transmitted_context_items
    )
    matrix_pass = bool(matrix is not None and matrix.passed)
    final_status = (
        "PROVIDER_FAILED" if provider_status == "FAIL"
        else "VERIFIED" if live_pass and matrix_pass
        else "NOT_VERIFIED"
    )
    values: dict[str, Any] = {
        "schema_version": P400_LIVE_PROOF_VERSION,
        "run_id": run_id,
        "created_at": datetime.now(timezone.utc),
        "execution_mode": "LIVE_PROOF",
        "source_live_repair_run_id": repair_evidence.run_id,
        "source_patch_digest": repair_evidence.derived_patch_digest,
        "provider": provider.provider_name,
        "model": provider.model_name,
        "provider_request_count": 1,
        "automatic_retries": 0,
        "model_switches": 0,
        "model_envelope": envelope,
        "provider_receipt": receipt,
        "provider_status": provider_status,
        "provider_error_type": provider_error_type,
        "provider_error": provider_error,
        "model_response": response,
        "execution": execution,
        "evaluation": evaluation,
        "live_post_repair": "PASS" if live_pass else (
            "NOT_RUN" if provider_status == "FAIL" else "FAIL"
        ),
        "deterministic_matrix": matrix,
        "deterministic_matrix_status": "PASS" if matrix_pass else (
            "NOT_RUN" if provider_status == "FAIL" else "FAIL"
        ),
        "final_status": final_status,
        "patch_application": application_status,
        "compilation": compilation_status,
        "workspace_cleanup": cleanup,
        "repository_digest_before": before,
        "repository_digest_after": after,
        "repository_immutability": "PASS" if before == after else "FAIL",
        "credential_scan": "PASS",
    }
    provisional = P400LiveProofEvidence.model_construct(
        **values, integrity_digest="0" * 64
    )
    evidence = P400LiveProofEvidence(
        **values, integrity_digest=_integrity_digest(provisional)
    )
    path = _persist(evidence, evidence_directory, credential_values)
    return evidence, path


def _execute_patched(agent_class, run_id: str, output_text: str):
    execution = agent_class().respond(
        run_id=run_id,
        user_request=GENERIC_APP_NAME_REQUEST,
        principal=CURRENT_USER,
        active_purpose=APP_NAME_PURPOSE,
        request_id=GENERIC_APP_NAME_REQUEST_ID,
        task=APP_NAME_PURPOSE,
        activated_personalization_dimensions=(),
        context_items=(TAMIL_CULTURAL_CONTEXT,),
        authorization_grants=(TAMIL_CULTURAL_GRANT,),
        output_text=output_text,
        model_claims={"provider_response_captured": True},
    )
    # The sandbox module has a distinct Python class identity. Re-validate its
    # data into the canonical evidence model without changing any values.
    return PersonalizationExecution.model_validate(execution.model_dump())


def _context_ids_reaching_output(execution: PersonalizationExecution) -> list[str]:
    output = next(
        event for event in execution.trace.events
        if event.event_type == NormalizedEventType.MODEL_OUTPUT
    )
    by_id = {event.event_id: event for event in execution.trace.events}
    return [
        str(by_id[event_id].metadata["context_id"])
        for event_id in output.input_event_ids
        if by_id[event_id].event_type == NormalizedEventType.IDENTITY_CONTEXT
    ]


def _proof_envelope(
    *, run_id: str, transmitted: list[PersonalContextItem],
) -> P400LiveProofEnvelope:
    transmitted_ids = {item.context_id for item in transmitted}
    context_payload = [item.model_dump(mode="json") for item in transmitted]
    content = json.dumps({
        "user_request": GENERIC_APP_NAME_REQUEST,
        "framework_personal_context": context_payload,
    }, ensure_ascii=True, sort_keys=True)
    return P400LiveProofEnvelope(
        run_id=run_id,
        user_request=GENERIC_APP_NAME_REQUEST,
        principal=CURRENT_USER,
        active_purpose=APP_NAME_PURPOSE,
        activated_personalization_dimensions=[],
        candidate_context_items=[TAMIL_CULTURAL_CONTEXT],
        transmitted_context_items=transmitted,
        inclusion_decisions=[P400ProofContextDecision(
            context_id=TAMIL_CULTURAL_CONTEXT.context_id,
            decision=(
                "INCLUDED" if TAMIL_CULTURAL_CONTEXT.context_id in transmitted_ids
                else "EXCLUDED"
            ),
            decided_by="patched_personalization_agent",
        )],
        messages=[
            P400LiveMessage(role="system", content=P400_LIVE_SYSTEM_PROMPT),
            P400LiveMessage(role="user", content=content),
        ],
    )


def _load_patched_agent(workspace_root: Path):
    path = workspace_root / "victims/personalization/agent.py"
    name = f"gauntlet_p400_live_proof_{uuid4().hex}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("patched P400 agent could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module.PersonalizationAgent


def _provider_receipt(
    provider: P400LiveProofProvider, latency: float,
) -> P400LiveProviderReceipt:
    metadata = provider.completion_metadata() or {}
    return P400LiveProviderReceipt(
        http_status=metadata.get("http_status"),
        finish_reason=metadata.get("finish_reason"),
        prompt_tokens=metadata.get("prompt_tokens"),
        completion_tokens=metadata.get("completion_tokens"),
        total_tokens=metadata.get("total_tokens"),
        latency_seconds=latency,
    )


def _safe_error(error: Exception, credentials: tuple[str, ...]) -> str:
    message = str(error)
    for secret in credentials:
        if secret:
            message = message.replace(secret, "[REDACTED]")
    message = re.sub(
        r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", message
    )
    return f"{type(error).__name__}: {message}"[:4_000]


def _integrity_digest(evidence: P400LiveProofEvidence) -> str:
    payload = evidence.model_dump(mode="json", exclude={"integrity_digest"})
    serialized = json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(serialized.encode()).hexdigest()


def _persist(
    evidence: P400LiveProofEvidence,
    directory: Path,
    credentials: tuple[str, ...],
) -> Path:
    serialized = evidence.model_dump_json(indent=2) + "\n"
    if any(secret and secret in serialized for secret in credentials):
        raise ValueError("credential scan failed; P400 proof not persisted")
    if re.search(
        r"(?i)(authorization\s*[:=]|bearer\s+[A-Za-z0-9._~+/=-]+|"
        r"api[_-]?key\s*[:=]|access[_-]?token\s*[:=])",
        serialized,
    ):
        raise ValueError("credential marker detected; P400 proof not persisted")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"live-{evidence.run_id}.json"
    path.write_text(serialized)
    return path
