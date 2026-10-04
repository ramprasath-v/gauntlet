"""One-shot live P300 repair experiment with integrity-bound evidence."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import Field, model_validator

from gauntlet.contracts.p300_repair import verify_p300_repair
from gauntlet.remediation.candidate_artifact import (
    persist_candidate_artifact,
    persist_validated_edit_artifact,
)
from gauntlet.remediation.contract_handoff import ContractRepairRequest
from gauntlet.remediation.contract_verification import (
    ContractRepairAssessment,
    ContractRepairExecutor,
)
from gauntlet.remediation.handoff import persist_repair_proposal
from gauntlet.remediation.models import (
    GeneratedEditCandidate,
    GeneratedRepairCandidate,
    RepairFailure,
    RepairProposal,
    StrictModel,
)
from gauntlet.remediation.provider import RemediationProvider
from gauntlet.remediation.workflow import generate_contract_repair_proposal
from gauntlet.sandbox.m4_runner import M41CommandRunner
from gauntlet.sandbox.models import CommandCategory, CommandResult
from gauntlet.sandbox.workspace import SandboxWorkspace, repository_digest


P300_LIVE_EVIDENCE_VERSION = "gauntlet.p300-live-repair.v1"


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class ProviderCallEvidence(StrictModel):
    phase: Literal["edit", "test"]
    request_number: int = Field(ge=1, le=2)
    outcome: Literal["PASS", "FAIL"]
    metadata: dict[str, Any] | None = None
    error_type: str | None = None


class P300LiveRepairReceipt(StrictModel):
    schema_version: Literal["gauntlet.p300-live-repair.v1"]
    run_id: str
    created_at: datetime
    contract_request: ContractRepairRequest
    provider: str
    model: str
    provider_requests: int = Field(ge=0, le=2)
    provider_calls: list[ProviderCallEvidence]
    candidate_id: str | None = None
    candidate_artifact: str | None = None
    candidate_integrity_digest: str | None = None
    exact_proposed_edit: dict[str, Any] | None = None
    proposal_artifact: str | None = None
    validation_outcome: Literal["PASS", "FAIL"]
    validation_failure: dict[str, Any] | None = None
    sandbox_assessment: ContractRepairAssessment | None = None
    p100_regression: CommandResult | None = None
    original_repository_digest: str
    final_repository_digest: str
    repository_immutability: Literal["PASS", "FAIL"]
    final_status: Literal["VERIFIED", "NOT_VERIFIED"]
    integrity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def integrity_matches(self) -> "P300LiveRepairReceipt":
        payload = self.model_dump(mode="json", exclude={"integrity_digest"})
        expected = _digest_text(json.dumps(
            payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ))
        if self.integrity_digest != expected:
            raise ValueError("P300 live repair receipt integrity failed")
        return self


class _RecordingProvider:
    def __init__(self, provider: RemediationProvider) -> None:
        self._provider = provider
        self.provider_name = provider.provider_name
        self.model_name = provider.model_name
        self.calls: list[ProviderCallEvidence] = []

    def _metadata(self) -> dict[str, Any] | None:
        getter = getattr(self._provider, "safe_completion_metadata", None)
        if getter is None:
            return None
        value = getter()
        return value.model_dump(mode="json") if value is not None else None

    async def generate_edit(self, request):
        try:
            result = await self._provider.generate_edit(request)
        except Exception as exc:
            self.calls.append(ProviderCallEvidence(
                phase="edit", request_number=len(self.calls) + 1,
                outcome="FAIL", metadata=self._metadata(),
                error_type=type(exc).__name__,
            ))
            raise
        self.calls.append(ProviderCallEvidence(
            phase="edit", request_number=len(self.calls) + 1,
            outcome="PASS", metadata=self._metadata(),
        ))
        return result

    async def generate_test(self, request, *, derived_patch: str):
        try:
            result = await self._provider.generate_test(
                request, derived_patch=derived_patch
            )
        except Exception as exc:
            self.calls.append(ProviderCallEvidence(
                phase="test", request_number=len(self.calls) + 1,
                outcome="FAIL", metadata=self._metadata(),
                error_type=type(exc).__name__,
            ))
            raise
        self.calls.append(ProviderCallEvidence(
            phase="test", request_number=len(self.calls) + 1,
            outcome="PASS", metadata=self._metadata(),
        ))
        return result


async def _p100_regression(
    repository_root: Path, proposal: RepairProposal,
) -> CommandResult | None:
    runner = M41CommandRunner()
    workspace = SandboxWorkspace(repository_root)
    with workspace:
        assert workspace.path is not None
        patch_path = workspace.resolve_relative(".gauntlet/p300-p100.patch")
        patch_path.parent.mkdir(parents=True, exist_ok=True)
        patch_path.write_bytes(proposal.patch.encode())
        applied = await runner.apply_patch(workspace, patch_path)
        if not applied.passed:
            return None
        return await runner._run(
            workspace,
            CommandCategory.SECURITY,
            [
                __import__("sys").executable,
                "-m", "pytest", "-q",
                "tests/test_security_contracts.py",
                "tests/test_indirect_prompt_injection.py",
            ],
        )


def _receipt_digest(values: dict[str, Any]) -> str:
    provisional = P300LiveRepairReceipt.model_construct(
        **values, integrity_digest="0" * 64
    )
    payload = provisional.model_dump(mode="json", exclude={"integrity_digest"})
    return _digest_text(json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ))


async def run_live_p300_repair(
    *,
    request: ContractRepairRequest,
    repository_root: Path,
    provider: RemediationProvider,
    evidence_root: Path,
) -> tuple[P300LiveRepairReceipt, Path]:
    """Run exactly one two-call workflow; never retry or alter the candidate."""
    run_id = str(uuid4())
    run_root = evidence_root / run_id
    run_root.mkdir(parents=True, exist_ok=False)
    before = repository_digest(repository_root)
    recording = _RecordingProvider(provider)
    capture: dict[str, object] = {}
    result: RepairProposal | RepairFailure | None = None
    raised: Exception | None = None
    try:
        result = await generate_contract_repair_proposal(
            request, repository_root, recording, capture=capture
        )
    except Exception as exc:
        raised = exc

    candidate_id = candidate_path = candidate_integrity = proposal_path = None
    exact_edit = None
    validation_failure = None
    assessment = None
    p100 = None
    edit = capture.get("edit_candidate")
    if isinstance(edit, GeneratedEditCandidate):
        exact_edit = edit.source_edit.model_dump(mode="json")
        derived_patch = capture.get("derived_patch")
        trusted_lines = capture.get("trusted_original_lines")
        if isinstance(derived_patch, str) and isinstance(trusted_lines, list):
            persist_validated_edit_artifact(
                edit,
                path=run_root / "validated-edit.json",
                edit_id=str(uuid4()),
                run_id=run_id,
                originating_attempt=1,
                provider=recording.provider_name,
                model=recording.model_name,
                trace_id=request.source_context.trace_id,
                boundary_id=request.source_context.boundary_id,
                evidence_ids=request.source_context.evidence_ids,
                target_path=request.source_context.repository_relative_path,
                target_symbol=request.source_context.target_symbol,
                source_hash=request.source_context.source_hash,
                trusted_original_lines=trusted_lines,
                derived_patch=derived_patch,
            )

    combined = capture.get("combined_candidate")
    if isinstance(combined, GeneratedRepairCandidate):
        candidate_id = str(uuid4())
        artifact_path = run_root / "candidate.json"
        artifact = persist_candidate_artifact(
            combined,
            path=artifact_path,
            candidate_id=candidate_id,
            run_id=run_id,
            attempt_number=1,
            provider=recording.provider_name,
            model=recording.model_name,
            trace_id=request.source_context.trace_id,
            boundary_id=request.source_context.boundary_id,
            evidence_ids=request.source_context.evidence_ids,
            target_path=request.source_context.repository_relative_path,
            target_symbol=request.source_context.target_symbol,
            source_hash=request.source_context.source_hash,
            derived_patch=capture.get("patch") if isinstance(
                capture.get("patch"), str
            ) else None,
            derived_regression_test=capture.get("regression_test") if isinstance(
                capture.get("regression_test"), str
            ) else None,
        )
        candidate_path = artifact_path.relative_to(evidence_root).as_posix()
        candidate_integrity = artifact.integrity_digest

    if isinstance(result, RepairFailure):
        validation_failure = result.model_dump(mode="json")
    elif isinstance(result, RepairProposal):
        proposal_artifact = run_root / "proposal.json"
        persist_repair_proposal(result, proposal_artifact)
        proposal_path = proposal_artifact.relative_to(evidence_root).as_posix()

        async def verifier(workspace_root: Path):
            return await verify_p300_repair(
                workspace_root, contract=request.contract
            )

        assessment = await ContractRepairExecutor(repository_root).run(
            result, verifier
        )
        if (
            assessment.patch_application is not None
            and assessment.patch_application.passed
            and assessment.compilation is not None
            and assessment.compilation.passed
        ):
            p100 = await _p100_regression(repository_root, result)

    after = repository_digest(repository_root)
    verified = bool(
        assessment is not None
        and assessment.verdict == "VERIFIED"
        and p100 is not None
        and p100.passed
    )
    if raised is not None:
        validation_failure = {"error_type": type(raised).__name__}
    values = dict(
        schema_version=P300_LIVE_EVIDENCE_VERSION,
        run_id=run_id,
        created_at=datetime.now(timezone.utc),
        contract_request=request,
        provider=recording.provider_name,
        model=recording.model_name,
        provider_requests=len(recording.calls),
        provider_calls=recording.calls,
        candidate_id=candidate_id,
        candidate_artifact=candidate_path,
        candidate_integrity_digest=candidate_integrity,
        exact_proposed_edit=exact_edit,
        proposal_artifact=proposal_path,
        validation_outcome="PASS" if isinstance(result, RepairProposal) else "FAIL",
        validation_failure=validation_failure,
        sandbox_assessment=assessment,
        p100_regression=p100,
        original_repository_digest=before,
        final_repository_digest=after,
        repository_immutability="PASS" if before == after else "FAIL",
        final_status="VERIFIED" if verified else "NOT_VERIFIED",
    )
    receipt = P300LiveRepairReceipt(
        **values, integrity_digest=_receipt_digest(values)
    )
    receipt_path = run_root / "receipt.json"
    receipt_path.write_text(receipt.model_dump_json(indent=2) + "\n")
    return receipt, receipt_path
