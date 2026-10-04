"""Generic bridge from contract violations to the existing repair pipeline."""

from pathlib import Path
from uuid import UUID, uuid4

from pydantic import Field, model_validator

from gauntlet.contracts.models import (
    ContractEvaluation,
    ContractStatus,
    NormalizedExecutionTrace,
    SecurityContract,
)
from gauntlet.remediation.context import build_authorized_source_context
from gauntlet.remediation.models import (
    RemediationRequest,
    RepairContext,
    SourceContext,
    StrictModel,
)


class AuthorizedSourceBoundary(StrictModel):
    """Caller-authorized repair target; generic code never infers this value."""

    target_path: str = Field(min_length=1, max_length=500)
    target_symbol: str = Field(min_length=1, max_length=500)


class ContractRepairRequest(StrictModel):
    """Serializable, property-neutral repair input owned by trusted Gauntlet code."""

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    contract: SecurityContract
    violation: ContractEvaluation
    counterexample_trace: NormalizedExecutionTrace
    source_context: SourceContext
    expected_security_property: str = Field(min_length=1, max_length=2_000)
    legitimate_behaviors_to_preserve: list[str] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def identities_and_evidence_match(self) -> "ContractRepairRequest":
        UUID(self.request_id)
        if self.violation.status != ContractStatus.VIOLATED:
            raise ValueError("repair requests require a violated contract result")
        if self.violation.contract_id != self.contract.contract_id:
            raise ValueError("repair request contract identity mismatch")
        if self.violation.trace_id != self.counterexample_trace.trace_id:
            raise ValueError("repair request trace identity mismatch")
        if self.source_context.trace_id != self.counterexample_trace.trace_id:
            raise ValueError("repair request source trace identity mismatch")
        if self.source_context.boundary_id != self.request_id:
            raise ValueError("repair request source boundary identity mismatch")
        trace_event_ids = {
            event.event_id for event in self.counterexample_trace.events
        }
        evidence_ids = {
            event_id
            for evidence in self.violation.evidence
            for event_id in evidence.event_ids
        }
        if not evidence_ids or not evidence_ids <= trace_event_ids:
            raise ValueError("repair request violation evidence is not in the trace")
        if set(self.source_context.evidence_ids) != evidence_ids:
            raise ValueError("repair request source evidence identity mismatch")
        return self


def build_contract_repair_request(
    *,
    contract: SecurityContract,
    violation: ContractEvaluation,
    counterexample_trace: NormalizedExecutionTrace,
    authorized_source: AuthorizedSourceBoundary,
    expected_security_property: str,
    legitimate_behaviors_to_preserve: list[str],
    repository_root: Path,
) -> ContractRepairRequest:
    """Bind one violation and an explicit source authorization to trusted source."""
    request_id = str(uuid4())
    evidence_ids = list(dict.fromkeys(
        event_id
        for evidence in violation.evidence
        for event_id in evidence.event_ids
    ))
    source = build_authorized_source_context(
        repository_root,
        target_path=authorized_source.target_path,
        target_symbol=authorized_source.target_symbol,
        trace_id=counterexample_trace.trace_id,
        boundary_id=request_id,
        evidence_ids=evidence_ids,
    )
    return ContractRepairRequest(
        request_id=request_id,
        contract=contract,
        violation=violation,
        counterexample_trace=counterexample_trace,
        source_context=source,
        expected_security_property=expected_security_property,
        legitimate_behaviors_to_preserve=legitimate_behaviors_to_preserve,
    )


def to_remediation_request(
    request: ContractRepairRequest, *, provider: str, model: str,
) -> RemediationRequest:
    """Adapt the generic request to the existing candidate-generation boundary."""
    source = request.source_context
    return RemediationRequest(
        source_context=source,
        repair_context=RepairContext(
            trace_id=source.trace_id,
            boundary_id=source.boundary_id,
            evidence_ids=source.evidence_ids,
            provider=provider,
            model=model,
            target_path=source.repository_relative_path,
            target_symbol=source.target_symbol,
            source_hash=source.source_hash,
            failure_type=request.contract.contract_id,
        ),
        evidence_summary={
            "request_kind": "contract_violation",
            "contract": request.contract.model_dump(mode="json"),
            "violation": request.violation.model_dump(mode="json"),
            "counterexample_trace": request.counterexample_trace.model_dump(
                mode="json"
            ),
            "expected_security_property": request.expected_security_property,
            "legitimate_behaviors_to_preserve": (
                request.legitimate_behaviors_to_preserve
            ),
        },
    )
