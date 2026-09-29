from pathlib import Path

from gauntlet.remediation.contract_handoff import (
    ContractRepairRequest, to_remediation_request,
)
from gauntlet.remediation.context import build_source_context
from gauntlet.remediation.models import (
    RemediationRequest, RepairContext, RepairFailure, RepairProposal,
    combine_repair_candidate,
)
from gauntlet.remediation.parsing import (
    parse_generated_edit_candidate, parse_generated_test_candidate,
)
from gauntlet.remediation.provider import RemediationProvider
from gauntlet.remediation.validation import validate_candidate, validate_source_edit
from gauntlet.tracing.models import AttackTrace


async def generate_repair_proposal(
    serialized_trace: str, repository_root: Path, provider: RemediationProvider
) -> RepairProposal | RepairFailure:
    """M3.1 single-shot proposal: edit call, then test call.

    The edit is validated first so the deterministically derived patch can be
    handed to the test call as grounding. Both parts are then combined and run
    through the standard combined validation path.
    """
    trace = AttackTrace.model_validate_json(serialized_trace)
    source = build_source_context(serialized_trace, repository_root)
    repair_context = RepairContext(
        trace_id=source.trace_id,
        boundary_id=source.boundary_id,
        evidence_ids=source.evidence_ids,
        provider=provider.provider_name,
        model=provider.model_name,
        target_path=source.repository_relative_path,
        target_symbol=source.target_symbol,
        source_hash=source.source_hash,
        failure_type="indirect_prompt_injection",
    )
    request = RemediationRequest(
        source_context=source,
        repair_context=repair_context,
        evidence_summary={
            "verdict": trace.verdict,
            "boundary_type": trace.failure_boundary.boundary_type,
            "evidence_strength": trace.evidence.get("strength", "UNKNOWN"),
        },
    )
    return await generate_repair_proposal_from_request(
        request, repository_root, provider
    )


async def generate_contract_repair_proposal(
    request: ContractRepairRequest,
    repository_root: Path,
    provider: RemediationProvider,
) -> RepairProposal | RepairFailure:
    """Generate a proposal from a generic contract violation without legacy traces."""
    remediation_request = to_remediation_request(
        request, provider=provider.provider_name, model=provider.model_name
    )
    return await generate_repair_proposal_from_request(
        remediation_request, repository_root, provider
    )


async def generate_repair_proposal_from_request(
    request: RemediationRequest,
    repository_root: Path,
    provider: RemediationProvider,
) -> RepairProposal | RepairFailure:
    """Shared proposal path for legacy P100 and generic contract handoffs."""
    source = request.source_context
    repair_context = request.repair_context
    target = repository_root / source.repository_relative_path
    before = target.read_bytes()
    edit_raw = await provider.generate_edit(request)
    edit_candidate = parse_generated_edit_candidate(edit_raw)
    materialized: dict[str, str] = {}
    derived = validate_source_edit(
        edit_candidate, repair_context, repository_root,
        materialized_output=materialized,
    )
    if isinstance(derived, RepairFailure):
        if target.read_bytes() != before:
            raise RuntimeError("remediation provider flow modified repository source")
        return derived
    test_raw = await provider.generate_test(request, derived_patch=derived)
    test_candidate = parse_generated_test_candidate(test_raw)
    combined = combine_repair_candidate(edit_candidate, test_candidate)
    result = validate_candidate(combined, repair_context, repository_root)
    if target.read_bytes() != before:
        raise RuntimeError("remediation provider flow modified repository source")
    return result
