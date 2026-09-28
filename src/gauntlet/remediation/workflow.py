from pathlib import Path
from uuid import uuid4

from gauntlet.remediation.context import build_source_context
from gauntlet.remediation.models import (
    RemediationRequest, RepairContext, RepairProposal,
)
from gauntlet.remediation.parsing import parse_generated_repair
from gauntlet.remediation.provider import RemediationProvider
from gauntlet.tracing.models import AttackTrace


async def generate_repair_proposal(
    serialized_trace: str, repository_root: Path, provider: RemediationProvider
) -> RepairProposal:
    trace = AttackTrace.model_validate_json(serialized_trace)
    source = build_source_context(serialized_trace, repository_root)
    target = repository_root / source.repository_relative_path
    before = target.read_bytes()
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
    raw = await provider.generate(request)
    generated = parse_generated_repair(raw)
    proposal = RepairProposal(
        repair_id=str(uuid4()),
        **repair_context.model_dump(),
        **generated.model_dump(),
    )
    if target.read_bytes() != before:
        raise RuntimeError("M3.1 provider flow modified repository source")
    return proposal
