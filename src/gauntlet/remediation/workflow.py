from pathlib import Path

from gauntlet.remediation.context import build_source_context
from gauntlet.remediation.models import RemediationRequest, RepairProposal
from gauntlet.remediation.parsing import parse_repair_proposal
from gauntlet.remediation.provider import RemediationProvider
from gauntlet.tracing.models import AttackTrace


async def generate_repair_proposal(
    serialized_trace: str, repository_root: Path, provider: RemediationProvider
) -> RepairProposal:
    trace = AttackTrace.model_validate_json(serialized_trace)
    source = build_source_context(serialized_trace, repository_root)
    target = repository_root / source.repository_relative_path
    before = target.read_bytes()
    request = RemediationRequest(
        source_context=source,
        failure_type="indirect_prompt_injection",
        provider=provider.provider_name,
        model=provider.model_name,
        evidence_summary={
            "verdict": trace.verdict,
            "boundary_type": trace.failure_boundary.boundary_type,
            "evidence_strength": trace.evidence.get("strength", "UNKNOWN"),
        },
    )
    raw = await provider.generate(request)
    proposal = parse_repair_proposal(raw)
    expected = {
        "trace_id": source.trace_id,
        "boundary_id": source.boundary_id,
        "evidence_ids": source.evidence_ids,
        "provider": provider.provider_name,
        "model": provider.model_name,
        "target_path": source.repository_relative_path,
        "target_symbol": source.target_symbol,
        "source_hash": source.source_hash,
        "failure_type": request.failure_type,
    }
    for field, value in expected.items():
        if getattr(proposal, field) != value:
            raise ValueError(f"Provider response changed required provenance field: {field}")
    if target.read_bytes() != before:
        raise RuntimeError("M3.1 provider flow modified repository source")
    return proposal
