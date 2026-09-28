"""Evidence-guided planner for the one explicitly supported synthetic seam."""
from gauntlet.patching.models import PatchPlan
from gauntlet.tracing.models import AttackTrace, TrustLevel

EXPECTED_FILE = "victims/customer_support/agent.py"
EXPECTED_SYMBOL = "CustomerSupportAgent.chat"


def plan_patch(serialized_trace: str) -> PatchPlan:
    trace = AttackTrace.model_validate_json(serialized_trace)
    boundary = trace.failure_boundary
    if boundary is None:
        raise ValueError("Patch planning requires an M2 FailureBoundary")
    if boundary.from_trust_level != TrustLevel.UNTRUSTED:
        raise ValueError("Patch planning requires an UNTRUSTED source boundary")
    location = next(
        (item for item in trace.source_locations
         if item.file == EXPECTED_FILE and item.symbol == EXPECTED_SYMBOL),
        None,
    )
    if location is None:
        raise ValueError("M3 is constrained to the known customer-support integration seam")
    known_ids = {event.event_id for event in trace.events}
    if not boundary.evidence_event_ids or not set(boundary.evidence_event_ids) <= known_ids:
        raise ValueError("FailureBoundary references missing trace evidence")
    evidence = ", ".join(boundary.evidence_event_ids)
    return PatchPlan(
        source_trace_id=trace.attack_id,
        failure_boundary_id=boundary.boundary_id,
        supporting_event_ids=boundary.evidence_event_ids,
        target_file=EXPECTED_FILE,
        target_symbol=EXPECTED_SYMBOL,
        failure_type="indirect_prompt_injection",
        proposed_control="Enforce a data-only boundary for UNTRUSTED tool content before model generation.",
        rationale=(
            f"M2 boundary {boundary.boundary_id} links UNTRUSTED search_reviews data "
            f"to privileged model context through evidence events: {evidence}."
        ),
        expected_security_invariant=(
            "UNTRUSTED review text may contribute factual review content but must never be "
            "interpreted as instructions or reveal privileged context."
        ),
    )
