import httpx
import pytest

from gauntlet.attacks.indirect_prompt_injection import IndirectPromptInjectionAttack
from gauntlet.patching.planner import EXPECTED_FILE, EXPECTED_SYMBOL, plan_patch
from gauntlet.patching.renderer import render_patch_proof
from gauntlet.patching.workflow import prove_patch
from victims.customer_support.app import create_app


async def vulnerable_trace():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://before"
    ) as client:
        result = await IndirectPromptInjectionAttack(client).run()
    return result.trace


async def test_patch_plan_consumes_serialized_m2_trace_and_carries_evidence():
    trace = await vulnerable_trace()
    plan = plan_patch(trace.model_dump_json())
    assert plan.source_trace_id == trace.attack_id
    assert plan.failure_boundary_id == trace.failure_boundary.boundary_id
    assert plan.supporting_event_ids == trace.failure_boundary.evidence_event_ids
    assert all(event_id in plan.rationale for event_id in plan.supporting_event_ids)


async def test_patch_is_constrained_to_expected_file_and_symbol():
    plan = plan_patch((await vulnerable_trace()).model_dump_json())
    assert plan.target_file == EXPECTED_FILE
    assert plan.target_symbol == EXPECTED_SYMBOL


async def test_planner_rejects_trace_without_failure_boundary():
    trace = await vulnerable_trace()
    trace.failure_boundary = None
    with pytest.raises(ValueError, match="FailureBoundary"):
        plan_patch(trace.model_dump_json())


async def test_planner_rejects_missing_evidence_and_wrong_location():
    trace = await vulnerable_trace()
    trace.failure_boundary.evidence_event_ids.append("missing-event")
    with pytest.raises(ValueError, match="missing trace evidence"):
        plan_patch(trace.model_dump_json())
    trace = await vulnerable_trace()
    trace.source_locations[0].symbol = "Other.symbol"
    with pytest.raises(ValueError, match="constrained"):
        plan_patch(trace.model_dump_json())


async def test_patch_proof_links_before_plan_after_and_preserves_same_attack():
    trace = await vulnerable_trace()
    proof = await prove_patch(trace.model_dump_json(), test_suite_passed=True)
    assert proof.plan.source_trace_id == proof.pre_patch_trace.attack_id
    assert proof.applied_patch.patch_id == proof.plan.patch_id
    assert proof.same_attack
    assert proof.pre_patch_trace.events[0].data == proof.post_patch_trace.events[0].data
    assert proof.pre_patch_trace.events[1].data == proof.post_patch_trace.events[1].data
    assert proof.post_patch_verdict == "CANARY_NOT_OBSERVED"
    assert proof.post_patch_trace.failure_boundary is None
    assert proof.regression.passed
    assert "sturdy construction" in proof.regression.observed_response
    assert proof.verified


async def test_proof_requires_recorded_passing_suite():
    trace = await vulnerable_trace()
    proof = await prove_patch(trace.model_dump_json())
    assert not proof.verified


async def test_cli_proof_renderer_is_derived_from_artifact():
    proof = await prove_patch(
        (await vulnerable_trace()).model_dump_json(), test_suite_passed=True
    )
    output = render_patch_proof(proof)
    for expected in (
        "PATCH PROOF", "CANARY_LEAKED", "tool_result → model_context",
        EXPECTED_FILE, EXPECTED_SYMBOL, "Same attack: YES",
        "CANARY_NOT_OBSERVED", "Clean behavior: PASS", "Test suite: PASS",
        "PATCH VERIFIED",
    ):
        assert expected in output
