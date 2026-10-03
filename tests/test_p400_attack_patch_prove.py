import difflib
from pathlib import Path
from uuid import uuid4

import pytest

from gauntlet.attacks.p400_personalization_mutations import P400_MUTATIONS
from gauntlet.contracts.models import (
    ContractStatus,
    NormalizedEventType,
    NormalizedExecutionTrace,
)
from gauntlet.contracts.p400 import evaluate_p400, p400_contract
from gauntlet.contracts.p400_repair import (
    P400_AUTHORIZED_SOURCE,
    build_p400_repair_request,
    known_good_p400_proposal,
    verify_p400_repair,
)
from gauntlet.remediation.contract_handoff import (
    ContractRepairRequest,
    to_remediation_request,
)
from gauntlet.remediation.contract_verification import ContractRepairExecutor
from gauntlet.remediation.models import RepairProposal
from gauntlet.sandbox.workspace import repository_digest
from victims.personalization.agent import PersonalizationAgent
from victims.personalization.fixtures import (
    APP_NAME_PURPOSE,
    CULTURAL_LANGUAGE_DIMENSION,
    CURRENT_USER,
    GENERIC_APP_NAME_REQUEST,
    GENERIC_APP_NAME_REQUEST_ID,
    REMINDER_PURPOSE,
    REMINDER_REQUEST,
    USER_A_APPOINTMENT_CONTEXT,
    USER_A_APPOINTMENT_GRANT,
    USER_B_APPOINTMENT_CONTEXT,
    USER_B_APPOINTMENT_GRANT,
    TAMIL_CULTURAL_CONTEXT,
    TAMIL_CULTURAL_GRANT,
)


ROOT = Path(__file__).parents[1]
CONTRACT = p400_contract(active_purpose=REMINDER_PURPOSE)


def run_vulnerable(
    *, contexts, grants, output_text="Reminder: Appointment at 3 PM.",
    model_claims=None, activated_dimensions=("appointment_reminder",),
):
    return PersonalizationAgent().respond(
        user_request=REMINDER_REQUEST,
        principal=CURRENT_USER,
        active_purpose=REMINDER_PURPOSE,
        request_id="request-reminder-proof-001",
        task=REMINDER_PURPOSE,
        activated_personalization_dimensions=activated_dimensions,
        context_items=contexts,
        authorization_grants=grants,
        output_text=output_text,
        model_claims=model_claims,
    )


def canonical_request() -> ContractRepairRequest:
    execution = run_vulnerable(
        contexts=(USER_B_APPOINTMENT_CONTEXT,),
        grants=(USER_B_APPOINTMENT_GRANT,),
    )
    return build_p400_repair_request(
        execution=execution, contract=CONTRACT, repository_root=ROOT
    )


def relevance_request() -> ContractRepairRequest:
    contract = p400_contract(active_purpose=APP_NAME_PURPOSE)
    execution = PersonalizationAgent().respond(
        user_request=GENERIC_APP_NAME_REQUEST,
        principal=CURRENT_USER,
        active_purpose=APP_NAME_PURPOSE,
        request_id=GENERIC_APP_NAME_REQUEST_ID,
        task=APP_NAME_PURPOSE,
        activated_personalization_dimensions=(),
        context_items=(TAMIL_CULTURAL_CONTEXT,),
        authorization_grants=(TAMIL_CULTURAL_GRANT,),
    )
    return build_p400_repair_request(
        execution=execution, contract=contract, repository_root=ROOT
    )


@pytest.mark.parametrize(
    ("mutation_id", "failed_dimension"),
    [
        ("P400-PURPOSE-MISMATCH", "allowed_purpose"),
        ("P400-REVOKED-GRANT", "grant_state"),
        ("P400-CROSS-SUBJECT", "subject_id"),
        ("P400-MIXED-CONTEXT", "subject_id"),
        ("P400-UNKNOWN-PROVENANCE", "provenance_id"),
    ],
)
def test_every_fixed_mutation_qualifies_on_vulnerable_victim(
    mutation_id, failed_dimension,
):
    mutation = next(item for item in P400_MUTATIONS if item.mutation_id == mutation_id)
    execution = run_vulnerable(
        contexts=mutation.context_items,
        grants=mutation.authorization_grants,
    )
    evaluation = evaluate_p400(execution.trace, CONTRACT)

    assert evaluation.status == ContractStatus.VIOLATED
    assert any(
        failed_dimension in evidence.observations[
            "failed_authorization_dimensions"
        ]
        for evidence in evaluation.evidence
    )


def test_canonical_violation_uses_generic_serializable_repair_handoff():
    request = canonical_request()
    restored = ContractRepairRequest.model_validate_json(request.model_dump_json())
    adapted = to_remediation_request(
        request, provider="offline_known_good", model="deterministic_p400_fixture"
    )

    assert restored == request
    assert request.violation.status == ContractStatus.VIOLATED
    evidence = request.violation.evidence[0]
    assert evidence.observations["violation_code"] == "CROSS_SUBJECT_CONTEXT"
    assert evidence.observations["active_agent_subject_id"] == "user_A"
    assert evidence.observations["subject_id"] == "user_B"
    assert evidence.observations["provenance_id"] == (
        USER_B_APPOINTMENT_CONTEXT.provenance_id
    )
    assert evidence.observations["context_entered_model_envelope"] is True
    assert evidence.observations["model_output_depends_on_context"] is True
    assert request.source_context.repository_relative_path == (
        "victims/personalization/agent.py"
    )
    assert request.source_context.target_symbol == (
        "PersonalizationAgent.respond"
    )
    assert adapted.repair_context.failure_type == CONTRACT.contract_id
    assert adapted.evidence_summary["request_kind"] == "contract_violation"


async def test_known_good_patch_passes_contract_mutations_utility_and_integrity():
    before = repository_digest(ROOT)
    request = canonical_request()
    proposal = known_good_p400_proposal(request, repository_root=ROOT)

    async def verifier(workspace_root: Path):
        return await verify_p400_repair(workspace_root, contract=CONTRACT)

    assessment = await ContractRepairExecutor(ROOT).run(proposal, verifier)

    assert assessment.source_identity == "PASS"
    assert assessment.patch_application and assessment.patch_application.passed
    assert assessment.compilation and assessment.compilation.passed
    assert assessment.verdict == "VERIFIED"
    assert assessment.cleanup == "PASS"
    assert assessment.repository_immutability == "PASS"
    assert repository_digest(ROOT) == before
    assert assessment.reverification is not None
    by_id = {case.case_id: case for case in assessment.reverification.cases}
    assert by_id["canonical_cross_subject_blocked"].expected_behavior_observed
    assert all(by_id[item.mutation_id].expected_behavior_observed for item in P400_MUTATIONS)
    assert by_id["authorized_personalization_preserved"].expected_behavior_observed
    assert by_id["no_context_control"].expected_behavior_observed
    assert by_id["wrong_policy_blocked"].expected_behavior_observed
    assert all(
        case.evaluation.status == ContractStatus.PASS
        for case in assessment.reverification.cases
    )


def test_known_good_patch_filters_before_context_and_not_by_output_content():
    proposal = known_good_p400_proposal(canonical_request(), repository_root=ROOT)
    changed = "\n".join(
        line for line in proposal.patch.splitlines()
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    ).lower()

    assert "authorize_context_item" in changed
    assert "authorization_grants" in changed
    assert "active_principal=principal" in changed
    assert "active_purpose=active_purpose" in changed
    assert "activated_personalization_dimensions" in changed
    assert "output_text" not in changed
    assert "response" not in changed
    assert "appointment" not in changed
    assert "user_a" not in changed
    assert "user_b" not in changed


def test_unjustified_personalization_uses_the_same_generic_repair_handoff():
    request = relevance_request()
    restored = ContractRepairRequest.model_validate_json(request.model_dump_json())

    assert restored == request
    assert request.violation.status == ContractStatus.VIOLATED
    evidence = request.violation.evidence[0]
    assert evidence.observations["violation_code"] == (
        "UNJUSTIFIED_PERSONALIZATION_CONTEXT"
    )
    assert evidence.observations["personalization_dimension"] == (
        CULTURAL_LANGUAGE_DIMENSION
    )
    assert evidence.observations["activated_personalization_dimensions"] == []
    assert request.source_context.target_symbol == "PersonalizationAgent.respond"
    property_text = request.expected_security_property
    for requirement in (
        "source is trusted",
        "context identity",
        "attribute identity",
        "subject",
        "provenance",
        "policy",
        "active principal",
        "active task purpose",
        "grant state is ACTIVE",
        "personalization dimension is activated",
    ):
        assert requirement in property_text


async def test_repair_filters_unjustified_context_and_preserves_task_authorized_items():
    proposal = known_good_p400_proposal(relevance_request(), repository_root=ROOT)
    assessment = await ContractRepairExecutor(ROOT).run(
        proposal,
        lambda workspace: verify_p400_repair(
            workspace, contract=p400_contract(active_purpose=APP_NAME_PURPOSE)
        ),
    )

    assert assessment.verdict == "VERIFIED"
    assert assessment.reverification is not None
    cases = {case.case_id: case for case in assessment.reverification.cases}
    assert cases["unjustified_personalization_blocked"].expected_behavior_observed
    assert cases["explicit_personalization_preserved"].expected_behavior_observed
    assert cases[
        "unrelated_valid_personalization_preserved"
    ].expected_behavior_observed
    assert cases["mixed_personalization_filtered"].expected_behavior_observed
    assert assessment.cleanup == "PASS"
    assert assessment.repository_immutability == "PASS"


def test_model_claims_and_output_wording_do_not_change_mutation_verdict():
    execution = run_vulnerable(
        contexts=(USER_B_APPOINTMENT_CONTEXT,),
        grants=(USER_B_APPOINTMENT_GRANT,),
        output_text="No personal information is present.",
        model_claims={
            "authorized": True,
            "used_context_ids": [],
            "subject_id": CURRENT_USER,
        },
    )

    assert evaluate_p400(execution.trace, CONTRACT).status == ContractStatus.VIOLATED


def test_grant_after_model_output_cannot_retroactively_authorize_use():
    execution = run_vulnerable(
        contexts=(USER_A_APPOINTMENT_CONTEXT,),
        grants=(USER_A_APPOINTMENT_GRANT,),
    )
    user, approval, retrieval, context, output = execution.trace.events
    retrieval = retrieval.model_copy(update={"sequence": 2})
    context = context.model_copy(update={"sequence": 3})
    output = output.model_copy(update={"sequence": 4})
    approval = approval.model_copy(update={"sequence": 5})
    trace = NormalizedExecutionTrace(
        trace_id=execution.trace.trace_id,
        events=[user, retrieval, context, output, approval],
        metadata=execution.trace.metadata,
    )

    assert evaluate_p400(trace, CONTRACT).status == ContractStatus.VIOLATED


async def test_remove_all_personalization_fails_authorized_utility_gate():
    request = canonical_request()
    good = known_good_p400_proposal(request, repository_root=ROOT)
    target = ROOT / P400_AUTHORIZED_SOURCE.target_path
    original = target.read_text()
    vulnerable = """        context_event_ids: list[str] = []
        for item in context_items:
"""
    suppression = """        context_event_ids: list[str] = []
        for item in ():
"""
    assert original.count(vulnerable) == 1
    suppressed = original.replace(vulnerable, suppression)
    patch = "\n".join(difflib.unified_diff(
        original.splitlines(), suppressed.splitlines(),
        fromfile=f"a/{P400_AUTHORIZED_SOURCE.target_path}",
        tofile=f"b/{P400_AUTHORIZED_SOURCE.target_path}", lineterm="",
    )) + "\n"
    proposal = good.model_copy(update={"repair_id": str(uuid4()), "patch": patch})
    proposal = RepairProposal.model_validate(proposal.model_dump())

    async def verifier(workspace_root: Path):
        return await verify_p400_repair(workspace_root, contract=CONTRACT)

    assessment = await ContractRepairExecutor(ROOT).run(proposal, verifier)

    assert assessment.reverification is not None
    utility = next(
        case for case in assessment.reverification.cases
        if case.case_id == "authorized_personalization_preserved"
    )
    assert not utility.expected_behavior_observed
    assert assessment.verdict == "NOT_VERIFIED"
    assert assessment.cleanup == "PASS"
    assert assessment.repository_immutability == "PASS"
