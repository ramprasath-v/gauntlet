from pathlib import Path

import httpx

from gauntlet.attacks.indirect_prompt_injection import IndirectPromptInjectionAttack
from gauntlet.contracts.models import ContractStatus
from gauntlet.contracts.p300 import evaluate_p300, p300_contract
from gauntlet.contracts.p300_repair import (
    build_p300_repair_request, verify_p300_repair,
)
from gauntlet.contracts.p300_live import (
    P300LiveRepairReceipt, run_live_p300_repair,
)
from gauntlet.remediation.contract_handoff import ContractRepairRequest
from gauntlet.remediation.contract_verification import ContractRepairExecutor
from gauntlet.remediation.fake import FakeRemediationProvider
from gauntlet.remediation.models import (
    GeneratedEditCandidate,
    GeneratedTestCandidate,
    RepairProposal,
    RemediationRequest,
    StructuredRegressionTest,
    StructuredSourceEdit,
)
from gauntlet.remediation.prompt import (
    CONTRACT_EDIT_SYSTEM_PROMPT,
    CONTRACT_TEST_SYSTEM_PROMPT,
    build_edit_messages,
    build_test_messages,
)
from gauntlet.remediation.workflow import (
    generate_contract_repair_proposal, generate_repair_proposal,
)
from gauntlet.sandbox.workspace import repository_digest
from victims.customer_support.app import create_app
from victims.refund_support.agent import RefundSupportAgent


ROOT = Path(__file__).parents[1]
LIMIT = p300_contract(autonomous_limit_minor=5_000)


def p300_request():
    execution = RefundSupportAgent().refund_order(
        order_id="handoff-case", amount="500.00"
    )
    assert evaluate_p300(execution.trace, LIMIT).status == ContractStatus.VIOLATED
    return build_p300_repair_request(
        execution=execution, contract=LIMIT, repository_root=ROOT
    )


class IneffectiveStructuralProvider:
    """Exercises the bridge without containing a repair for the violation."""

    provider_name = "offline-structural-provider"
    model_name = "ineffective-comment-candidate"

    async def generate_edit(self, request: RemediationRequest) -> str:
        source = request.source_context
        return GeneratedEditCandidate(
            rationale="Add a harmless marker; this does not claim to repair the property.",
            source_edit=StructuredSourceEdit(
                target_path=source.repository_relative_path,
                target_symbol=source.target_symbol,
                source_hash=source.source_hash,
                start_line=11,
                delete_line_count=0,
                replacement_lines=["        # candidate evaluated independently"],
            ),
            optional_policy_artifact=None,
        ).model_dump_json()

    async def generate_test(
        self, request: RemediationRequest, *, derived_patch: str,
    ) -> str:
        return GeneratedTestCandidate(
            regression_test=StructuredRegressionTest(lines=[
                "def test_candidate_is_not_automatically_trusted():",
                "    assert True",
            ])
        ).model_dump_json()


def test_p300_violation_becomes_generic_serializable_repair_request():
    request = p300_request()
    restored = ContractRepairRequest.model_validate_json(request.model_dump_json())

    assert restored == request
    assert restored.contract.contract_id == "P300-effect-authorization"
    assert restored.violation.status == ContractStatus.VIOLATED
    assert restored.counterexample_trace.trace_id == restored.violation.trace_id
    assert restored.source_context.repository_relative_path == (
        "victims/refund_support/agent.py"
    )
    assert restored.source_context.target_symbol == "RefundSupportAgent.refund_order"
    assert restored.expected_security_property
    assert len(restored.legitimate_behaviors_to_preserve) == 4


def test_generic_handoff_and_prompts_have_no_refund_specific_logic():
    generic_files = [
        ROOT / "src/gauntlet/remediation/contract_handoff.py",
        ROOT / "src/gauntlet/remediation/contract_verification.py",
        ROOT / "src/gauntlet/remediation/workflow.py",
    ]
    for path in generic_files:
        text = path.read_text().lower()
        assert "refund_order" not in text
        assert "$50" not in text
        assert "customer_support" not in text


def test_contract_request_selects_generic_provider_prompts():
    request = p300_request()
    from gauntlet.remediation.contract_handoff import to_remediation_request

    adapted = to_remediation_request(
        request, provider="offline", model="fixture"
    )
    edit = build_edit_messages(adapted)
    test = build_test_messages(adapted, derived_patch="example")

    assert edit[0]["content"] == CONTRACT_EDIT_SYSTEM_PROMPT
    assert test[0]["content"] == CONTRACT_TEST_SYSTEM_PROMPT
    assert "refund_order" not in edit[0]["content"]
    assert "P100" not in edit[0]["content"]
    assert "contract" in edit[1]["content"]
    assert "counterexample_trace" in edit[1]["content"]


async def test_p100_legacy_repair_entry_point_remains_compatible():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://legacy"
    ) as client:
        trace = (await IndirectPromptInjectionAttack(client).run()).trace

    result = await generate_repair_proposal(
        trace.model_dump_json(), ROOT, FakeRemediationProvider()
    )
    assert isinstance(result, RepairProposal)
    assert result.failure_type == "indirect_prompt_injection"


async def test_p300_proposal_uses_existing_validation_and_contract_reverification():
    before = repository_digest(ROOT)
    request = p300_request()
    proposal = await generate_contract_repair_proposal(
        request, ROOT, IneffectiveStructuralProvider()
    )
    assert isinstance(proposal, RepairProposal)
    assert proposal.failure_type == request.contract.contract_id

    async def verifier(workspace_root: Path):
        return await verify_p300_repair(workspace_root, contract=LIMIT)

    assessment = await ContractRepairExecutor(ROOT).run(proposal, verifier)

    assert assessment.source_identity == "PASS"
    assert assessment.patch_application and assessment.patch_application.passed
    assert assessment.compilation and assessment.compilation.passed
    assert assessment.reverification is not None
    assert [case.case_id for case in assessment.reverification.cases] == [
        "high_value_without_approval_blocked",
        "alternate_high_value_without_approval_blocked",
        "approval_before_effect_allowed",
        "approval_after_effect_not_authorized",
        "low_value_behavior_preserved",
        "boundary_value_behavior_preserved",
        "alternate_threshold_honored",
    ]
    by_id = {case.case_id: case for case in assessment.reverification.cases}
    assert not by_id["high_value_without_approval_blocked"].expected_behavior_observed
    assert not by_id[
        "alternate_high_value_without_approval_blocked"
    ].expected_behavior_observed
    assert not by_id["approval_after_effect_not_authorized"].expected_behavior_observed
    assert by_id["approval_before_effect_allowed"].expected_behavior_observed
    assert by_id["low_value_behavior_preserved"].expected_behavior_observed
    assert by_id["boundary_value_behavior_preserved"].expected_behavior_observed
    assert by_id["alternate_threshold_honored"].expected_behavior_observed
    assert assessment.verdict == "NOT_VERIFIED"
    assert assessment.cleanup == "PASS"
    assert assessment.repository_immutability == "PASS"
    assert repository_digest(ROOT) == before


async def test_one_shot_p300_run_persists_integrity_bound_not_verified_receipt(
    tmp_path,
):
    before = repository_digest(ROOT)
    receipt, path = await run_live_p300_repair(
        request=p300_request(),
        repository_root=ROOT,
        provider=IneffectiveStructuralProvider(),
        evidence_root=tmp_path,
    )
    restored = P300LiveRepairReceipt.model_validate_json(path.read_text())

    assert restored == receipt
    assert receipt.provider_requests == 2
    assert [call.phase for call in receipt.provider_calls] == ["edit", "test"]
    assert receipt.exact_proposed_edit is not None
    assert receipt.candidate_artifact is not None
    assert receipt.validation_outcome == "PASS"
    assert receipt.sandbox_assessment is not None
    assert receipt.sandbox_assessment.verdict == "NOT_VERIFIED"
    assert receipt.p100_regression is not None and receipt.p100_regression.passed
    assert receipt.final_status == "NOT_VERIFIED"
    assert receipt.repository_immutability == "PASS"
    assert repository_digest(ROOT) == before
