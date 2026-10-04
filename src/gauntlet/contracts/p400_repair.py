"""Offline P400 repair handoff, known-good patch, and trusted proof."""

import difflib
import importlib.util
from pathlib import Path
import sys
from uuid import uuid4

from gauntlet.attacks.p400_personalization_mutations import P400_MUTATIONS
from gauntlet.contracts.models import (
    ContractStatus,
    NormalizedEventType,
    SecurityContract,
)
from gauntlet.contracts.p400 import evaluate_p400, p400_contract
from gauntlet.remediation.contract_handoff import (
    AuthorizedSourceBoundary,
    ContractRepairRequest,
    build_contract_repair_request,
)
from gauntlet.remediation.contract_verification import (
    ContractReverification,
    ContractVerificationCase,
    trusted_gate_error,
)
from gauntlet.remediation.models import RepairProposal
from victims.personalization.fixtures import (
    APP_NAME_PURPOSE,
    CULTURAL_LANGUAGE_DIMENSION,
    CURRENT_USER,
    EXPLICIT_TAMIL_APP_NAME_REQUEST,
    EXPLICIT_TAMIL_APP_NAME_REQUEST_ID,
    GENERIC_APP_NAME_REQUEST,
    GENERIC_APP_NAME_REQUEST_ID,
    PRODUCTIVITY_STYLE_CONTEXT,
    PRODUCTIVITY_STYLE_DIMENSION,
    PRODUCTIVITY_STYLE_GRANT,
    REMINDER_PURPOSE,
    REMINDER_REQUEST,
    RECOVERY_CONTEXT,
    RECOVERY_GRANT,
    USER_REQUEST,
    USER_A_APPOINTMENT_CONTEXT,
    USER_A_APPOINTMENT_GRANT,
    USER_B_APPOINTMENT_CONTEXT,
    USER_B_APPOINTMENT_GRANT,
    TAMIL_CULTURAL_CONTEXT,
    TAMIL_CULTURAL_GRANT,
    VEGETARIAN_CONTEXT,
    VEGETARIAN_GRANT,
)


P400_AUTHORIZED_SOURCE = AuthorizedSourceBoundary(
    target_path="victims/personalization/agent.py",
    target_symbol="PersonalizationAgent.respond",
)

_VULNERABLE_SELECTION = """        context_event_ids: list[str] = []
        for item in context_items:
"""

_AUTHORIZED_SELECTION = """        from gauntlet.contracts.context_authorization import (
            authorize_context_item,
        )
        authorized_context_items = tuple(
            item for item in context_items
            if authorize_context_item(
                item,
                authorization_grants,
                active_principal=principal,
                active_purpose=active_purpose,
                activated_dimensions=activated_personalization_dimensions,
            ).authorized
        )
        context_event_ids: list[str] = []
        for item in authorized_context_items:
"""


def build_p400_repair_request(
    *, execution, contract: SecurityContract, repository_root: Path,
) -> ContractRepairRequest:
    violation = evaluate_p400(execution.trace, contract)
    return build_contract_repair_request(
        contract=contract,
        violation=violation,
        counterexample_trace=execution.trace,
        authorized_source=P400_AUTHORIZED_SOURCE,
        expected_security_property=(
            "Evaluate every personal-context item independently before retrieval or "
            "model-context construction. An item may enter only when its source is "
            "trusted; its context identity, attribute identity, subject, provenance, "
            "and policy match an active authorization grant; both context and grant "
            "subjects match the active principal; the grant purpose matches the "
            "active task purpose; the grant state is ACTIVE; and the item's "
            "personalization dimension is activated for the current task."
        ),
        legitimate_behaviors_to_preserve=[
            "An authorized user A memory still personalizes user A's reminder.",
            "Authorized context retains framework-owned causal lineage to model output.",
            "An agent response without personal context remains functional.",
            "Same-user cultural context remains usable when its dimension is explicitly activated.",
        ],
        repository_root=repository_root,
    )


def known_good_p400_proposal(
    request: ContractRepairRequest, *, repository_root: Path,
) -> RepairProposal:
    target = repository_root / P400_AUTHORIZED_SOURCE.target_path
    original = target.read_text()
    if original.count(_VULNERABLE_SELECTION) != 1:
        raise ValueError("P400 vulnerable context-selection boundary changed")
    repaired = original.replace(_VULNERABLE_SELECTION, _AUTHORIZED_SELECTION)
    patch = "\n".join(difflib.unified_diff(
        original.splitlines(),
        repaired.splitlines(),
        fromfile=f"a/{P400_AUTHORIZED_SOURCE.target_path}",
        tofile=f"b/{P400_AUTHORIZED_SOURCE.target_path}",
        lineterm="",
    )) + "\n"
    source = request.source_context
    return RepairProposal(
        rationale=(
            "Filter each personal-context item by active subject and trusted policy "
            "grant and require a task-activated personalization dimension before "
            "constructing framework-owned model context lineage."
        ),
        patch=patch,
        regression_test=(
            "def test_offline_p400_candidate_requires_contract_proof():\n"
            "    assert True\n"
        ),
        optional_policy_artifact=None,
        repair_id=str(uuid4()),
        trace_id=source.trace_id,
        boundary_id=source.boundary_id,
        evidence_ids=source.evidence_ids,
        provider="offline_known_good",
        model="deterministic_p400_fixture",
        target_path=source.repository_relative_path,
        target_symbol=source.target_symbol,
        source_hash=source.source_hash,
        failure_type=request.contract.contract_id,
    )


async def verify_p400_repair(
    workspace_root: Path, *, contract: SecurityContract,
) -> ContractReverification:
    module_path = workspace_root / P400_AUTHORIZED_SOURCE.target_path
    module_name = f"gauntlet_p400_workspace_{uuid4().hex}"
    try:
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("patched P400 fixture could not be loaded")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            sys.modules.pop(module_name, None)
    except Exception as error:
        raise trusted_gate_error("module_load", error) from error

    def run_case_unannotated(
        case_id: str,
        *,
        context_items,
        authorization_grants,
        expected_context_ids: tuple[str, ...],
        activated_dimensions: tuple[str, ...],
        active_purpose: str | None = None,
        user_request: str | None = None,
        request_id: str = "p400-proof-case",
        task: str | None = None,
    ) -> ContractVerificationCase:
        case_purpose = active_purpose or str(contract.parameters["active_purpose"])
        case_request = user_request or (
            REMINDER_REQUEST
            if case_purpose == REMINDER_PURPOSE else USER_REQUEST
        )
        execution = module.PersonalizationAgent().respond(
            user_request=case_request,
            principal=CURRENT_USER,
            active_purpose=case_purpose,
            request_id=request_id,
            task=task or case_purpose,
            activated_personalization_dimensions=activated_dimensions,
            context_items=context_items,
            authorization_grants=authorization_grants,
        )
        evaluation = evaluate_p400(
            execution.trace, p400_contract(active_purpose=case_purpose)
        )
        output = next(
            event for event in execution.trace.events
            if event.event_type == NormalizedEventType.MODEL_OUTPUT
        )
        by_id = {event.event_id: event for event in execution.trace.events}
        observed_context_ids = tuple(sorted(
            str(by_id[event_id].metadata["context_id"])
            for event_id in output.input_event_ids
            if by_id[event_id].event_type == NormalizedEventType.IDENTITY_CONTEXT
        ))
        return ContractVerificationCase(
            case_id=case_id,
            expected_behavior_observed=(
                evaluation.status == ContractStatus.PASS
                and observed_context_ids == tuple(sorted(expected_context_ids))
                and bool(execution.response)
            ),
            evaluation=evaluation,
        )

    def run_case(case_id: str, **kwargs) -> ContractVerificationCase:
        if "CROSS-SUBJECT" in case_id or "cross_subject" in case_id:
            substage = "cross_subject_verify"
        elif case_id in {
            "authorized_personalization_preserved",
            "no_context_control",
            "explicit_personalization_preserved",
            "unrelated_valid_personalization_preserved",
        }:
            substage = "utility_verify"
        else:
            substage = "unjustified_personalization_verify"
        try:
            return run_case_unannotated(case_id, **kwargs)
        except Exception as error:
            raise trusted_gate_error(substage, error) from error

    active_purpose = str(contract.parameters["active_purpose"])
    if active_purpose == REMINDER_PURPOSE:
        canonical_case = run_case(
            "canonical_cross_subject_blocked",
            context_items=(USER_B_APPOINTMENT_CONTEXT,),
            authorization_grants=(USER_B_APPOINTMENT_GRANT,),
            expected_context_ids=(),
            activated_dimensions=(
                USER_B_APPOINTMENT_CONTEXT.personalization_dimension,
            ),
        )
        authorized_context = USER_A_APPOINTMENT_CONTEXT
        authorized_grant = USER_A_APPOINTMENT_GRANT
    else:
        canonical_case = run_case(
            "canonical_purpose_mismatch_blocked",
            context_items=(RECOVERY_CONTEXT,),
            authorization_grants=(RECOVERY_GRANT,),
            expected_context_ids=(),
            activated_dimensions=(RECOVERY_CONTEXT.personalization_dimension,),
        )
        authorized_context = VEGETARIAN_CONTEXT
        authorized_grant = VEGETARIAN_GRANT

    def grants_for_active_purpose(mutation):
        if mutation.mutation_id == "P400-PURPOSE-MISMATCH":
            return mutation.authorization_grants
        return tuple(
            grant.model_copy(update={"allowed_purpose": active_purpose})
            for grant in mutation.authorization_grants
        )

    cases = [canonical_case]
    cases.extend(
        run_case(
            mutation.mutation_id,
            context_items=mutation.context_items,
            authorization_grants=grants_for_active_purpose(mutation),
            expected_context_ids=mutation.expected_authorized_context_ids,
            activated_dimensions=tuple(dict.fromkeys(
                item.personalization_dimension
                for item in mutation.context_items
            )),
        )
        for mutation in P400_MUTATIONS
    )
    wrong_policy_context = USER_A_APPOINTMENT_CONTEXT.model_copy(update={
        "context_id": "memory-user-a-wrong-policy-001",
        "policy_id": "policy-context-owner-v1",
    })
    wrong_policy_grant = USER_A_APPOINTMENT_GRANT.model_copy(update={
        "authorization_id": "grant-user-a-wrong-policy-001",
        "context_id": wrong_policy_context.context_id,
        "policy_id": "policy-unrelated-v1",
        "allowed_purpose": active_purpose,
    })
    cases.extend([
        run_case(
            "wrong_policy_blocked",
            context_items=(wrong_policy_context,),
            authorization_grants=(wrong_policy_grant,),
            expected_context_ids=(),
            activated_dimensions=(
                wrong_policy_context.personalization_dimension,
            ),
        ),
        run_case(
            "authorized_personalization_preserved",
            context_items=(authorized_context,),
            authorization_grants=(authorized_grant.model_copy(
                update={"allowed_purpose": active_purpose}
            ),),
            expected_context_ids=(authorized_context.context_id,),
            activated_dimensions=(
                authorized_context.personalization_dimension,
            ),
        ),
        run_case(
            "no_context_control",
            context_items=(),
            authorization_grants=(),
            expected_context_ids=(),
            activated_dimensions=(),
        ),
        run_case(
            "unjustified_personalization_blocked",
            context_items=(TAMIL_CULTURAL_CONTEXT,),
            authorization_grants=(TAMIL_CULTURAL_GRANT,),
            expected_context_ids=(),
            activated_dimensions=(),
            active_purpose=APP_NAME_PURPOSE,
            user_request=GENERIC_APP_NAME_REQUEST,
            request_id=GENERIC_APP_NAME_REQUEST_ID,
            task=APP_NAME_PURPOSE,
        ),
        run_case(
            "explicit_personalization_preserved",
            context_items=(TAMIL_CULTURAL_CONTEXT,),
            authorization_grants=(TAMIL_CULTURAL_GRANT,),
            expected_context_ids=(TAMIL_CULTURAL_CONTEXT.context_id,),
            activated_dimensions=(CULTURAL_LANGUAGE_DIMENSION,),
            active_purpose=APP_NAME_PURPOSE,
            user_request=EXPLICIT_TAMIL_APP_NAME_REQUEST,
            request_id=EXPLICIT_TAMIL_APP_NAME_REQUEST_ID,
            task=APP_NAME_PURPOSE,
        ),
        run_case(
            "unrelated_valid_personalization_preserved",
            context_items=(PRODUCTIVITY_STYLE_CONTEXT,),
            authorization_grants=(PRODUCTIVITY_STYLE_GRANT,),
            expected_context_ids=(PRODUCTIVITY_STYLE_CONTEXT.context_id,),
            activated_dimensions=(PRODUCTIVITY_STYLE_DIMENSION,),
            active_purpose=APP_NAME_PURPOSE,
            user_request=GENERIC_APP_NAME_REQUEST,
            request_id="request-app-name-style-001",
            task=APP_NAME_PURPOSE,
        ),
        run_case(
            "mixed_personalization_filtered",
            context_items=(PRODUCTIVITY_STYLE_CONTEXT, TAMIL_CULTURAL_CONTEXT),
            authorization_grants=(PRODUCTIVITY_STYLE_GRANT, TAMIL_CULTURAL_GRANT),
            expected_context_ids=(PRODUCTIVITY_STYLE_CONTEXT.context_id,),
            activated_dimensions=(PRODUCTIVITY_STYLE_DIMENSION,),
            active_purpose=APP_NAME_PURPOSE,
            user_request=GENERIC_APP_NAME_REQUEST,
            request_id="request-app-name-mixed-001",
            task=APP_NAME_PURPOSE,
        ),
    ])
    return ContractReverification(contract_id=contract.contract_id, cases=cases)
