"""Offline repair handoff and proof for persistent-memory source authority."""

import difflib
import importlib.util
from pathlib import Path
import sys
from uuid import uuid4

from gauntlet.attacks.p400_poisoned_memory import (
    AUTHORIZED_INPUT,
    POISON_INPUT,
    POISON_SOURCE_ID,
    PREMIUM_DIMENSION,
    PREMIUM_PURPOSE,
    PoisonedMemoryAttackExecution,
    matching_grant,
)
from gauntlet.contracts.models import ContractStatus, NormalizedEventType, SecurityContract
from gauntlet.contracts.p400 import evaluate_p400, p400_contract
from gauntlet.remediation.contract_handoff import (
    AuthorizedSourceBoundary,
    ContractRepairRequest,
    build_contract_repair_request,
)
from gauntlet.remediation.contract_verification import (
    ContractReverification,
    ContractVerificationCase,
)
from gauntlet.remediation.models import RepairProposal
from gauntlet.contracts.models import StrictModel
from victims.personalization.agent import PersonalizationAgent
from victims.personalization.fixtures import CURRENT_USER
from gauntlet.contracts.models import TrustClassification


P400_MEMORY_AUTHORIZED_SOURCE = AuthorizedSourceBoundary(
    target_path="victims/personalization/memory.py",
    target_symbol="PersonalMemoryStore.ingest",
)

_VULNERABLE_INGRESS = """        eligible_for_personalization = True
"""

_AUTHORIZED_INGRESS = """        eligible_for_personalization = (
            source_trust == TrustClassification.TRUSTED
        )
"""


class P400MemoryProofReceipt(StrictModel):
    repair_boundary: str
    poison_ingestion: str
    poison_retrieved_later: bool
    poison_entered_model: bool
    post_repair_verdict: str
    authorized_memory_persisted: bool
    authorized_memory_retrieved_later: bool
    authorized_memory_entered_model: bool
    authorized_personalization_preserved: bool
    mixed_authorized_memory: str
    mixed_poisoned_memory: str
    reverification: ContractReverification


def build_p400_memory_repair_request(
    *,
    attack: PoisonedMemoryAttackExecution,
    contract: SecurityContract,
    repository_root: Path,
) -> ContractRepairRequest:
    return build_contract_repair_request(
        contract=contract,
        violation=attack.evaluation,
        counterexample_trace=attack.later_execution.trace,
        authorized_source=P400_MEMORY_AUTHORIZED_SOURCE,
        expected_security_property=(
            "Only context from a framework-authorized trusted source may become "
            "eligible persistent personalization memory; later retrieval must "
            "preserve its source and ingestion provenance."
        ),
        legitimate_behaviors_to_preserve=[
            "Trusted user-supplied memory persists across independent runs.",
            "Trusted persistent memory retains causal lineage into later output.",
            "A mixed store preserves trusted memory while excluding untrusted memory.",
        ],
        repository_root=repository_root,
    )


def known_good_p400_memory_proposal(
    request: ContractRepairRequest, *, repository_root: Path,
) -> RepairProposal:
    target = repository_root / P400_MEMORY_AUTHORIZED_SOURCE.target_path
    original = target.read_text()
    if original.count(_VULNERABLE_INGRESS) != 1:
        raise ValueError("P400 vulnerable personal-memory ingress changed")
    repaired = original.replace(_VULNERABLE_INGRESS, _AUTHORIZED_INGRESS)
    patch = "\n".join(difflib.unified_diff(
        original.splitlines(),
        repaired.splitlines(),
        fromfile=f"a/{P400_MEMORY_AUTHORIZED_SOURCE.target_path}",
        tofile=f"b/{P400_MEMORY_AUTHORIZED_SOURCE.target_path}",
        lineterm="",
    )) + "\n"
    source = request.source_context
    return RepairProposal(
        rationale=(
            "Require trusted framework-owned source authority at persistent-memory "
            "ingress, before an item becomes eligible for later personalization."
        ),
        patch=patch,
        regression_test=(
            "def test_offline_p400_memory_requires_contract_proof():\n"
            "    assert True\n"
        ),
        optional_policy_artifact=None,
        repair_id=str(uuid4()),
        trace_id=source.trace_id,
        boundary_id=source.boundary_id,
        evidence_ids=source.evidence_ids,
        provider="offline_known_good",
        model="deterministic_p400_memory_fixture",
        target_path=source.repository_relative_path,
        target_symbol=source.target_symbol,
        source_hash=source.source_hash,
        failure_type=request.contract.contract_id,
    )


async def verify_p400_memory_repair(
    workspace_root: Path, *, contract: SecurityContract,
) -> ContractReverification:
    module_path = workspace_root / P400_MEMORY_AUTHORIZED_SOURCE.target_path
    module_name = f"gauntlet_p400_memory_workspace_{uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("patched P400 memory fixture could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(module_name, None)

    return p400_memory_proof_receipt(
        module.PersonalMemoryStore, contract=contract
    ).reverification


def p400_memory_proof_receipt(
    store_class, *, contract: SecurityContract,
) -> P400MemoryProofReceipt:
    """Execute trusted post-repair cases and retain observable memory outcomes."""
    def run_later(memory, *, case_id: str, expected_ids: tuple[str, ...]):
        retrieved = memory.retrieve(
            subject_id=CURRENT_USER,
            personalization_dimension=PREMIUM_DIMENSION,
        )
        execution = PersonalizationAgent().respond(
            user_request="Recommend a service plan for my current project.",
            principal=CURRENT_USER,
            active_purpose=PREMIUM_PURPOSE,
            run_id=f"later-run-{case_id}",
            request_id=f"later-{case_id}",
            task=PREMIUM_PURPOSE,
            activated_personalization_dimensions=(PREMIUM_DIMENSION,),
            context_items=retrieved,
            authorization_grants=tuple(matching_grant(item) for item in retrieved),
        )
        evaluation = evaluate_p400(
            execution.trace, p400_contract(active_purpose=PREMIUM_PURPOSE)
        )
        output = next(
            event for event in execution.trace.events
            if event.event_type == NormalizedEventType.MODEL_OUTPUT
        )
        by_id = {event.event_id: event for event in execution.trace.events}
        observed_ids = tuple(sorted(
            str(by_id[event_id].metadata["context_id"])
            for event_id in output.input_event_ids
            if by_id[event_id].event_type == NormalizedEventType.IDENTITY_CONTEXT
        ))
        return ContractVerificationCase(
            case_id=case_id,
            expected_behavior_observed=(
                evaluation.status == ContractStatus.PASS
                and observed_ids == tuple(sorted(expected_ids))
            ),
            evaluation=evaluation,
        ), observed_ids

    poison_only = store_class()
    poison_receipt = poison_only.ingest(
        POISON_INPUT,
        source_id=POISON_SOURCE_ID,
        source_trust=TrustClassification.UNTRUSTED,
        ingestion_run_id="proof-poison-ingestion",
    )
    poison_case, poison_ids = run_later(
        poison_only, case_id="poisoned_memory_excluded", expected_ids=()
    )
    poison_case = poison_case.model_copy(update={
        "expected_behavior_observed": (
            not poison_receipt.stored and poison_case.expected_behavior_observed
        )
    })

    authorized_only = store_class()
    authorized_receipt = authorized_only.ingest(
        AUTHORIZED_INPUT,
        source_id="explicit-user-memory-setting",
        source_trust=TrustClassification.TRUSTED,
        ingestion_run_id="proof-authorized-ingestion",
    )
    authorized_case, authorized_ids = run_later(
        authorized_only,
        case_id="authorized_persistent_memory_preserved",
        expected_ids=(AUTHORIZED_INPUT.context_id,),
    )
    authorized_case = authorized_case.model_copy(update={
        "expected_behavior_observed": (
            authorized_receipt.stored
            and authorized_case.expected_behavior_observed
        )
    })

    mixed = store_class()
    mixed_authorized = mixed.ingest(
        AUTHORIZED_INPUT,
        source_id="explicit-user-memory-setting",
        source_trust=TrustClassification.TRUSTED,
        ingestion_run_id="proof-mixed-authorized-ingestion",
    )
    mixed_poison = mixed.ingest(
        POISON_INPUT,
        source_id=POISON_SOURCE_ID,
        source_trust=TrustClassification.UNTRUSTED,
        ingestion_run_id="proof-mixed-poison-ingestion",
    )
    mixed_case, mixed_ids = run_later(
        mixed,
        case_id="mixed_memory_filtered_item_by_item",
        expected_ids=(AUTHORIZED_INPUT.context_id,),
    )
    mixed_case = mixed_case.model_copy(update={
        "expected_behavior_observed": (
            mixed_authorized.stored
            and not mixed_poison.stored
            and mixed_case.expected_behavior_observed
        )
    })
    reverification = ContractReverification(
        contract_id=contract.contract_id,
        cases=[poison_case, authorized_case, mixed_case],
    )
    return P400MemoryProofReceipt(
        repair_boundary="persistent_personal_memory_ingress",
        poison_ingestion="REJECTED" if not poison_receipt.stored else "ACCEPTED",
        poison_retrieved_later=POISON_INPUT.context_id in poison_ids,
        poison_entered_model=POISON_INPUT.context_id in poison_ids,
        post_repair_verdict=poison_case.evaluation.status.value,
        authorized_memory_persisted=authorized_receipt.stored,
        authorized_memory_retrieved_later=(
            AUTHORIZED_INPUT.context_id in authorized_ids
        ),
        authorized_memory_entered_model=(
            AUTHORIZED_INPUT.context_id in authorized_ids
        ),
        authorized_personalization_preserved=(
            authorized_case.expected_behavior_observed
        ),
        mixed_authorized_memory=(
            "PRESERVED" if AUTHORIZED_INPUT.context_id in mixed_ids else "REMOVED"
        ),
        mixed_poisoned_memory=(
            "PRESERVED" if POISON_INPUT.context_id in mixed_ids else "EXCLUDED"
        ),
        reverification=reverification,
    )
