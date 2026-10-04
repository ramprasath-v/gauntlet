from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError

from gauntlet.contracts.p400_live_repair import (
    build_live_p400_repair_request,
    load_p400_live_attack,
)
from gauntlet.remediation.contract_handoff import (
    to_multi_target_remediation_request,
)
from gauntlet.remediation.models import (
    GeneratedEditCandidate,
    GeneratedMultiEditCandidate,
    RepairFailure,
    StructuredSourceEdit,
)
from gauntlet.remediation.multi_target import validate_multi_target_edit
from gauntlet.remediation.validation import validate_source_edit
from gauntlet.sandbox.workspace import repository_digest


ROOT = Path(__file__).parents[1]
LIVE_ATTACK = (
    ROOT / "evidence" / "p400-live"
    / "live-f43d28c4-c2ba-4884-a532-e3dd98d42b1d.json"
)


def _request():
    contract_request = build_live_p400_repair_request(
        live_attack=load_p400_live_attack(LIVE_ATTACK), repository_root=ROOT,
    )
    return to_multi_target_remediation_request(
        contract_request, provider="offline_test", model="synthetic_test_double",
    )


def _valid_edits():
    request = _request()
    agent, memory = request.source_contexts
    agent_lines = agent.source_text.splitlines()
    loop = agent_lines.index("        for item in context_items:") + 1
    start = agent_lines.index("        context_event_ids: list[str] = []") + 1
    output = agent_lines.index("        output = NormalizedExecutionEvent(") + 1
    loop_body = agent_lines[loop:output - 1]
    agent_edit = StructuredSourceEdit(
        target_path=agent.repository_relative_path,
        target_symbol=agent.target_symbol,
        source_hash=agent.source_hash,
        start_line=start,
        delete_line_count=output - start,
        replacement_lines=[
            "        from gauntlet.contracts.context_authorization import (",
            "            authorize_context_item,",
            "        )",
            "        authorized_context_items = tuple(",
            "            item for item in context_items",
            "            if authorize_context_item(",
            "                item, authorization_grants,",
            "                active_principal=principal,",
            "                active_purpose=active_purpose,",
            "                activated_dimensions=activated_personalization_dimensions,",
            "            ).authorized",
            "        )",
            "        context_event_ids: list[str] = []",
            "        for item in authorized_context_items:",
            *loop_body,
        ],
    )
    memory_lines = memory.source_text.splitlines()
    memory_edit = StructuredSourceEdit(
        target_path=memory.repository_relative_path,
        target_symbol=memory.target_symbol,
        source_hash=memory.source_hash,
        start_line=memory_lines.index(
            "        eligible_for_personalization = True"
        ) + 1,
        delete_line_count=1,
        replacement_lines=[
            "        eligible_for_personalization = (",
            "            source_trust == TrustClassification.TRUSTED",
            "        )",
        ],
    )
    return request, agent_edit, memory_edit


def _candidate(*edits: StructuredSourceEdit) -> GeneratedMultiEditCandidate:
    return GeneratedMultiEditCandidate(
        rationale="Enforce the complete property at both bounded sources.",
        source_edits=list(edits),
    )


def test_two_authorized_contexts_and_one_edit_each_materialize_deterministically():
    before = repository_digest(ROOT)
    request, agent_edit, memory_edit = _valid_edits()
    result = validate_multi_target_edit(
        _candidate(memory_edit, agent_edit), request.repair_contexts, ROOT,
    )

    assert not isinstance(result, RepairFailure)
    assert len(request.source_contexts) == len(result.edits) == 2
    assert [edit.context.target_symbol for edit in result.edits] == [
        "PersonalizationAgent.respond", "PersonalMemoryStore.ingest",
    ]
    assert result.combined_patch.count("--- a/victims/personalization/") == 2
    assert result.combined_patch_digest == sha256(
        result.combined_patch.encode()
    ).hexdigest()
    assert all(
        edit.patch_digest == sha256(edit.derived_patch.encode()).hexdigest()
        for edit in result.edits
    )
    assert repository_digest(ROOT) == before


def test_unknown_third_target_and_symbol_escape_are_rejected():
    request, agent_edit, _ = _valid_edits()
    unknown = agent_edit.model_copy(update={
        "target_path": "victims/personalization/other.py",
        "target_symbol": "Other.run",
    })
    result = validate_multi_target_edit(
        _candidate(agent_edit, unknown), request.repair_contexts, ROOT,
    )
    assert isinstance(result, RepairFailure)
    assert result.failure_code == "unauthorized_edit_target"

    escaped = agent_edit.model_copy(update={"target_symbol": "Other.respond"})
    result = validate_multi_target_edit(
        _candidate(escaped), request.repair_contexts, ROOT,
    )
    assert isinstance(result, RepairFailure)
    assert result.failure_code == "unauthorized_edit_target"


def test_duplicate_and_more_than_two_edits_are_schema_rejected():
    _, agent_edit, memory_edit = _valid_edits()
    with pytest.raises(ValidationError, match="duplicate source boundaries"):
        _candidate(agent_edit, agent_edit)
    with pytest.raises(ValidationError):
        _candidate(agent_edit, memory_edit, agent_edit)


def test_hash_mismatch_and_split_range_reject_whole_candidate_without_mutation():
    before = repository_digest(ROOT)
    request, agent_edit, memory_edit = _valid_edits()
    stale = memory_edit.model_copy(update={"source_hash": "0" * 64})
    result = validate_multi_target_edit(
        _candidate(agent_edit, stale), request.repair_contexts, ROOT,
    )
    assert isinstance(result, RepairFailure)
    assert result.failure_code == "candidate_source_hash_mismatch"

    agent_source = request.source_contexts[0]
    lines = agent_source.source_text.splitlines()
    split = agent_edit.model_copy(update={
        "start_line": next(
            index for index, line in enumerate(lines, 1)
            if "event_type=NormalizedEventType.DATA_READ" in line
        ),
        "delete_line_count": 1,
        "replacement_lines": [
            "                event_type=NormalizedEventType.DATA_READ,"
        ],
    })
    result = validate_multi_target_edit(
        _candidate(split, memory_edit), request.repair_contexts, ROOT,
    )
    assert isinstance(result, RepairFailure)
    assert result.failure_code in {
        "edit_range_splits_python_construct",
        "edit_range_splits_compound_statement",
    }
    assert repository_digest(ROOT) == before


def test_existing_single_target_validator_remains_compatible():
    request, agent_edit, _ = _valid_edits()
    legacy = GeneratedEditCandidate(
        rationale="A bounded legacy edit.", source_edit=agent_edit,
    )
    result = validate_source_edit(legacy, request.repair_contexts[0], ROOT)
    assert isinstance(result, str)
    assert result.startswith("--- a/victims/personalization/agent.py")
