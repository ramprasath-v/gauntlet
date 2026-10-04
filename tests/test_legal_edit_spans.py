import json
from pathlib import Path

from gauntlet.contracts.p400_live import P400_LIVE_MODEL
from gauntlet.contracts.p400_live_repair import (
    build_live_p400_repair_request,
    load_p400_live_attack,
)
from gauntlet.remediation.contract_handoff import (
    to_multi_target_remediation_request,
)
from gauntlet.remediation.legal_spans import derive_legal_edit_spans
from gauntlet.remediation.models import (
    GeneratedEditCandidate,
    RemediationRequest,
    RepairFailure,
    StructuredSourceEdit,
)
from gauntlet.remediation.prompt import (
    build_edit_messages,
    build_multi_target_edit_messages,
)
from gauntlet.remediation.validation import validate_source_edit
from gauntlet.sandbox.workspace import repository_digest


ROOT = Path(__file__).parents[1]
LIVE_ATTACK = (
    ROOT / "evidence" / "p400-live"
    / "live-f43d28c4-c2ba-4884-a532-e3dd98d42b1d.json"
)


def _p400_request():
    contract = build_live_p400_repair_request(
        live_attack=load_p400_live_attack(LIVE_ATTACK), repository_root=ROOT,
    )
    return to_multi_target_remediation_request(
        contract, provider="offline_test", model=P400_LIVE_MODEL,
    )


def test_p400_memory_assignment_and_complete_if_spans_are_explicit():
    memory = _p400_request().source_contexts[1]
    spans = {
        (item.start_line, item.end_line, item.statement_kind)
        for item in derive_legal_edit_spans(memory.source_text)
    }

    assert (48, 48, "Assign") in spans
    assert (49, 50, "If") in spans
    assert (48, 50, "Assign+If") in spans
    assert (49, 49, "If") not in spans


def test_all_supported_compound_headers_are_only_exposed_as_complete_ranges():
    source = """\
    def bounded():
        if ready:
            use_ready()
        for item in items:
            use(item)
        while waiting:
            poll()
        try:
            work()
        except RuntimeError:
            recover()
        with resource():
            consume()
    """
    spans = derive_legal_edit_spans(source)
    by_kind = {
        item.statement_kind: item for item in spans
        if item.statement_kind in {"If", "For", "While", "Try", "With"}
    }
    assert (by_kind["If"].start_line, by_kind["If"].end_line) == (2, 3)
    assert (by_kind["For"].start_line, by_kind["For"].end_line) == (4, 5)
    assert (by_kind["While"].start_line, by_kind["While"].end_line) == (6, 7)
    assert (by_kind["Try"].start_line, by_kind["Try"].end_line) == (8, 11)
    assert (by_kind["With"].start_line, by_kind["With"].end_line) == (12, 13)
    assert all(item.compound_statement for item in by_kind.values())
    for item in by_kind.values():
        assert not any(
            span.statement_kind == item.statement_kind
            and span.start_line == item.start_line
            and span.end_line < item.end_line
            for span in spans
        )


def test_multi_target_prompt_carries_target_local_spans_and_strict_instruction():
    request = _p400_request()
    messages = build_multi_target_edit_messages(request)
    payload = json.loads(messages[1]["content"])

    assert len(payload["source_contexts_line_numbered"]) == 2
    for context in payload["source_contexts_line_numbered"]:
        assert context["legal_edit_spans"]
        assert all(
            set(span) == {
                "start_line", "end_line", "delete_line_count",
                "statement_kind", "compound_statement",
            }
            for span in context["legal_edit_spans"]
        )
    prompt = messages[0]["content"]
    assert "select an exact `start_line` and" in prompt
    assert "Never select" in prompt and "only the header" in prompt
    assert "Gauntlet will not expand, correct" in prompt


def test_single_target_contract_prompt_remains_compatible_and_uses_spans():
    multi = _p400_request()
    request = RemediationRequest(
        source_context=multi.source_contexts[0],
        repair_context=multi.repair_contexts[0],
        evidence_summary={"request_kind": "contract_violation"},
    )
    messages = build_edit_messages(request)
    payload = json.loads(messages[1]["content"])

    assert payload["legal_edit_spans"]
    assert payload["source_context"]["target_symbol"] == (
        "PersonalizationAgent.respond"
    )
    assert "select an exact `start_line`" in messages[0]["content"]


def test_invalid_assignment_plus_if_header_remains_rejected_without_correction():
    before = repository_digest(ROOT)
    request = _p400_request()
    memory_context = request.repair_contexts[1]
    candidate = GeneratedEditCandidate(
        rationale="Change the ingress eligibility assignment.",
        source_edit=StructuredSourceEdit(
            target_path=memory_context.target_path,
            target_symbol=memory_context.target_symbol,
            source_hash=memory_context.source_hash,
            start_line=48,
            delete_line_count=2,
            replacement_lines=[
                "        eligible_for_personalization = (",
                "            source_trust == TrustClassification.TRUSTED",
                "        )",
            ],
        ),
    )
    result = validate_source_edit(candidate, memory_context, ROOT)

    assert isinstance(result, RepairFailure)
    assert result.failure_code == "edit_range_splits_compound_statement"
    assert result.diagnostics["start_line"] == 48
    assert result.diagnostics["delete_line_count"] == 2
    assert repository_digest(ROOT) == before
