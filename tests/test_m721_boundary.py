import hashlib
from pathlib import Path

from gauntlet.demo.m72 import LiveRunEvidence
from gauntlet.remediation.candidate_artifact import load_candidate_artifact
from gauntlet.remediation.models import (
    GeneratedEditCandidate, RepairContext, RepairFailure, RepairProposal,
)
from gauntlet.remediation.validation import validate_source_edit
from gauntlet.sandbox.workspace import repository_digest


ROOT = Path(__file__).parents[1]
FAILED = ROOT / (
    "evidence/m7-live/m7-live-20260929T072344Z.candidates/"
    "b1b28d1b-ceef-4de6-97c9-9d8a76cf6026.json"
)
SUCCESSFUL = ROOT / (
    "evidence/live-m42-repair-run.candidates/"
    "attempt-03-6a64deaf-c0a5-48d7-ada2-83a8e1701f62.json"
)


def context(artifact):
    return RepairContext(
        trace_id=artifact.trace_id, boundary_id=artifact.boundary_id,
        evidence_ids=artifact.evidence_ids, provider=artifact.provider,
        model=artifact.model, target_path=artifact.target_path,
        target_symbol=artifact.target_symbol, source_hash=artifact.source_hash,
        failure_type="indirect_prompt_injection",
    )


def revised(artifact, *, start, delete, replacement):
    source_edit = artifact.source_edit.model_copy(update={
        "start_line": start, "delete_line_count": delete,
        "replacement_lines": replacement,
    })
    return GeneratedEditCandidate(
        rationale=artifact.rationale, source_edit=source_edit,
        optional_policy_artifact=artifact.optional_policy_artifact,
    )


def symbol_lines():
    return (ROOT / "victims/customer_support/agent.py").read_text().splitlines()[15:48]


def test_range_ending_inside_multiline_call_is_rejected_exactly():
    artifact = load_candidate_artifact(FAILED)
    result = validate_source_edit(
        GeneratedEditCandidate(
            rationale=artifact.rationale, source_edit=artifact.source_edit,
            optional_policy_artifact=artifact.optional_policy_artifact,
        ), context(artifact), ROOT,
    )
    assert isinstance(result, RepairFailure)
    assert result.failure_code == "edit_range_splits_python_construct"
    assert result.diagnostics == {
        "start_line": 2, "delete_line_count": 28, "selected_end_line": 29,
        "construct": "delimiter_(", "construct_start_line": 26,
        "construct_end_line": 30, "split_boundary": "end",
    }


def test_range_beginning_inside_multiline_call_is_rejected():
    artifact = load_candidate_artifact(FAILED)
    lines = symbol_lines()
    edit = revised(
        artifact, start=18, delete=8,
        replacement=[line for line in lines[17:25]],
    )
    result = validate_source_edit(edit, context(artifact), ROOT)
    assert isinstance(result, RepairFailure)
    assert result.failure_code == "edit_range_splits_python_construct"
    assert result.diagnostics["split_boundary"] == "start"


def test_complete_multiline_construct_replacement_is_accepted():
    artifact = load_candidate_artifact(FAILED)
    lines = symbol_lines()
    replacement = list(lines[16:25])
    replacement[0] += "  # complete construct"
    result = validate_source_edit(
        revised(artifact, start=17, delete=9, replacement=replacement),
        context(artifact), ROOT,
    )
    assert isinstance(result, str)
    assert "+                events[-1].context_flow = ContextFlow(  # complete construct" in result


def test_ordinary_complete_statement_range_is_accepted():
    artifact = load_candidate_artifact(FAILED)
    lines = symbol_lines()
    replacement = [lines[1] + "  # complete statement"]
    result = validate_source_edit(
        revised(artifact, start=2, delete=1, replacement=replacement),
        context(artifact), ROOT,
    )
    assert isinstance(result, str)


def test_range_and_indentation_are_never_corrected():
    artifact = load_candidate_artifact(FAILED)
    lines = symbol_lines()
    invalid = "            " + lines[1]
    edit = revised(artifact, start=2, delete=1, replacement=[invalid])
    result = validate_source_edit(edit, context(artifact), ROOT)
    assert isinstance(result, RepairFailure)
    assert result.failure_code == "reconstructed_source_invalid_python"
    assert result.diagnostics["start_line"] == 2
    assert result.diagnostics["delete_line_count"] == 1
    assert edit.source_edit.replacement_lines == [invalid]


def test_failed_live_candidate_is_rejected_before_patch_or_compile():
    before = repository_digest(ROOT)
    artifact = load_candidate_artifact(FAILED)
    materialized = {}
    result = validate_source_edit(
        GeneratedEditCandidate(
            rationale=artifact.rationale, source_edit=artifact.source_edit,
            optional_policy_artifact=artifact.optional_policy_artifact,
        ), context(artifact), ROOT, materialized_output=materialized,
    )
    assert isinstance(result, RepairFailure)
    assert result.failure_stage == "patch_authorization"
    assert materialized == {}
    live = LiveRunEvidence.model_validate_json(
        (ROOT / "evidence/m7-live/m7-live-20260929T072344Z.json").read_text()
    )
    assert live.candidate_id == artifact.candidate_id
    assert live.final_verdict == "NOT_VERIFIED"
    assert repository_digest(ROOT) == before


def test_retained_successful_attempt3_remains_accepted():
    artifact = load_candidate_artifact(SUCCESSFUL)
    result = validate_source_edit(
        GeneratedEditCandidate(
            rationale=artifact.rationale, source_edit=artifact.source_edit,
            optional_policy_artifact=artifact.optional_policy_artifact,
        ), context(artifact), ROOT,
    )
    assert isinstance(result, str)
    assert hashlib.sha256(result.encode()).hexdigest() == artifact.derived_patch_digest


def test_m71_replay_and_historical_evidence_are_unchanged_by_validation():
    paths = [
        ROOT / "demo/gauntlet-m7.html", FAILED, SUCCESSFUL,
        ROOT / "evidence/m7-live/m7-live-20260929T072344Z.json",
    ]
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    artifact = load_candidate_artifact(FAILED)
    validate_source_edit(
        GeneratedEditCandidate(
            rationale=artifact.rationale, source_edit=artifact.source_edit,
            optional_policy_artifact=artifact.optional_policy_artifact,
        ), context(artifact), ROOT,
    )
    assert before == {
        path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths
    }
