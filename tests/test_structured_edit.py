import shutil
import subprocess
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from gauntlet.attacks.indirect_prompt_injection import IndirectPromptInjectionAttack
from gauntlet.remediation.context import build_source_context
from gauntlet.remediation.models import (
    GeneratedEditCandidate, GeneratedRepairCandidate, RepairContext,
    RepairFailure, RepairProposal,
    StructuredRegressionTest, StructuredSourceEdit,
)
from gauntlet.remediation.validation import validate_candidate
from gauntlet.sandbox.m4_executor import M41RepairExecutor
from gauntlet.sandbox.m4_models import PatchAssessment
from gauntlet.sandbox.workspace import repository_digest
from victims.customer_support.app import create_app


ROOT = Path(__file__).parents[1]
TARGET = "victims/customer_support/agent.py"
SYMBOL = "CustomerSupportAgent.chat"


@pytest.fixture
async def trusted_context():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://test"
    ) as client:
        trace = (await IndirectPromptInjectionAttack(client).run()).trace
    source = build_source_context(trace.model_dump_json(), ROOT)
    return source, RepairContext(
        trace_id=source.trace_id,
        boundary_id=source.boundary_id,
        evidence_ids=source.evidence_ids,
        provider="offline_structured_edit",
        model="nvidia/Nemotron-3_5-Lightning",
        target_path=source.repository_relative_path,
        target_symbol=source.target_symbol,
        source_hash=source.source_hash,
        failure_type="indirect_prompt_injection",
    )


def candidate(source, *, start, delete, replacement, test_lines=None):
    return GeneratedRepairCandidate(
        rationale="Apply the exact model-proposed source edit.",
        source_edit=StructuredSourceEdit(
            target_path=source.repository_relative_path,
            target_symbol=source.target_symbol,
            source_hash=source.source_hash,
            start_line=start,
            delete_line_count=delete,
            replacement_lines=replacement,
        ),
        regression_test=StructuredRegressionTest(lines=(test_lines or [
            "def test_structured_candidate():", "    assert True",
        ])),
        optional_policy_artifact=None,
    )


def test_call_one_schema_omits_trusted_original_lines():
    schema = GeneratedEditCandidate.model_json_schema()
    edit_schema = schema["$defs"]["StructuredSourceEdit"]

    assert "expected_original_lines" not in edit_schema["properties"]
    assert set(edit_schema["properties"]) == {
        "target_path", "target_symbol", "source_hash", "start_line",
        "delete_line_count", "replacement_lines",
    }


@pytest.mark.parametrize("operation", ["replacement", "insertion", "deletion"])
async def test_valid_structured_edit_operations_derive_unified_diff(
    trusted_context, operation
):
    source, context = trusted_context
    lines = source.source_text.splitlines()
    if operation == "replacement":
        start, delete = 2, 1
        replacement = [lines[1] + "  # model replacement"]
    elif operation == "insertion":
        start, delete = 2, 0
        replacement = ["        model_inserted_value = True"]
    else:
        comment_index = lines.index(
            "                # Instrument the actual integration seam without storing system context."
        )
        start, delete = comment_index + 1, 1
        replacement = []

    proposal = validate_candidate(
        candidate(source, start=start, delete=delete, replacement=replacement),
        context, ROOT,
    )

    assert isinstance(proposal, RepairProposal)
    assert proposal.patch.startswith(f"--- a/{TARGET}\n+++ b/{TARGET}\n@@")
    for line in replacement:
        assert f"+{line}" in proposal.patch


@pytest.mark.parametrize("control", ["line one\nline two", "line one\rline two"])
def test_structured_line_elements_reject_lf_and_cr(control):
    with pytest.raises(ValidationError, match="cannot contain LF or CR"):
        StructuredRegressionTest(lines=[control])
    with pytest.raises(ValidationError, match="cannot contain LF or CR"):
        StructuredSourceEdit(
            target_path=TARGET, target_symbol=SYMBOL, source_hash="0" * 64,
            start_line=1, delete_line_count=1, replacement_lines=[control],
        )


@pytest.mark.parametrize(
    ("change", "stage", "code"),
    [
        ({"target_path": "src/gauntlet/core/config.py"},
         "patch_authorization", "unauthorized_edit_target"),
        ({"target_symbol": "Other.chat"},
         "patch_authorization", "unauthorized_edit_target"),
        ({"source_hash": "0" * 64},
         "source_identity", "candidate_source_hash_mismatch"),
        ({"start_line": 100_000},
         "patch_authorization", "edit_range_outside_symbol"),
    ],
)
async def test_structured_edit_authorization_and_source_anchor_failures(
    trusted_context, change, stage, code
):
    source, context = trusted_context
    lines = source.source_text.splitlines()
    edit = StructuredSourceEdit(
        target_path=source.repository_relative_path,
        target_symbol=source.target_symbol,
        source_hash=source.source_hash,
        start_line=2,
        delete_line_count=1,
        replacement_lines=[lines[1] + "  # replacement"],
    ).model_copy(update=change)
    result = validate_candidate(
        GeneratedRepairCandidate(
            rationale="Untrusted candidate.", source_edit=edit,
            regression_test=StructuredRegressionTest(
                lines=["def test_candidate():", "    assert True"]
            ),
        ),
        context, ROOT,
    )

    assert isinstance(result, RepairFailure)
    assert (result.failure_stage, result.failure_code) == (stage, code)


async def test_trusted_source_is_not_read_before_claim_and_hash_gates(
    trusted_context, monkeypatch
):
    source, context = trusted_context
    candidate_value = candidate(
        source, start=2, delete=1, replacement=["        replacement = True"]
    )

    def unexpected_read(_path):
        raise AssertionError("trusted source read occurred before identity gates")

    monkeypatch.setattr(Path, "read_bytes", unexpected_read)
    for edit in (
        candidate_value.source_edit.model_copy(
            update={"target_symbol": "Other.chat"}
        ),
        candidate_value.source_edit.model_copy(update={"source_hash": "0" * 64}),
    ):
        result = validate_candidate(
            candidate_value.model_copy(update={"source_edit": edit}), context, ROOT
        )
        assert isinstance(result, RepairFailure)


async def test_reconstruction_and_diff_contain_exact_model_replacement_only(
    trusted_context, tmp_path
):
    source, context = trusted_context
    before_digest = repository_digest(ROOT)
    bounded_lines = source.source_text.splitlines()
    replacement = [
        "        model_owned_first = 'exact text'",
        "        model_owned_second = model_owned_first",
    ]
    proposal = validate_candidate(
        candidate(
            source, start=2, delete=1,
            replacement=replacement,
            test_lines=["def test_materialization():", "    assert True"],
        ),
        context, ROOT,
    )
    assert isinstance(proposal, RepairProposal)

    workspace = tmp_path / "workspace"
    target = workspace / TARGET
    target.parent.mkdir(parents=True)
    shutil.copy2(ROOT / TARGET, target)
    patch_path = workspace / "repair.patch"
    patch_path.write_text(proposal.patch)
    checked = subprocess.run(
        ["git", "apply", "--check", str(patch_path)], cwd=workspace,
        capture_output=True, text=True, check=False,
    )
    assert checked.returncode == 0, checked.stderr
    applied = subprocess.run(
        ["git", "apply", str(patch_path)], cwd=workspace,
        capture_output=True, text=True, check=False,
    )
    assert applied.returncode == 0, applied.stderr

    original_lines = (ROOT / TARGET).read_text().splitlines()
    symbol_lines = source.source_text.splitlines()
    symbol_start = next(
        index for index in range(len(original_lines))
        if original_lines[index:index + len(symbol_lines)] == symbol_lines
    )
    expected_lines = list(original_lines)
    absolute_start = symbol_start + 1
    expected_lines[absolute_start:absolute_start + 1] = replacement
    expected_source = "\n".join(expected_lines) + "\n"

    assert target.read_text() == expected_source
    assert proposal.regression_test == "def test_materialization():\n    assert True\n"
    assert repository_digest(ROOT) == before_digest


async def test_invalid_model_replacement_reaches_compile_failure_unchanged(
    trusted_context
):
    source, context = trusted_context
    before_digest = repository_digest(ROOT)
    lines = source.source_text.splitlines()
    invalid = lines[0].removesuffix(":")
    proposal = validate_candidate(
        candidate(
            source, start=1, delete=1,
            replacement=[invalid],
        ),
        context, ROOT,
    )
    assert isinstance(proposal, RepairProposal)
    assert f"+{invalid}" in proposal.patch
    assert f"+{invalid}:" not in proposal.patch

    result = await M41RepairExecutor(ROOT).run(proposal)

    assert isinstance(result, PatchAssessment)
    assert result.build_integrity.status == "FAIL"
    assert result.p100_security.status == "NOT_RUN"
    assert repository_digest(ROOT) == before_digest


async def test_valid_but_incorrect_model_range_is_not_silently_corrected(
    trusted_context
):
    source, context = trusted_context
    lines = source.source_text.splitlines()
    chosen_line = 2
    replacement = [lines[chosen_line - 1] + "  # wrong semantic location"]

    proposal = validate_candidate(
        candidate(
            source, start=chosen_line, delete=1, replacement=replacement,
        ),
        context, ROOT,
    )

    assert isinstance(proposal, RepairProposal)
    assert f"-{lines[chosen_line - 1]}" in proposal.patch
    assert f"+{replacement[0]}" in proposal.patch


def test_deterministic_validator_contains_no_benchmark_repair_recipe():
    validator_source = (ROOT / "src/gauntlet/remediation/validation.py").read_text()
    for repair_fragment in (
        "privileged_context=False", "External review content",
        "enforce_data_only_boundary=True", "_test_only_known_good_change",
    ):
        assert repair_fragment not in validator_source
