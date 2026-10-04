import difflib
import hashlib
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from gauntlet.remediation.candidate_artifact import persist_candidate_artifact
from gauntlet.remediation.models import (
    GeneratedRepairCandidate, StructuredRegressionTest, StructuredSourceEdit,
)
from gauntlet.sandbox.m4_executor import _symbol_text
from gauntlet.sandbox.m4_models import PATCH_ASSESSMENT_SCHEMA_VERSION
from gauntlet.sandbox.m5_executor import M51MutationExecutor
from gauntlet.sandbox.m5_models import (
    ATTACK_MUTATION_ASSESSMENT_VERSION,
    AttackMutationAssessment,
    MutationPatchInput,
)
from gauntlet.sandbox.m5_runner import M51CommandRunner
from gauntlet.sandbox.models import CommandCategory, CommandResult
from gauntlet.sandbox.workspace import repository_digest


ROOT = Path(__file__).parents[1]
TARGET = "victims/customer_support/agent.py"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _test_patch_input() -> MutationPatchInput:
    source = (ROOT / TARGET).read_text()
    changed = source.replace(
        "enforce_data_only_boundary=self.enforce_tool_data_boundary))",
        "enforce_data_only_boundary=True))",
    )
    assert changed != source
    patch = "".join(difflib.unified_diff(
        source.splitlines(keepends=True), changed.splitlines(keepends=True),
        fromfile=f"a/{TARGET}", tofile=f"b/{TARGET}",
    ))
    return MutationPatchInput(
        candidate_schema_version="gauntlet.repair-candidate.v3",
        candidate_id=str(uuid4()),
        candidate_digest=_digest("offline-test-candidate"),
        target_path=TARGET,
        target_symbol="CustomerSupportAgent.chat",
        source_hash=_digest(_symbol_text(
            ROOT / TARGET, "CustomerSupportAgent.chat"
        )),
        patch=patch,
        patch_digest=_digest(patch),
    )


async def test_all_mutations_are_independent_and_verified_offline():
    before = repository_digest(ROOT)
    result = await M51MutationExecutor(ROOT).run(_test_patch_input())

    assert result.schema_version == ATTACK_MUTATION_ASSESSMENT_VERSION
    assert result.qualified_mutation_count == 4
    assert result.blocked_mutation_count == 4
    assert result.verified
    assert result.cleanup == "PASS"
    assert result.repository_immutability == "PASS"
    assert result.original_repository_unchanged
    assert result.patch_digest == _test_patch_input().patch_digest
    assert len({item.pre_patch_workspace_id for item in result.mutations}) == 4
    assert len({item.post_patch_workspace_id for item in result.mutations}) == 4
    assert not (
        {item.pre_patch_workspace_id for item in result.mutations}
        & {item.post_patch_workspace_id for item in result.mutations}
    )
    for item in result.mutations:
        assert item.pre_patch_attack_reproduced == "PASS"
        assert item.post_patch_attack_blocked == "PASS"
        assert item.pre_patch_source_identity == "PASS"
        assert item.post_patch_source_identity == "PASS"
        assert item.source_hash == result.source_hash
        assert item.patch_digest == result.patch_digest
        assert item.post_patch_application is not None
        assert item.post_patch_application.passed
        assert item.post_patch_compile.status == "PASS"
        assert item.post_patch_files_changed == [TARGET]
        assert item.pre_patch_workspace_cleaned
        assert item.post_patch_workspace_cleaned
    assert repository_digest(ROOT) == before


class OneUnqualifiedMutationRunner(M51CommandRunner):
    post_ids: list[str]

    def __init__(self):
        super().__init__()
        self.post_ids = []

    async def pre_patch_mutation(self, workspace, mutation_id):
        if mutation_id == "M5-P100-PREFIX":
            return CommandResult(
                category=CommandCategory.SECURITY,
                argv=["offline-test", mutation_id],
                exit_code=1,
                stdout="mutation did not reproduce",
                stderr="",
                duration_seconds=0,
                workspace_id=workspace.workspace_id,
                working_directory=str(workspace.path),
            )
        return await super().pre_patch_mutation(workspace, mutation_id)

    async def post_patch_mutation(self, workspace, mutation_id):
        self.post_ids.append(mutation_id)
        return await super().post_patch_mutation(workspace, mutation_id)


async def test_failed_prequalification_cannot_count_or_run_post_patch():
    runner = OneUnqualifiedMutationRunner()
    result = await M51MutationExecutor(ROOT, runner=runner).run(
        _test_patch_input()
    )

    failed = next(
        item for item in result.mutations
        if item.mutation_id == "M5-P100-PREFIX"
    )
    assert failed.pre_patch_attack_reproduced == "FAIL"
    assert failed.post_patch_attack_blocked == "NOT_RUN"
    assert failed.post_patch_workspace_id is None
    assert failed.post_patch_source_identity == "NOT_RUN"
    assert failed.post_patch_application is None
    assert "M5-P100-PREFIX" not in runner.post_ids
    assert result.qualified_mutation_count == 3
    assert result.blocked_mutation_count == 3
    assert not result.verified


def test_patch_digest_mismatch_is_rejected_before_execution():
    values = _test_patch_input().model_dump()
    values["patch_digest"] = "0" * 64
    with pytest.raises(ValidationError, match="declared digest"):
        MutationPatchInput.model_validate(values)


async def test_wrong_source_identity_is_rejected_and_repository_is_unchanged():
    before = repository_digest(ROOT)
    candidate = _test_patch_input().model_copy(update={"source_hash": "0" * 64})
    with pytest.raises(ValueError, match="Repository source identity"):
        await M51MutationExecutor(ROOT).run(candidate)
    assert repository_digest(ROOT) == before


async def test_persisted_candidate_requires_expected_identity(tmp_path):
    patch_input = _test_patch_input()
    candidate = GeneratedRepairCandidate(
        rationale="Offline identity-bound test candidate.",
        source_edit=StructuredSourceEdit(
            target_path=TARGET,
            target_symbol="CustomerSupportAgent.chat",
            source_hash=patch_input.source_hash,
            start_line=1,
            delete_line_count=1,
            replacement_lines=["    async def chat(self, message: str):"],
        ),
        regression_test=StructuredRegressionTest(lines=[
            "def test_offline_identity():", "    assert True",
        ]),
    )
    artifact_path = tmp_path / "candidate.json"
    persist_candidate_artifact(
        candidate,
        path=artifact_path,
        candidate_id=patch_input.candidate_id,
        run_id=str(uuid4()),
        attempt_number=1,
        provider="offline_test",
        model="offline_test",
        trace_id=str(uuid4()),
        boundary_id=str(uuid4()),
        evidence_ids=[str(uuid4())],
        target_path=TARGET,
        target_symbol="CustomerSupportAgent.chat",
        source_hash=patch_input.source_hash,
        derived_patch=patch_input.patch,
        derived_regression_test="def test_offline_identity():\n    assert True\n",
    )

    with pytest.raises(ValueError, match="candidate ID"):
        await M51MutationExecutor(ROOT).run_persisted_candidate(
            artifact_path,
            expected_candidate_id=str(uuid4()),
            expected_patch_digest=patch_input.patch_digest,
        )


async def test_assessment_cannot_claim_cleanup_without_cleaned_workspaces():
    result = await M51MutationExecutor(ROOT).run(_test_patch_input())
    payload = result.model_dump(mode="json")
    payload["mutations"][0]["pre_patch_workspace_cleaned"] = False
    with pytest.raises(ValidationError, match="Cleanup status"):
        AttackMutationAssessment.model_validate(payload)


def test_m5_is_additive_and_does_not_change_patch_assessment_version():
    assert PATCH_ASSESSMENT_SCHEMA_VERSION == "gauntlet.patch-assessment.v1"
    assert ATTACK_MUTATION_ASSESSMENT_VERSION == (
        "gauntlet.attack-mutation-assessment.v1"
    )
