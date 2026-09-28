from pathlib import Path

import httpx
import pytest

from gauntlet.attacks.indirect_prompt_injection import IndirectPromptInjectionAttack
from gauntlet.patching.planner import plan_patch
from gauntlet.sandbox.applicator import apply_patch
from gauntlet.sandbox.models import (
    CommandCategory, CommandResult, FailureCategory, RepairProposal,
)
from gauntlet.sandbox.orchestrator import MAX_REPAIR_ATTEMPTS, SandboxRepairOrchestrator
from gauntlet.sandbox.renderer import render_sandbox_result
from gauntlet.sandbox.runner import SandboxCommandRunner
from gauntlet.sandbox.workspace import REQUIRED_PATHS, SandboxWorkspace, repository_digest
from victims.customer_support.app import create_app


REPOSITORY_ROOT = Path(__file__).parents[1]


async def valid_plan():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://before"
    ) as client:
        trace = (await IndirectPromptInjectionAttack(client).run()).trace
    return plan_patch(trace.model_dump_json())


def test_sandbox_creation_copies_only_required_project_inputs_and_cleans_up():
    workspace = SandboxWorkspace(REPOSITORY_ROOT)
    with workspace:
        path = workspace.path
        assert path.is_dir()
        assert {item.name for item in path.iterdir()} == set(REQUIRED_PATHS)
        for required in REQUIRED_PATHS:
            assert (path / required).exists()
        assert not (path / ".git").exists()
        assert not (path / ".venv").exists()
    assert not path.exists()


async def test_patch_changes_only_sandbox_and_original_remains_unchanged():
    plan = await valid_plan()
    original = (REPOSITORY_ROOT / plan.target_file).read_bytes()
    original_digest = repository_digest(REPOSITORY_ROOT)
    workspace = SandboxWorkspace(REPOSITORY_ROOT)
    with workspace:
        result = apply_patch(workspace, plan)
        assert result.applied
        assert result.files_changed == [plan.target_file]
        assert workspace.resolve_relative(plan.target_file).read_bytes() != original
    assert (REPOSITORY_ROOT / plan.target_file).read_bytes() == original
    assert repository_digest(REPOSITORY_ROOT) == original_digest


@pytest.mark.parametrize("path", ["../outside.py", "/tmp/outside.py", "src/../../outside.py"])
def test_path_traversal_and_outside_paths_are_rejected(path):
    with SandboxWorkspace(REPOSITORY_ROOT) as workspace:
        with pytest.raises(ValueError):
            workspace.resolve_relative(path)


async def test_applicator_rejects_plan_outside_allowed_scope():
    plan = (await valid_plan()).model_copy(update={"target_file": "../outside.py"})
    with SandboxWorkspace(REPOSITORY_ROOT) as workspace:
        result = apply_patch(workspace, plan)
        assert not result.applied
        assert result.files_changed == []
        assert "scope" in result.error


async def test_build_runs_in_sandbox_working_directory():
    with SandboxWorkspace(REPOSITORY_ROOT) as workspace:
        result = await SandboxCommandRunner().run(workspace, CommandCategory.BUILD)
        assert result.passed
        assert result.working_directory == str(workspace.path)
        assert result.workspace_id == workspace.workspace_id
        assert result.argv[-2:] == ["src", "victims"]


async def test_build_failure_is_structured_execution_evidence():
    with SandboxWorkspace(REPOSITORY_ROOT) as workspace:
        workspace.resolve_relative("src/broken.py").write_text("def broken(:\n")
        result = await SandboxCommandRunner().run(workspace, CommandCategory.BUILD)
        assert not result.passed
        assert result.exit_code != 0
        assert "SyntaxError" in result.stdout + result.stderr


async def test_test_failure_is_structured_execution_evidence():
    with SandboxWorkspace(REPOSITORY_ROOT) as workspace:
        workspace.resolve_relative("sandbox_checks/test_repair.py").write_text(
            "def test_failure():\n    assert False\n"
        )
        result = await SandboxCommandRunner().run(workspace, CommandCategory.TEST)
        assert not result.passed
        assert result.exit_code != 0
        assert "failed" in result.stdout.lower()


class AlwaysFailRunner:
    def __init__(self):
        self.calls = 0

    async def run(self, workspace, category):
        self.calls += 1
        return CommandResult(
            category=category, argv=["fixed-test-double"], exit_code=1,
            stdout="observable failure", stderr="", duration_seconds=0,
            workspace_id=workspace.workspace_id,
            working_directory=str(workspace.path),
        )


class RecordingRepairClient:
    def __init__(self):
        self.calls = 0

    async def propose(self, plan, source, failure):
        self.calls += 1
        return RepairProposal(
            patch_id=plan.patch_id, target_file=plan.target_file,
            target_symbol=plan.target_symbol, control=plan.proposed_control,
            source_failure_category=failure.category,
        )


class TestStageFailRunner:
    async def run(self, workspace, category):
        failed = category == CommandCategory.TEST
        return CommandResult(
            category=category, argv=["fixed-test-double"],
            exit_code=1 if failed else 0,
            stdout="test failed" if failed else "build passed", stderr="",
            duration_seconds=0, workspace_id=workspace.workspace_id,
            working_directory=str(workspace.path),
        )


async def test_retry_loop_is_bounded_and_failures_are_structured():
    runner = AlwaysFailRunner()
    repair = RecordingRepairClient()
    result = await SandboxRepairOrchestrator(
        REPOSITORY_ROOT, runner=runner, repair_client=repair,
        max_attempts=MAX_REPAIR_ATTEMPTS,
    ).run(await valid_plan())
    assert not result.succeeded
    assert result.attempts == MAX_REPAIR_ATTEMPTS
    assert runner.calls == MAX_REPAIR_ATTEMPTS
    assert repair.calls == MAX_REPAIR_ATTEMPTS
    assert [failure.category for failure in result.failures] == [
        FailureCategory.BUILD_FAILED
    ] * MAX_REPAIR_ATTEMPTS
    assert result.workspace_cleaned


async def test_test_stage_failure_is_captured_as_repair_failure():
    result = await SandboxRepairOrchestrator(
        REPOSITORY_ROOT, runner=TestStageFailRunner(), max_attempts=1
    ).run(await valid_plan())
    assert not result.succeeded
    assert result.build_result.passed
    assert not result.test_result.passed
    assert result.failures[0].category == FailureCategory.TEST_FAILED
    assert result.failures[0].command_result.stdout == "test failed"


async def test_successful_sandbox_repair_isolated_tested_and_cleaned():
    result = await SandboxRepairOrchestrator(REPOSITORY_ROOT).run(await valid_plan())
    assert result.succeeded
    assert result.attempts == 1
    assert result.patch_result.applied
    assert result.build_result.passed
    assert result.test_result.passed
    assert result.original_workspace_unchanged
    assert result.outside_writes == "NONE"
    assert result.workspace_cleaned
    assert not Path(result.workspace_path).exists()
    output = render_sandbox_result(result)
    assert "SANDBOX REPAIR VERIFIED" in output
    assert "Original workspace modified: NO" in output
    assert "Outside writes: NONE" in output
