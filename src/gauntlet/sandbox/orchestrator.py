from pathlib import Path
from typing import Protocol

from gauntlet.patching.models import PatchPlan
from gauntlet.sandbox.applicator import apply_patch
from gauntlet.sandbox.models import (
    CommandCategory, CommandResult, FailureCategory, RepairFailure,
    SandboxRepairResult, SourceContext,
)
from gauntlet.sandbox.repair import DeterministicRepairProposalClient, RepairProposalClient
from gauntlet.sandbox.runner import SandboxCommandRunner
from gauntlet.sandbox.workspace import SandboxWorkspace, repository_digest

MAX_REPAIR_ATTEMPTS = 3


class CommandRunner(Protocol):
    async def run(
        self, workspace: SandboxWorkspace, category: CommandCategory
    ) -> CommandResult: ...


class SandboxRepairOrchestrator:
    def __init__(
        self, repository_root: Path, *, runner: CommandRunner | None = None,
        repair_client: RepairProposalClient | None = None,
        max_attempts: int = MAX_REPAIR_ATTEMPTS,
    ):
        if not 1 <= max_attempts <= MAX_REPAIR_ATTEMPTS:
            raise ValueError(f"max_attempts must be between 1 and {MAX_REPAIR_ATTEMPTS}")
        self.repository_root = repository_root.resolve(strict=True)
        self.runner = runner or SandboxCommandRunner()
        self.repair_client = repair_client or DeterministicRepairProposalClient()
        self.max_attempts = max_attempts

    async def run(self, plan: PatchPlan) -> SandboxRepairResult:
        original_digest = repository_digest(self.repository_root)
        failures: list[RepairFailure] = []
        last_patch = last_build = last_test = None
        last_workspace_id = last_workspace_path = ""
        source_revision = None

        for attempt in range(1, self.max_attempts + 1):
            workspace = SandboxWorkspace(self.repository_root)
            with workspace:
                last_workspace_id = workspace.workspace_id
                last_workspace_path = str(workspace.path)
                source_revision = workspace.source_revision
                last_patch = apply_patch(workspace, plan)
                failure = None
                if not last_patch.applied:
                    failure = RepairFailure(
                        category=FailureCategory.PATCH_APPLY_FAILED, attempt=attempt,
                        workspace_id=workspace.workspace_id,
                        summary=last_patch.error or "Patch application failed",
                        patch_result=last_patch,
                    )
                else:
                    last_build = await self.runner.run(workspace, CommandCategory.BUILD)
                    if not last_build.passed:
                        failure = RepairFailure(
                            category=FailureCategory.BUILD_FAILED, attempt=attempt,
                            workspace_id=workspace.workspace_id,
                            summary="Configured sandbox build command failed",
                            command_result=last_build,
                        )
                    else:
                        last_test = await self.runner.run(workspace, CommandCategory.TEST)
                        if not last_test.passed:
                            failure = RepairFailure(
                                category=FailureCategory.TEST_FAILED, attempt=attempt,
                                workspace_id=workspace.workspace_id,
                                summary="Configured sandbox regression command failed",
                                command_result=last_test,
                            )
                if failure is None:
                    break
                failures.append(failure)
                source_path = workspace.resolve_relative(plan.target_file)
                source = SourceContext(
                    file=plan.target_file, symbol=plan.target_symbol,
                    content=source_path.read_text() if source_path.exists() else "",
                )
                proposal = await self.repair_client.propose(plan, source, failure)
                if (proposal.patch_id != plan.patch_id
                        or proposal.target_file != plan.target_file
                        or proposal.target_symbol != plan.target_symbol):
                    raise ValueError("Repair proposal exceeded the constrained PatchPlan scope")

        unchanged = repository_digest(self.repository_root) == original_digest
        cleaned = not Path(last_workspace_path).exists()
        succeeded = bool(
            last_patch and last_patch.applied and last_build and last_build.passed
            and last_test and last_test.passed and unchanged and cleaned
        )
        return SandboxRepairResult(
            succeeded=succeeded, attempts=(len(failures) + (1 if succeeded else 0)),
            max_attempts=self.max_attempts,
            workspace_id=last_workspace_id, workspace_path=last_workspace_path,
            source_revision=source_revision,
            workspace_cleaned=cleaned, original_workspace_unchanged=unchanged,
            outside_writes="NONE" if unchanged else "DETECTED",
            patch_result=last_patch, build_result=last_build, test_result=last_test,
            failures=failures,
        )
