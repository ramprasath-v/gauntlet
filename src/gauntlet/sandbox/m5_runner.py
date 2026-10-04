"""Fixed commands for the benchmark-owned M5.1 mutation checks."""
import sys

from gauntlet.sandbox.m4_runner import M41CommandRunner
from gauntlet.sandbox.models import CommandCategory, CommandResult
from gauntlet.sandbox.workspace import SandboxWorkspace


class M51CommandRunner(M41CommandRunner):
    async def pre_patch_mutation(
        self, workspace: SandboxWorkspace, mutation_id: str,
    ) -> CommandResult:
        return await self._run(
            workspace, CommandCategory.SECURITY,
            [sys.executable, "-m", "pytest", "-q",
             "sandbox_checks/test_attack_mutations.py::"
             f"test_pre_patch_attack_reproduced[{mutation_id}]"],
        )

    async def post_patch_mutation(
        self, workspace: SandboxWorkspace, mutation_id: str,
    ) -> CommandResult:
        return await self._run(
            workspace, CommandCategory.SECURITY,
            [sys.executable, "-m", "pytest", "-q",
             "sandbox_checks/test_attack_mutations.py::"
             f"test_post_patch_attack_blocked[{mutation_id}]"],
        )
