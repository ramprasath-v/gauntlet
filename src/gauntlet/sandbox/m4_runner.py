"""Fixed M4.1 commands executed in disposable workspace/process isolation."""
import asyncio
import os
from pathlib import Path
import sys
from time import monotonic

from gauntlet.sandbox.models import CommandCategory, CommandResult
from gauntlet.sandbox.workspace import SandboxWorkspace


MAX_COMMAND_OUTPUT = 8_000


def _bounded(value: bytes) -> str:
    decoded = value.decode(errors="replace")
    if len(decoded) <= MAX_COMMAND_OUTPUT:
        return decoded
    return decoded[:MAX_COMMAND_OUTPUT] + "\n...[truncated]"


class M41CommandRunner:
    def __init__(self, *, timeout_seconds: float = 30.0):
        self.timeout_seconds = timeout_seconds

    async def _run(
        self, workspace: SandboxWorkspace, category: CommandCategory, argv: list[str]
    ) -> CommandResult:
        if workspace.path is None:
            raise RuntimeError("Disposable workspace has not been created")
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": os.pathsep.join([
                str(workspace.path / "src"), str(workspace.path)
            ]),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        started = monotonic()
        process = await asyncio.create_subprocess_exec(
            *argv, cwd=workspace.path, env=environment,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        timed_out = False
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.timeout_seconds
            )
        except TimeoutError:
            timed_out = True
            process.kill()
            stdout, stderr = await process.communicate()
        return CommandResult(
            category=category,
            argv=argv,
            exit_code=process.returncode if not timed_out else 124,
            stdout=_bounded(stdout),
            stderr=_bounded(stderr),
            duration_seconds=monotonic() - started,
            workspace_id=workspace.workspace_id,
            working_directory=str(workspace.path),
            timed_out=timed_out,
        )

    async def apply_patch(
        self, workspace: SandboxWorkspace, patch_path: Path
    ) -> CommandResult:
        relative = patch_path.relative_to(workspace.path.resolve()).as_posix()
        return await self._run(
            workspace, CommandCategory.PATCH_APPLY,
            ["git", "apply", "--verbose", relative],
        )

    async def compile(self, workspace: SandboxWorkspace) -> CommandResult:
        return await self._run(
            workspace, CommandCategory.BUILD,
            [sys.executable, "-m", "compileall", "-q", "src", "victims"],
        )

    async def generated_regression(
        self, workspace: SandboxWorkspace, test_path: Path
    ) -> CommandResult:
        relative = test_path.relative_to(workspace.path.resolve()).as_posix()
        return await self._run(
            workspace, CommandCategory.GENERATED_REGRESSION,
            [sys.executable, "-m", "pytest", "-q", relative],
        )

    async def p100_security(self, workspace: SandboxWorkspace) -> CommandResult:
        return await self._run(
            workspace, CommandCategory.SECURITY,
            [sys.executable, "-m", "pytest", "-q",
             "sandbox_checks/test_repair.py::test_same_attack_is_blocked_by_sandbox_patch"],
        )

    async def p200_utility(self, workspace: SandboxWorkspace) -> CommandResult:
        return await self._run(
            workspace, CommandCategory.UTILITY,
            [sys.executable, "-m", "pytest", "-q",
             "sandbox_checks/test_repair.py::test_clean_review_remains_useful_after_sandbox_patch"],
        )

    async def broader_suite(self, workspace: SandboxWorkspace) -> CommandResult:
        # Frozen M1/M2 tests assert the intentionally vulnerable baseline, so the
        # patched workspace runs the broader compatible utility/verifier/CLI set.
        return await self._run(
            workspace, CommandCategory.EXISTING_SUITE,
            [sys.executable, "-m", "pytest", "-q",
             "tests/test_canary_verifier.py", "tests/test_customer_support_utility.py",
             "tests/test_cli.py"],
        )
