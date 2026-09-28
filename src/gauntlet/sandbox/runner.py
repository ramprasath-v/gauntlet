"""Fixed-command runner; it is intentionally not a general shell interface."""
import asyncio
import os
from pathlib import Path
import sys
from time import monotonic

from gauntlet.sandbox.models import CommandCategory, CommandResult
from gauntlet.sandbox.workspace import SandboxWorkspace


class SandboxCommandRunner:
    def __init__(self, *, timeout_seconds: float = 30.0):
        self.timeout_seconds = timeout_seconds

    def _argv(self, category: CommandCategory) -> list[str]:
        commands = {
            CommandCategory.BUILD: [sys.executable, "-m", "compileall", "-q", "src", "victims"],
            CommandCategory.TEST: [sys.executable, "-m", "pytest", "-q", "sandbox_checks/test_repair.py"],
        }
        return commands[category]

    async def run(self, workspace: SandboxWorkspace, category: CommandCategory) -> CommandResult:
        if workspace.path is None:
            raise RuntimeError("Sandbox workspace has not been created")
        argv = self._argv(category)
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
            category=category, argv=argv,
            exit_code=process.returncode if not timed_out else 124,
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
            duration_seconds=monotonic() - started,
            workspace_id=workspace.workspace_id, timed_out=timed_out,
            working_directory=str(workspace.path),
        )
