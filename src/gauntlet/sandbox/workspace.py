"""Repository-local input copied to a disposable working directory."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
from uuid import uuid4


REQUIRED_PATHS = ("pyproject.toml", "src", "victims", "sandbox_checks")


def repository_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for relative in REQUIRED_PATHS:
        path = root / relative
        if path.is_file():
            digest.update(relative.encode())
            digest.update(path.read_bytes())
        elif path.is_dir():
            for child in sorted(item for item in path.rglob("*") if item.is_file()):
                if "__pycache__" in child.parts or child.suffix in {".pyc", ".pyo"}:
                    continue
                digest.update(child.relative_to(root).as_posix().encode())
                digest.update(child.read_bytes())
    return digest.hexdigest()


class SandboxWorkspace:
    def __init__(self, repository_root: Path, *, retain: bool = False):
        self.repository_root = repository_root.resolve(strict=True)
        self.retain = retain
        self.workspace_id = str(uuid4())
        self.path: Path | None = None
        self.source_revision = self._source_revision()

    def _source_revision(self) -> str | None:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repository_root,
            capture_output=True, text=True, check=False,
        )
        return result.stdout.strip() if result.returncode == 0 else None

    def create(self) -> "SandboxWorkspace":
        if self.path is not None:
            raise RuntimeError("Sandbox workspace already created")
        self.path = Path(tempfile.mkdtemp(prefix="gauntlet-sandbox-"))
        for relative in REQUIRED_PATHS:
            source = self.repository_root / relative
            if not source.exists():
                self.cleanup()
                raise FileNotFoundError(f"Required sandbox input is missing: {relative}")
            destination = self.path / relative
            if source.is_dir():
                shutil.copytree(
                    source, destination,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
                )
            else:
                shutil.copy2(source, destination)
        return self

    def resolve_relative(self, relative: str) -> Path:
        if self.path is None:
            raise RuntimeError("Sandbox workspace has not been created")
        candidate_relative = Path(relative)
        if candidate_relative.is_absolute() or ".." in candidate_relative.parts:
            raise ValueError("Sandbox paths must be repository-relative without traversal")
        candidate = (self.path / candidate_relative).resolve()
        if not candidate.is_relative_to(self.path.resolve()):
            raise ValueError("Resolved path escapes sandbox workspace")
        return candidate

    def cleanup(self) -> None:
        if self.path is not None and self.path.exists() and not self.retain:
            shutil.rmtree(self.path)

    def __enter__(self) -> "SandboxWorkspace":
        return self.create()

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.cleanup()
