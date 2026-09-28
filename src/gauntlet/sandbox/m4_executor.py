"""Execute one exact validated repair proposal and derive proof from commands."""
import ast
import hashlib
import json
from pathlib import Path
import re
from time import monotonic
from datetime import datetime, timezone
from uuid import uuid4

from gauntlet.remediation.handoff import load_repair_proposal
from gauntlet.remediation.models import FailureStage, RepairFailure, RepairProposal
from gauntlet.sandbox.m4_models import PatchProof
from gauntlet.sandbox.m4_runner import M41CommandRunner
from gauntlet.sandbox.models import CommandResult
from gauntlet.sandbox.workspace import (
    REQUIRED_PATHS, SandboxWorkspace, repository_digest,
)


DIAGNOSTIC_LIMIT = 2_000


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _redact(value: str) -> str:
    value = re.sub(
        r"(?i)((?:api[_-]?key|authorization|access[_-]?token|password|secret)"
        r"\s*[=:]\s*['\"]?)[^\s'\"]+",
        r"\1[REDACTED]", value,
    )
    value = re.sub(
        r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value
    )
    return value[:DIAGNOSTIC_LIMIT]


def _symbol_text(path: Path, symbol: str) -> str:
    """Read the same bounded class method span hashed by M3 SourceContext."""
    parts = symbol.split(".")
    if len(parts) != 2:
        raise ValueError("M4.1 supports an authorized Class.method target")
    class_name, method_name = parts
    source = path.read_text()
    tree = ast.parse(source)
    class_node = next(
        (node for node in tree.body
         if isinstance(node, ast.ClassDef) and node.name == class_name), None,
    )
    method = next(
        (node for node in class_node.body
         if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
         and node.name == method_name), None,
    ) if class_node else None
    if method is None or method.end_lineno is None:
        raise ValueError("Authorized target symbol is missing")
    lines = source.splitlines(keepends=True)
    return "".join(lines[method.lineno - 1:method.end_lineno])


def _workspace_files(workspace: SandboxWorkspace) -> dict[str, str]:
    if workspace.path is None:
        raise RuntimeError("Disposable workspace has not been created")
    files: dict[str, str] = {}
    for relative in REQUIRED_PATHS:
        path = workspace.path / relative
        candidates = [path] if path.is_file() else path.rglob("*")
        for child in candidates:
            if (not child.is_file() or "__pycache__" in child.parts
                    or child.suffix in {".pyc", ".pyo"}):
                continue
            name = child.relative_to(workspace.path).as_posix()
            files[name] = hashlib.sha256(child.read_bytes()).hexdigest()
    return files


def _changed_files(before: dict[str, str], after: dict[str, str]) -> list[str]:
    return sorted(
        path for path in before.keys() | after.keys()
        if before.get(path) != after.get(path)
    )


class M41RepairExecutor:
    """One-shot executor; it never regenerates, edits, or retries a proposal."""

    def __init__(
        self, repository_root: Path, *, runner: M41CommandRunner | None = None
    ):
        self.repository_root = repository_root.resolve(strict=True)
        self.runner = runner or M41CommandRunner()

    async def run_persisted(self, path: Path) -> PatchProof | RepairFailure:
        return await self.run(load_repair_proposal(path))

    def _failure(
        self,
        proposal: RepairProposal,
        *,
        stage: FailureStage,
        code: str,
        message: str,
        diagnostics: dict[str, str | int | bool | None],
    ) -> RepairFailure:
        fields = {
            "rationale": proposal.rationale,
            "patch": proposal.patch,
            "regression_test": proposal.regression_test,
            "optional_policy_artifact": proposal.optional_policy_artifact,
        }
        serialized = json.dumps(fields, ensure_ascii=True, sort_keys=True)
        return RepairFailure(
            repair_id=proposal.repair_id,
            candidate_digest=_sha256_text(serialized),
            candidate_field_digests={
                name: _sha256_text(json.dumps(value, ensure_ascii=True))
                for name, value in fields.items()
            },
            candidate_field_lengths={
                name: len(value) if isinstance(value, str) else 0
                for name, value in fields.items()
            },
            trace_id=proposal.trace_id,
            boundary_id=proposal.boundary_id,
            evidence_ids=proposal.evidence_ids,
            provider=proposal.provider,
            model=proposal.model,
            target_path=proposal.target_path,
            target_symbol=proposal.target_symbol,
            source_hash=proposal.source_hash,
            failure_type=proposal.failure_type,
            failure_stage=stage,
            failure_code=code,
            message=message,
            diagnostics=diagnostics,
            attempt=1,
        )

    def _command_failure(
        self,
        proposal: RepairProposal,
        result: CommandResult,
        *,
        stage: FailureStage,
        code: str,
        message: str,
    ) -> RepairFailure:
        return self._failure(
            proposal, stage=stage, code=code, message=message,
            diagnostics={
                "command": " ".join(result.argv),
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "stdout": _redact(result.stdout),
                "stderr": _redact(result.stderr),
                "workspace_id": result.workspace_id,
            },
        )

    async def run(self, proposal: RepairProposal) -> PatchProof | RepairFailure:
        """Execute exactly one proposal in one fresh disposable workspace."""
        original_digest = repository_digest(self.repository_root)
        started_at = datetime.now(timezone.utc)
        started = monotonic()
        failure: RepairFailure | None = None
        evidence: dict[str, object] = {}
        workspace = SandboxWorkspace(self.repository_root)

        with workspace:
            assert workspace.path is not None
            target = workspace.resolve_relative(proposal.target_path)
            try:
                observed_hash = _sha256_text(
                    _symbol_text(target, proposal.target_symbol)
                )
            except (OSError, SyntaxError, ValueError) as exc:
                failure = self._failure(
                    proposal, stage="source_identity", code="target_unreadable",
                    message="The authorized workspace target could not be identified.",
                    diagnostics={"error_type": type(exc).__name__},
                )
            else:
                if observed_hash != proposal.source_hash:
                    failure = self._failure(
                        proposal, stage="source_identity", code="source_hash_mismatch",
                        message="The workspace target does not match the proposal source.",
                        diagnostics={
                            "expected_source_hash": proposal.source_hash,
                            "observed_source_hash": observed_hash,
                        },
                    )

            if failure is None:
                before_files = _workspace_files(workspace)
                artifact_root = workspace.resolve_relative(".gauntlet/artifacts")
                artifact_root.mkdir(parents=True, exist_ok=True)
                patch_path = artifact_root / "repair.patch"
                patch_path.write_bytes(proposal.patch.encode())
                patch_result = await self.runner.apply_patch(workspace, patch_path)
                evidence["patch_application"] = patch_result
                if not patch_result.passed:
                    failure = self._command_failure(
                        proposal, patch_result, stage="patch_apply",
                        code="git_apply_failed",
                        message="The exact proposal patch did not apply.",
                    )

            if failure is None:
                files_changed = _changed_files(before_files, _workspace_files(workspace))
                evidence["files_changed"] = files_changed
                if files_changed != [proposal.target_path]:
                    failure = self._failure(
                        proposal, stage="patch_authorization",
                        code="unauthorized_post_patch_change",
                        message="Patch application changed files outside the authorized target.",
                        diagnostics={
                            "expected_target": proposal.target_path,
                            "changed_files": json.dumps(files_changed),
                            "workspace_id": workspace.workspace_id,
                        },
                    )

            if failure is None:
                compile_result = await self.runner.compile(workspace)
                evidence["compile_evidence"] = compile_result
                if not compile_result.passed:
                    failure = self._command_failure(
                        proposal, compile_result, stage="compile",
                        code="compile_failed",
                        message="Patched Python source did not compile.",
                    )

            if failure is None:
                try:
                    patched_source_hash = _sha256_text(
                        _symbol_text(target, proposal.target_symbol)
                    )
                except (OSError, SyntaxError, ValueError) as exc:
                    failure = self._failure(
                        proposal, stage="compile", code="patched_target_unreadable",
                        message="The patched target symbol could not be identified.",
                        diagnostics={"error_type": type(exc).__name__},
                    )
                else:
                    evidence["patched_source_hash"] = patched_source_hash
                    if patched_source_hash == proposal.source_hash:
                        failure = self._failure(
                            proposal, stage="patch_authorization",
                            code="target_unchanged",
                            message="Patch application did not change the authorized symbol.",
                            diagnostics={"source_hash": proposal.source_hash},
                        )

            if failure is None:
                generated_path = workspace.resolve_relative(
                    ".gauntlet/generated_tests/test_generated_repair.py"
                )
                generated_path.parent.mkdir(parents=True, exist_ok=True)
                generated_path.write_bytes(proposal.regression_test.encode())
                regression_digest = hashlib.sha256(generated_path.read_bytes()).hexdigest()
                evidence["regression_test_digest"] = regression_digest
                if regression_digest != _sha256_text(proposal.regression_test):
                    failure = self._failure(
                        proposal, stage="regression_execution",
                        code="regression_artifact_mismatch",
                        message="Materialized regression test differs from the proposal.",
                        diagnostics={"observed_digest": regression_digest},
                    )

            if failure is None:
                regression_result = await self.runner.generated_regression(
                    workspace, generated_path
                )
                evidence["generated_regression_evidence"] = regression_result
                if not regression_result.passed:
                    failure = self._command_failure(
                        proposal, regression_result, stage="regression_execution",
                        code="generated_regression_failed",
                        message="The exact generated regression test failed.",
                    )

            if failure is None:
                security_result = await self.runner.p100_security(workspace)
                evidence["p100_security_evidence"] = security_result
                if not security_result.passed:
                    failure = self._command_failure(
                        proposal, security_result, stage="security_test",
                        code="p100_security_failed",
                        message="The frozen P100 security verification failed.",
                    )

            if failure is None:
                utility_result = await self.runner.p200_utility(workspace)
                evidence["p200_utility_evidence"] = utility_result
                if not utility_result.passed:
                    failure = self._command_failure(
                        proposal, utility_result, stage="utility_test",
                        code="p200_utility_failed",
                        message="The frozen P200 utility verification failed.",
                    )

            if failure is None:
                broader_result = await self.runner.broader_suite(workspace)
                evidence["broader_suite_evidence"] = broader_result
                if not broader_result.passed:
                    failure = self._command_failure(
                        proposal, broader_result, stage="existing_suite",
                        code="existing_suite_failed",
                        message="The broader compatible existing test suite failed.",
                    )

        original_unchanged = repository_digest(self.repository_root) == original_digest
        if not original_unchanged:
            return self._failure(
                proposal, stage="patch_authorization",
                code="original_repository_modified",
                message="M4.1 detected a change in the original repository inputs.",
                diagnostics={"workspace_id": workspace.workspace_id},
            )
        if failure is not None:
            return failure

        completed_at = datetime.now(timezone.utc)
        return PatchProof(
            proof_id=str(uuid4()),
            repair_id=proposal.repair_id,
            trace_id=proposal.trace_id,
            boundary_id=proposal.boundary_id,
            evidence_ids=proposal.evidence_ids,
            target_path=proposal.target_path,
            target_symbol=proposal.target_symbol,
            original_source_hash=proposal.source_hash,
            patched_source_hash=evidence["patched_source_hash"],
            patch_digest=_sha256_text(proposal.patch),
            regression_test_digest=evidence["regression_test_digest"],
            workspace_id=workspace.workspace_id,
            source_revision=workspace.source_revision,
            files_changed=evidence["files_changed"],
            patch_application=evidence["patch_application"],
            compile_evidence=evidence["compile_evidence"],
            generated_regression_evidence=evidence["generated_regression_evidence"],
            p100_security_evidence=evidence["p100_security_evidence"],
            p200_utility_evidence=evidence["p200_utility_evidence"],
            broader_suite_evidence=evidence["broader_suite_evidence"],
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=monotonic() - started,
            workspace_cleaned=workspace.path is not None and not workspace.path.exists(),
            original_repository_unchanged=original_unchanged,
        )
