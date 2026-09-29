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
from gauntlet.sandbox.m4_models import GateAssessment, PatchAssessment
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

    async def run_persisted(self, path: Path) -> PatchAssessment | RepairFailure:
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

    async def _prepare_workspace(
        self, proposal: RepairProposal, workspace: SandboxWorkspace,
    ) -> dict[str, object]:
        """Apply and compile the exact patch without interpreting its contents."""
        assert workspace.path is not None
        prepared: dict[str, object] = {}
        target = workspace.resolve_relative(proposal.target_path)
        try:
            observed_hash = _sha256_text(
                _symbol_text(target, proposal.target_symbol)
            )
        except (OSError, SyntaxError, ValueError) as exc:
            prepared["failure"] = self._failure(
                proposal, stage="source_identity", code="target_unreadable",
                message="The authorized workspace target could not be identified.",
                diagnostics={"error_type": type(exc).__name__},
            )
            return prepared
        if observed_hash != proposal.source_hash:
            prepared["failure"] = self._failure(
                proposal, stage="source_identity", code="source_hash_mismatch",
                message="The workspace target does not match the proposal source.",
                diagnostics={
                    "expected_source_hash": proposal.source_hash,
                    "observed_source_hash": observed_hash,
                },
            )
            return prepared

        before_files = _workspace_files(workspace)
        artifact_root = workspace.resolve_relative(".gauntlet/artifacts")
        artifact_root.mkdir(parents=True, exist_ok=True)
        patch_path = artifact_root / "repair.patch"
        patch_path.write_bytes(proposal.patch.encode())
        patch_result = await self.runner.apply_patch(workspace, patch_path)
        prepared["patch_application"] = patch_result
        if not patch_result.passed:
            prepared["failure"] = self._command_failure(
                proposal, patch_result, stage="patch_apply",
                code="git_apply_failed",
                message="The exact proposal patch did not apply.",
            )
            return prepared

        files_changed = _changed_files(before_files, _workspace_files(workspace))
        prepared["files_changed"] = files_changed
        if files_changed != [proposal.target_path]:
            prepared["failure"] = self._failure(
                proposal, stage="patch_authorization",
                code="unauthorized_post_patch_change",
                message="Patch application changed files outside the authorized target.",
                diagnostics={
                    "expected_target": proposal.target_path,
                    "changed_files": json.dumps(files_changed),
                    "workspace_id": workspace.workspace_id,
                },
            )
            return prepared

        compile_result = await self.runner.compile(workspace)
        prepared["compile_evidence"] = compile_result
        if not compile_result.passed:
            return prepared
        try:
            patched_source_hash = _sha256_text(
                _symbol_text(target, proposal.target_symbol)
            )
        except (OSError, SyntaxError, ValueError) as exc:
            prepared["failure"] = self._failure(
                proposal, stage="compile", code="patched_target_unreadable",
                message="The patched target symbol could not be identified.",
                diagnostics={"error_type": type(exc).__name__},
            )
            return prepared
        if patched_source_hash == proposal.source_hash:
            prepared["failure"] = self._failure(
                proposal, stage="patch_authorization", code="target_unchanged",
                message="Patch application did not change the authorized symbol.",
                diagnostics={"source_hash": proposal.source_hash},
            )
            return prepared
        prepared["patched_source_hash"] = patched_source_hash
        return prepared

    @staticmethod
    def _gate(result: CommandResult | None) -> GateAssessment:
        if result is None:
            return GateAssessment(status="NOT_RUN")
        return GateAssessment(status="PASS" if result.passed else "FAIL", evidence=result)

    async def run(
        self, proposal: RepairProposal, *, candidate_id: str | None = None,
        candidate_digest: str | None = None,
        candidate_field_digests: dict[str, str] | None = None,
        expected_patch_digest: str | None = None,
        expected_regression_test_digest: str | None = None,
    ) -> PatchAssessment | RepairFailure:
        """Evaluate trusted gates and model tests in isolated workspaces."""
        original_digest = repository_digest(self.repository_root)
        started_at = datetime.now(timezone.utc)
        started = monotonic()
        patch_digest = _sha256_text(proposal.patch)
        regression_digest = _sha256_text(proposal.regression_test)
        if expected_patch_digest is not None and expected_patch_digest != patch_digest:
            return self._failure(
                proposal, stage="candidate_validation", code="patch_digest_mismatch",
                message="Candidate patch digest differs from the execution artifact.",
                diagnostics={"expected_patch_digest": expected_patch_digest,
                             "observed_patch_digest": patch_digest},
            )
        if (expected_regression_test_digest is not None
                and expected_regression_test_digest != regression_digest):
            return self._failure(
                proposal, stage="candidate_validation",
                code="regression_test_digest_mismatch",
                message="Candidate regression digest differs from the execution artifact.",
                diagnostics={"expected_regression_test_digest": expected_regression_test_digest,
                             "observed_regression_test_digest": regression_digest},
            )

        fields = {
            "rationale": proposal.rationale, "patch": proposal.patch,
            "regression_test": proposal.regression_test,
            "optional_policy_artifact": proposal.optional_policy_artifact,
        }
        default_serialized = json.dumps(fields, ensure_ascii=True, sort_keys=True)
        candidate_id = candidate_id or proposal.repair_id
        candidate_digest = candidate_digest or _sha256_text(default_serialized)
        candidate_field_digests = candidate_field_digests or {
            name: _sha256_text(json.dumps(value, ensure_ascii=True))
            for name, value in fields.items()
        }

        trusted = SandboxWorkspace(self.repository_root)
        trusted_prepared: dict[str, object]
        p100_result = p200_result = compatibility_result = None
        with trusted:
            trusted_prepared = await self._prepare_workspace(proposal, trusted)
            early_failure = trusted_prepared.get("failure")
            if isinstance(early_failure, RepairFailure):
                return early_failure
            compile_result = trusted_prepared.get("compile_evidence")
            assert isinstance(compile_result, CommandResult)
            if compile_result.passed:
                p100_result = await self.runner.p100_security(
                    trusted, proposal.target_path
                )
                p200_result = await self.runner.p200_utility(
                    trusted, proposal.target_path
                )
                compatibility_result = await self.runner.broader_suite(trusted)

        trusted_cleaned = trusted.path is not None and not trusted.path.exists()
        compile_result = trusted_prepared["compile_evidence"]
        assert isinstance(compile_result, CommandResult)
        build = self._gate(compile_result)
        patched_source_hash = trusted_prepared.get("patched_source_hash")

        generated: SandboxWorkspace | None = None
        generated_prepared: dict[str, object] = {}
        generated_result: CommandResult | None = None
        same_patch: str = "NOT_RUN"
        generated_workspace_integrity: str = "NOT_RUN"
        if build.status == "PASS" and isinstance(patched_source_hash, str):
            generated = SandboxWorkspace(self.repository_root)
            with generated:
                generated_prepared = await self._prepare_workspace(proposal, generated)
                generated_failure = generated_prepared.get("failure")
                generated_compile = generated_prepared.get("compile_evidence")
                generated_hash = generated_prepared.get("patched_source_hash")
                if (generated_failure is None
                        and isinstance(generated_compile, CommandResult)
                        and generated_compile.passed
                        and generated_hash == patched_source_hash):
                    same_patch = "PASS"
                    generated_workspace_integrity = "PASS"
                    generated_path = generated.resolve_relative(
                        ".gauntlet/generated_tests/test_generated_repair.py"
                    )
                    generated_path.parent.mkdir(parents=True, exist_ok=True)
                    generated_path.write_bytes(proposal.regression_test.encode())
                    if _sha256_text(generated_path.read_text()) == regression_digest:
                        generated_files_before = _workspace_files(generated)
                        generated_result = await self.runner.generated_regression(
                            generated, generated_path
                        )
                        if _changed_files(
                            generated_files_before, _workspace_files(generated)
                        ):
                            generated_workspace_integrity = "FAIL"
                    else:
                        same_patch = "FAIL"
                else:
                    same_patch = "FAIL"

        generated_cleaned = (
            None if generated is None else
            generated.path is not None and not generated.path.exists()
        )
        original_unchanged = repository_digest(self.repository_root) == original_digest
        cleanup = "PASS" if trusted_cleaned and generated_cleaned is not False else "FAIL"
        immutability = "PASS" if original_unchanged else "FAIL"
        completed_at = datetime.now(timezone.utc)
        patch_application = trusted_prepared["patch_application"]
        assert isinstance(patch_application, CommandResult)
        generated_patch_application = generated_prepared.get("patch_application")
        if not isinstance(generated_patch_application, CommandResult):
            generated_patch_application = None
        return PatchAssessment(
            assessment_id=str(uuid4()),
            repair_id=proposal.repair_id,
            candidate_id=candidate_id,
            candidate_digest=candidate_digest,
            candidate_field_digests=candidate_field_digests,
            trace_id=proposal.trace_id,
            boundary_id=proposal.boundary_id,
            evidence_ids=proposal.evidence_ids,
            target_path=proposal.target_path,
            target_symbol=proposal.target_symbol,
            original_source_hash=proposal.source_hash,
            patched_source_hash=(patched_source_hash
                                 if isinstance(patched_source_hash, str) else None),
            patch_digest=patch_digest,
            regression_test_digest=regression_digest,
            trusted_workspace_id=trusted.workspace_id,
            generated_test_workspace_id=(generated.workspace_id if generated else None),
            source_revision=trusted.source_revision,
            files_changed=trusted_prepared.get("files_changed", []),
            trusted_patch_application=patch_application,
            generated_test_patch_application=generated_patch_application,
            build_integrity=build,
            p100_security=self._gate(p100_result),
            p200_utility=self._gate(p200_result),
            compatibility=self._gate(compatibility_result),
            generated_regression=self._gate(generated_result),
            same_patch_integrity=same_patch,
            generated_workspace_integrity=generated_workspace_integrity,
            cleanup=cleanup,
            repository_immutability=immutability,
            trusted_workspace_cleaned=trusted_cleaned,
            generated_test_workspace_cleaned=generated_cleaned,
            original_repository_unchanged=original_unchanged,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=monotonic() - started,
        )
