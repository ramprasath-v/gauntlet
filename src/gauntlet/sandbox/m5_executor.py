"""Deterministic M5.1 evaluation of one exact retained patch."""
import ast
import hashlib
from pathlib import Path
from time import monotonic
from datetime import datetime, timezone
from uuid import uuid4

from gauntlet.attacks.indirect_prompt_injection_mutations import ATTACK_MUTATIONS
from gauntlet.remediation.candidate_artifact import (
    RepairCandidateArtifact, load_candidate_artifact,
)
from gauntlet.sandbox.m4_models import GateAssessment
from gauntlet.sandbox.m5_models import (
    AttackMutationAssessment, AttackMutationEvidence, MutationPatchInput,
)
from gauntlet.sandbox.m5_runner import M51CommandRunner
from gauntlet.sandbox.models import CommandResult
from gauntlet.sandbox.workspace import (
    REQUIRED_PATHS, SandboxWorkspace, repository_digest,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _symbol_text(path: Path, symbol: str) -> str:
    parts = symbol.split(".")
    if len(parts) != 2:
        raise ValueError("M5.1 supports an authorized Class.method target")
    source = path.read_text()
    tree = ast.parse(source)
    class_node = next(
        (node for node in tree.body
         if isinstance(node, ast.ClassDef) and node.name == parts[0]), None,
    )
    method = next(
        (node for node in class_node.body
         if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
         and node.name == parts[1]), None,
    ) if class_node else None
    if method is None or method.end_lineno is None:
        raise ValueError("Authorized target symbol is missing")
    return "".join(source.splitlines(keepends=True)[
        method.lineno - 1:method.end_lineno
    ])


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


def _gate(result: CommandResult | None) -> GateAssessment:
    if result is None:
        return GateAssessment(status="NOT_RUN")
    return GateAssessment(status="PASS" if result.passed else "FAIL", evidence=result)


class M51MutationExecutor:
    """Qualify and evaluate fixed attacks without changing repair semantics."""

    def __init__(
        self, repository_root: Path, *, runner: M51CommandRunner | None = None,
    ):
        self.repository_root = repository_root.resolve(strict=True)
        self.runner = runner or M51CommandRunner()

    def _verify_source(self, workspace: SandboxWorkspace, candidate: MutationPatchInput) -> None:
        target = workspace.resolve_relative(candidate.target_path)
        observed = _digest(_symbol_text(target, candidate.target_symbol))
        if observed != candidate.source_hash:
            raise ValueError(
                "Workspace source identity differs from the retained candidate"
            )

    async def run_persisted_candidate(
        self,
        path: Path,
        *,
        expected_candidate_id: str,
        expected_patch_digest: str,
    ) -> AttackMutationAssessment:
        artifact = load_candidate_artifact(path)
        if not isinstance(artifact, RepairCandidateArtifact):
            raise ValueError("M5.1 requires gauntlet.repair-candidate.v3")
        if artifact.candidate_id != expected_candidate_id:
            raise ValueError("Retained candidate ID differs from the expected candidate")
        if artifact.derived_patch is None or artifact.derived_patch_digest is None:
            raise ValueError("Retained candidate does not contain a derived patch")
        if artifact.derived_patch_digest != expected_patch_digest:
            raise ValueError("Retained patch digest differs from the expected digest")
        return await self.run(MutationPatchInput(
            candidate_schema_version=artifact.schema_version,
            candidate_id=artifact.candidate_id,
            candidate_digest=artifact.candidate_digest,
            target_path=artifact.target_path,
            target_symbol=artifact.target_symbol,
            source_hash=artifact.source_hash,
            patch=artifact.derived_patch,
            patch_digest=artifact.derived_patch_digest,
        ))

    async def run(self, candidate: MutationPatchInput) -> AttackMutationAssessment:
        if _digest(candidate.patch) != candidate.patch_digest:
            raise ValueError("Execution patch differs from its integrity digest")
        repository_source = self.repository_root / candidate.target_path
        if _digest(_symbol_text(repository_source, candidate.target_symbol)) != candidate.source_hash:
            raise ValueError("Repository source identity differs from the retained candidate")

        original_digest = repository_digest(self.repository_root)
        started_at = datetime.now(timezone.utc)
        started = monotonic()
        evidence: list[AttackMutationEvidence] = []
        source_revision: str | None = None

        for mutation in ATTACK_MUTATIONS:
            pre = SandboxWorkspace(self.repository_root)
            with pre:
                source_revision = source_revision or pre.source_revision
                self._verify_source(pre, candidate)
                pre_result = await self.runner.pre_patch_mutation(
                    pre, mutation.mutation_id
                )
            pre_cleaned = pre.path is not None and not pre.path.exists()

            if not pre_result.passed:
                evidence.append(AttackMutationEvidence(
                    mutation_id=mutation.mutation_id,
                    dimension=mutation.dimension,
                    description=mutation.description,
                    product_id=mutation.product_id,
                    payload_digest=mutation.payload_digest,
                    user_prompt_digest=mutation.user_prompt_digest,
                    source_hash=candidate.source_hash,
                    patch_digest=candidate.patch_digest,
                    pre_patch_source_identity="PASS",
                    post_patch_source_identity="NOT_RUN",
                    pre_patch_workspace_id=pre.workspace_id,
                    pre_patch_attack=_gate(pre_result),
                    post_patch_compile=_gate(None),
                    post_patch_attack=_gate(None),
                    pre_patch_attack_reproduced="FAIL",
                    post_patch_attack_blocked="NOT_RUN",
                    post_patch_files_changed=[],
                    pre_patch_workspace_cleaned=pre_cleaned,
                ))
                continue

            post = SandboxWorkspace(self.repository_root)
            patch_result: CommandResult | None = None
            compile_result: CommandResult | None = None
            post_result: CommandResult | None = None
            files_changed: list[str] = []
            with post:
                self._verify_source(post, candidate)
                before_files = _workspace_files(post)
                artifact_dir = post.resolve_relative(".gauntlet/artifacts")
                artifact_dir.mkdir(parents=True, exist_ok=True)
                patch_path = artifact_dir / "retained.patch"
                patch_path.write_bytes(candidate.patch.encode())
                if _digest(patch_path.read_text()) != candidate.patch_digest:
                    raise ValueError("Materialized patch differs from its integrity digest")
                patch_result = await self.runner.apply_patch(post, patch_path)
                if patch_result.passed:
                    files_changed = _changed_files(
                        before_files, _workspace_files(post)
                    )
                if patch_result.passed and files_changed == [candidate.target_path]:
                    compile_result = await self.runner.compile(post)
                if compile_result is not None and compile_result.passed:
                    patched_hash = _digest(_symbol_text(
                        post.resolve_relative(candidate.target_path),
                        candidate.target_symbol,
                    ))
                    if patched_hash == candidate.source_hash:
                        raise ValueError("Retained patch did not change its target symbol")
                    post_result = await self.runner.post_patch_mutation(
                        post, mutation.mutation_id
                    )
            post_cleaned = post.path is not None and not post.path.exists()

            evidence.append(AttackMutationEvidence(
                mutation_id=mutation.mutation_id,
                dimension=mutation.dimension,
                description=mutation.description,
                product_id=mutation.product_id,
                payload_digest=mutation.payload_digest,
                user_prompt_digest=mutation.user_prompt_digest,
                source_hash=candidate.source_hash,
                patch_digest=candidate.patch_digest,
                pre_patch_source_identity="PASS",
                post_patch_source_identity="PASS",
                pre_patch_workspace_id=pre.workspace_id,
                post_patch_workspace_id=post.workspace_id,
                pre_patch_attack=_gate(pre_result),
                post_patch_application=patch_result,
                post_patch_compile=_gate(compile_result),
                post_patch_attack=_gate(post_result),
                pre_patch_attack_reproduced="PASS",
                post_patch_attack_blocked=(
                    "NOT_RUN" if post_result is None
                    else "PASS" if post_result.passed else "FAIL"
                ),
                post_patch_files_changed=files_changed,
                pre_patch_workspace_cleaned=pre_cleaned,
                post_patch_workspace_cleaned=post_cleaned,
            ))

        original_unchanged = repository_digest(self.repository_root) == original_digest
        all_cleaned = all(
            item.pre_patch_workspace_cleaned
            and item.post_patch_workspace_cleaned is not False
            for item in evidence
        )
        return AttackMutationAssessment(
            assessment_id=str(uuid4()),
            candidate_schema_version=candidate.candidate_schema_version,
            candidate_id=candidate.candidate_id,
            candidate_digest=candidate.candidate_digest,
            target_path=candidate.target_path,
            target_symbol=candidate.target_symbol,
            source_hash=candidate.source_hash,
            patch_digest=candidate.patch_digest,
            source_revision=source_revision,
            mutations=evidence,
            cleanup="PASS" if all_cleaned else "FAIL",
            repository_immutability="PASS" if original_unchanged else "FAIL",
            original_repository_unchanged=original_unchanged,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            duration_seconds=monotonic() - started,
        )
