"""Independent contract re-verification for an exact repair proposal."""

from hashlib import sha256
from pathlib import Path
from typing import Protocol

from pydantic import Field

from gauntlet.contracts.models import ContractEvaluation
from gauntlet.remediation.context import read_authorized_source_text
from gauntlet.remediation.models import RepairProposal, StrictModel
from gauntlet.sandbox.m4_runner import M41CommandRunner
from gauntlet.sandbox.models import CommandResult
from gauntlet.sandbox.workspace import SandboxWorkspace, repository_digest


class ContractVerificationCase(StrictModel):
    case_id: str = Field(min_length=1, max_length=128)
    expected_behavior_observed: bool
    evaluation: ContractEvaluation


class ContractReverification(StrictModel):
    contract_id: str = Field(min_length=1, max_length=128)
    cases: list[ContractVerificationCase] = Field(min_length=1)

    @property
    def passed(self) -> bool:
        return all(case.expected_behavior_observed for case in self.cases)


class ContractVerifier(Protocol):
    async def __call__(self, workspace_root: Path) -> ContractReverification: ...


class ContractRepairAssessment(StrictModel):
    repair_id: str
    target_path: str
    patch_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_identity: str
    patch_application: CommandResult | None = None
    compilation: CommandResult | None = None
    reverification: ContractReverification | None = None
    verdict: str
    cleanup: str
    repository_immutability: str


class ContractRepairExecutor:
    """Apply exact candidate bytes, compile, then invoke a trusted evaluator adapter."""

    def __init__(
        self, repository_root: Path, *, runner: M41CommandRunner | None = None
    ) -> None:
        self.repository_root = repository_root.resolve(strict=True)
        self.runner = runner or M41CommandRunner()

    async def run(
        self, proposal: RepairProposal, verifier: ContractVerifier,
    ) -> ContractRepairAssessment:
        before = repository_digest(self.repository_root)
        patch_digest = sha256(proposal.patch.encode()).hexdigest()
        source_identity = "FAIL"
        application = compilation = None
        reverification = None
        verdict = "NOT_VERIFIED"
        workspace = SandboxWorkspace(self.repository_root)
        with workspace:
            assert workspace.path is not None
            _, source = read_authorized_source_text(
                workspace.path,
                target_path=proposal.target_path,
                target_symbol=proposal.target_symbol,
            )
            if sha256(source.encode()).hexdigest() == proposal.source_hash:
                source_identity = "PASS"
                artifact = workspace.resolve_relative(".gauntlet/contract-repair.patch")
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_bytes(proposal.patch.encode())
                application = await self.runner.apply_patch(workspace, artifact)
                if application.passed:
                    compilation = await self.runner.compile(workspace)
                    if compilation.passed:
                        reverification = await verifier(workspace.path)
                        if reverification.passed:
                            verdict = "VERIFIED"
        cleanup = "PASS" if workspace.path and not workspace.path.exists() else "FAIL"
        unchanged = repository_digest(self.repository_root) == before
        return ContractRepairAssessment(
            repair_id=proposal.repair_id,
            target_path=proposal.target_path,
            patch_digest=patch_digest,
            source_identity=source_identity,
            patch_application=application,
            compilation=compilation,
            reverification=reverification,
            verdict=verdict,
            cleanup=cleanup,
            repository_immutability="PASS" if unchanged else "FAIL",
        )
