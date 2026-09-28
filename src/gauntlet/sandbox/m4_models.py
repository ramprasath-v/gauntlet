"""Execution-derived M4.1 proof for one exact validated proposal."""
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from gauntlet.remediation.models import StrictModel
from gauntlet.sandbox.models import CommandResult


class PatchProof(StrictModel):
    proof_id: str
    repair_id: str
    trace_id: str
    boundary_id: str
    evidence_ids: list[str] = Field(min_length=1)
    target_path: str
    target_symbol: str
    original_source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    patched_source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    patch_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    regression_test_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    workspace_id: str
    source_revision: str | None
    files_changed: list[str]
    patch_application: CommandResult
    compile_evidence: CommandResult
    generated_regression_evidence: CommandResult
    p100_security_evidence: CommandResult
    p200_utility_evidence: CommandResult
    broader_suite_evidence: CommandResult
    started_at: datetime
    completed_at: datetime
    duration_seconds: float = Field(ge=0)
    workspace_cleaned: bool
    original_repository_unchanged: bool
    status: Literal["VERIFIED"] = "VERIFIED"

    @field_validator("proof_id", "repair_id")
    @classmethod
    def valid_uuid(cls, value: str) -> str:
        UUID(value)
        return value

    @model_validator(mode="after")
    def status_comes_only_from_execution(self) -> "PatchProof":
        evidence = (
            self.patch_application,
            self.compile_evidence,
            self.generated_regression_evidence,
            self.p100_security_evidence,
            self.p200_utility_evidence,
            self.broader_suite_evidence,
        )
        if not all(item.passed for item in evidence):
            raise ValueError("VERIFIED requires every recorded command to pass")
        if self.files_changed != [self.target_path]:
            raise ValueError("VERIFIED requires only the authorized target to change")
        if self.original_source_hash == self.patched_source_hash:
            raise ValueError("VERIFIED requires an observed source change")
        if not self.workspace_cleaned or not self.original_repository_unchanged:
            raise ValueError("VERIFIED requires cleanup and unchanged original repository")
        return self

    @property
    def verified(self) -> bool:
        return self.status == "VERIFIED"
