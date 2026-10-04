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


GateStatus = Literal["PASS", "FAIL", "NOT_RUN"]
PATCH_ASSESSMENT_SCHEMA_VERSION = "gauntlet.patch-assessment.v1"


class GateAssessment(StrictModel):
    """One independently reported deterministic gate outcome."""

    status: GateStatus
    evidence: CommandResult | None = None

    @model_validator(mode="after")
    def status_matches_evidence(self) -> "GateAssessment":
        if self.status == "NOT_RUN" and self.evidence is not None:
            raise ValueError("NOT_RUN gate cannot contain command evidence")
        if self.status != "NOT_RUN" and self.evidence is None:
            raise ValueError("Executed gate requires command evidence")
        if self.evidence is not None and self.evidence.passed != (self.status == "PASS"):
            raise ValueError("Gate status differs from command evidence")
        return self


class PatchAssessment(StrictModel):
    """Versioned multidimensional evaluation of one exact repair candidate.

    Trusted benchmark gates and the model-authored regression test execute in
    different disposable workspaces. Both branches are bound to the same
    source and patch digests; no partial result is represented as PatchProof.
    """

    schema_version: Literal["gauntlet.patch-assessment.v1"] = (
        PATCH_ASSESSMENT_SCHEMA_VERSION
    )
    assessment_id: str
    repair_id: str
    candidate_id: str
    candidate_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_field_digests: dict[str, str]
    trace_id: str
    boundary_id: str
    evidence_ids: list[str] = Field(min_length=1)
    target_path: str
    target_symbol: str
    original_source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    patched_source_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    patch_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    regression_test_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_workspace_id: str
    generated_test_workspace_id: str | None = None
    source_revision: str | None
    files_changed: list[str]
    trusted_patch_application: CommandResult
    generated_test_patch_application: CommandResult | None = None
    build_integrity: GateAssessment
    p100_security: GateAssessment
    p200_utility: GateAssessment
    compatibility: GateAssessment
    generated_regression: GateAssessment
    same_patch_integrity: GateStatus
    generated_workspace_integrity: GateStatus
    cleanup: GateStatus
    repository_immutability: GateStatus
    trusted_workspace_cleaned: bool
    generated_test_workspace_cleaned: bool | None = None
    original_repository_unchanged: bool
    started_at: datetime
    completed_at: datetime
    duration_seconds: float = Field(ge=0)

    @field_validator("assessment_id", "repair_id", "candidate_id")
    @classmethod
    def valid_uuid(cls, value: str) -> str:
        UUID(value)
        return value

    @model_validator(mode="after")
    def coherent_isolated_evaluation(self) -> "PatchAssessment":
        if (self.generated_test_workspace_id is not None
                and self.generated_test_workspace_id == self.trusted_workspace_id):
            raise ValueError("Generated tests require an isolated workspace")
        if self.cleanup == "PASS" and not (
            self.trusted_workspace_cleaned
            and self.generated_test_workspace_cleaned is not False
        ):
            raise ValueError("Cleanup PASS requires every created workspace cleaned")
        if ((self.repository_immutability == "PASS")
                != self.original_repository_unchanged):
            raise ValueError("Repository immutability status differs from observation")
        if self.same_patch_integrity == "PASS" and (
            self.generated_test_workspace_id is None
            or self.generated_test_patch_application is None
            or not self.generated_test_patch_application.passed
        ):
            raise ValueError("Same-patch PASS requires the isolated patch application")
        return self

    @property
    def security_repair_verified(self) -> bool:
        return all(status == "PASS" for status in (
            self.build_integrity.status, self.p100_security.status,
            self.same_patch_integrity, self.cleanup,
            self.repository_immutability,
        ))

    @property
    def utility_preserved(self) -> bool:
        return all(status == "PASS" for status in (
            self.build_integrity.status, self.p200_utility.status,
            self.same_patch_integrity, self.cleanup,
            self.repository_immutability,
        ))

    @property
    def compatibility_preserved(self) -> bool:
        return all(status == "PASS" for status in (
            self.build_integrity.status, self.compatibility.status,
            self.same_patch_integrity, self.cleanup,
            self.repository_immutability,
        ))

    @property
    def generated_regression_valid(self) -> bool:
        return (
            self.same_patch_integrity == "PASS"
            and self.generated_workspace_integrity == "PASS"
            and self.generated_regression.status == "PASS"
            and self.cleanup == "PASS"
            and self.repository_immutability == "PASS"
        )

    @property
    def full_candidate_verified(self) -> bool:
        return all((
            self.security_repair_verified,
            self.utility_preserved,
            self.compatibility_preserved,
            self.generated_regression_valid,
        ))
