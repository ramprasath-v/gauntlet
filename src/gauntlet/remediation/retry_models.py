"""Safe lineage and terminal results for bounded M4.2 repair runs."""
from datetime import datetime
import hashlib
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from gauntlet.remediation.candidate_artifact import (
    CandidateArtifactReference, ValidatedEditArtifactReference,
)
from gauntlet.remediation.models import RepairFailure, RepairProposal, StrictModel
from gauntlet.sandbox.m4_models import PatchAssessment, PatchProof


StepOutcome = Literal["NOT_RUN", "PASS", "FAIL", "VERIFIED"]


class SafeProviderCompletion(StrictModel):
    http_status: int | None = None
    response_id: str | None = None
    returned_model: str | None = None
    finish_reason: str | None = None
    content_type: str | None = None
    content_length: int | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None


class RepairAttempt(StrictModel):
    attempt: int = Field(ge=1, le=3)
    candidate_id: str
    previous_failure_id: str | None = None
    provider: str
    model: str
    candidate_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_field_digests: dict[str, str]
    candidate_field_lengths: dict[str, int]
    candidate_artifact: CandidateArtifactReference | None = None
    edit_artifact: ValidatedEditArtifactReference | None = None
    edit_provider_call: StepOutcome
    edit_decode: StepOutcome
    edit_validation: StepOutcome
    edit_reused: bool = False
    test_provider_call: StepOutcome
    test_decode: StepOutcome
    test_validation: StepOutcome
    proposal_execution: StepOutcome
    patch_proof: StepOutcome
    repair_id: str | None = None
    failure: RepairFailure | None = None
    proof_id: str | None = None
    assessment: PatchAssessment | None = None
    workspace_id: str | None = None
    edit_provider_completion: SafeProviderCompletion | None = None
    test_provider_completion: SafeProviderCompletion | None = None
    started_at: datetime
    completed_at: datetime
    duration_seconds: float = Field(ge=0)

    @field_validator(
        "candidate_id", "previous_failure_id", "repair_id", "proof_id"
    )
    @classmethod
    def valid_optional_uuid(cls, value: str | None) -> str | None:
        if value is not None:
            UUID(value)
        return value

    @model_validator(mode="after")
    def coherent_outcome(self) -> "RepairAttempt":
        if self.assessment is not None and (
            self.assessment.candidate_id != self.candidate_id
            or self.assessment.candidate_digest != self.candidate_digest
            or self.assessment.candidate_field_digests != self.candidate_field_digests
            or self.assessment.repair_id != self.repair_id
            or self.assessment.assessment_id != self.proof_id
            or self.assessment.trusted_workspace_id != self.workspace_id
        ):
            raise ValueError("Attempt identity differs from its patch assessment")
        if self.patch_proof == "VERIFIED":
            if (self.edit_provider_call, self.edit_decode, self.edit_validation,
                    self.test_provider_call, self.test_decode,
                    self.test_validation, self.proposal_execution) != (
                "PASS", "PASS", "PASS", "PASS", "PASS", "PASS", "PASS"
            ) or not self.proof_id or self.failure is not None:
                raise ValueError("VERIFIED attempt requires complete successful lineage")
            if self.assessment is not None and not self.assessment.full_candidate_verified:
                raise ValueError("VERIFIED attempt requires a fully verified assessment")
        elif self.failure is None:
            raise ValueError("Unverified attempt requires a structured failure")
        return self


class RepairRunSucceeded(StrictModel):
    status: Literal["VERIFIED"] = "VERIFIED"
    run_id: str
    trace_id: str
    boundary_id: str
    evidence_ids: list[str] = Field(min_length=1)
    provider: str
    model: str
    total_attempts: int = Field(ge=1, le=3)
    successful_attempt: int = Field(ge=1, le=3)
    attempts: list[RepairAttempt] = Field(min_length=1, max_length=3)
    final_proposal: RepairProposal
    patch_proof: PatchProof | None = None
    assessment: PatchAssessment | None = None
    started_at: datetime
    completed_at: datetime
    duration_seconds: float = Field(ge=0)
    original_repository_unchanged: bool

    @field_validator("run_id")
    @classmethod
    def valid_run_uuid(cls, value: str) -> str:
        UUID(value)
        return value

    @model_validator(mode="after")
    def verified_by_m41_only(self) -> "RepairRunSucceeded":
        legacy_verified = self.patch_proof is not None and self.patch_proof.verified
        assessed_verified = (
            self.assessment is not None
            and self.assessment.full_candidate_verified
        )
        proof_identity = (
            self.patch_proof.proof_id if self.patch_proof is not None
            else self.assessment.assessment_id if self.assessment is not None
            else None
        )
        repair_identity = (
            self.patch_proof.repair_id if self.patch_proof is not None
            else self.assessment.repair_id if self.assessment is not None
            else None
        )
        if ((legacy_verified == assessed_verified)
                or self.total_attempts != len(self.attempts)
                or self.successful_attempt != self.total_attempts
                or self.attempts[-1].proof_id != proof_identity
                or self.final_proposal.repair_id != repair_identity
                or not self.original_repository_unchanged):
            raise ValueError("Repair run success requires one final verified proof")
        if self.assessment is not None and (
            self.attempts[-1].assessment != self.assessment
            or hashlib.sha256(self.final_proposal.patch.encode()).hexdigest()
            != self.assessment.patch_digest
            or hashlib.sha256(
                self.final_proposal.regression_test.encode()
            ).hexdigest() != self.assessment.regression_test_digest
        ):
            raise ValueError("Final proposal differs from the verified assessment")
        return self


class RepairRunFailed(StrictModel):
    status: Literal["FAILED"] = "FAILED"
    run_id: str
    trace_id: str
    boundary_id: str
    evidence_ids: list[str] = Field(min_length=1)
    provider: str
    model: str
    total_attempts: Literal[3]
    attempts: list[RepairAttempt] = Field(min_length=3, max_length=3)
    final_failure: RepairFailure
    safe_failure_summary: str = Field(min_length=1, max_length=1_000)
    started_at: datetime
    completed_at: datetime
    duration_seconds: float = Field(ge=0)
    original_repository_unchanged: bool

    @field_validator("run_id")
    @classmethod
    def valid_run_uuid(cls, value: str) -> str:
        UUID(value)
        return value

    @model_validator(mode="after")
    def exhausted_without_proof(self) -> "RepairRunFailed":
        if (len(self.attempts) != 3
                or self.attempts[-1].failure != self.final_failure
                or any(item.patch_proof == "VERIFIED" for item in self.attempts)):
            raise ValueError("Failed repair run must exhaust three unverified attempts")
        return self


RepairRunResult = RepairRunSucceeded | RepairRunFailed
