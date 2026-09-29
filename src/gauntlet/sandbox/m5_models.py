"""Versioned evidence for independent pre/post attack-mutation proof."""
from datetime import datetime
import hashlib
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from gauntlet.remediation.models import StrictModel
from gauntlet.sandbox.m4_models import GateAssessment, GateStatus
from gauntlet.sandbox.models import CommandResult


ATTACK_MUTATION_ASSESSMENT_VERSION = "gauntlet.attack-mutation-assessment.v1"


class MutationPatchInput(StrictModel):
    """Exact already-generated patch identity accepted by the M5 evaluator."""

    candidate_schema_version: Literal["gauntlet.repair-candidate.v3"]
    candidate_id: str
    candidate_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_path: str
    target_symbol: str
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    patch: str = Field(min_length=1)
    patch_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("candidate_id")
    @classmethod
    def valid_candidate_id(cls, value: str) -> str:
        UUID(value)
        return value

    @model_validator(mode="after")
    def exact_patch_digest(self) -> "MutationPatchInput":
        if hashlib.sha256(self.patch.encode()).hexdigest() != self.patch_digest:
            raise ValueError("Patch content differs from its declared digest")
        return self


class AttackMutationEvidence(StrictModel):
    mutation_id: str
    dimension: str
    description: str
    product_id: str
    payload_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    user_prompt_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    patch_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    pre_patch_source_identity: Literal["PASS"]
    post_patch_source_identity: Literal["PASS", "NOT_RUN"]
    pre_patch_workspace_id: str
    post_patch_workspace_id: str | None = None
    pre_patch_attack: GateAssessment
    post_patch_application: CommandResult | None = None
    post_patch_compile: GateAssessment
    post_patch_attack: GateAssessment
    pre_patch_attack_reproduced: Literal["PASS", "FAIL"]
    post_patch_attack_blocked: GateStatus
    post_patch_files_changed: list[str]
    pre_patch_workspace_cleaned: bool
    post_patch_workspace_cleaned: bool | None = None

    @model_validator(mode="after")
    def coherent_outcomes(self) -> "AttackMutationEvidence":
        if ((self.pre_patch_attack_reproduced == "PASS")
                != (self.pre_patch_attack.status == "PASS")):
            raise ValueError("Pre-patch qualification differs from command evidence")
        if self.pre_patch_attack_reproduced == "FAIL":
            if self.post_patch_attack_blocked != "NOT_RUN":
                raise ValueError("Unqualified mutation cannot claim a post-patch result")
            if self.post_patch_workspace_id is not None:
                raise ValueError("Unqualified mutation cannot create a post workspace")
            if self.post_patch_source_identity != "NOT_RUN":
                raise ValueError("Unqualified mutation has no post source identity")
        if self.post_patch_attack_blocked != self.post_patch_attack.status:
            raise ValueError("Post-patch status differs from command evidence")
        if self.post_patch_attack.status != "NOT_RUN" and (
            self.post_patch_application is None
            or not self.post_patch_application.passed
            or self.post_patch_compile.status != "PASS"
        ):
            raise ValueError("Post-patch attack requires applied, compiled patch")
        return self

    @property
    def counts_toward_proof(self) -> bool:
        return self.pre_patch_attack_reproduced == "PASS"

    @property
    def verified(self) -> bool:
        return self.counts_toward_proof and self.post_patch_attack_blocked == "PASS"


class AttackMutationAssessment(StrictModel):
    schema_version: Literal["gauntlet.attack-mutation-assessment.v1"] = (
        ATTACK_MUTATION_ASSESSMENT_VERSION
    )
    assessment_id: str
    candidate_schema_version: Literal["gauntlet.repair-candidate.v3"]
    candidate_id: str
    candidate_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_path: str
    target_symbol: str
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    patch_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_revision: str | None
    mutations: list[AttackMutationEvidence] = Field(min_length=4, max_length=4)
    cleanup: GateStatus
    repository_immutability: GateStatus
    original_repository_unchanged: bool
    started_at: datetime
    completed_at: datetime
    duration_seconds: float = Field(ge=0)

    @field_validator("assessment_id", "candidate_id")
    @classmethod
    def valid_uuid(cls, value: str) -> str:
        UUID(value)
        return value

    @model_validator(mode="after")
    def coherent_assessment(self) -> "AttackMutationAssessment":
        ids = [item.mutation_id for item in self.mutations]
        if len(set(ids)) != len(ids):
            raise ValueError("Mutation evidence IDs must be unique")
        if any(item.source_hash != self.source_hash for item in self.mutations):
            raise ValueError("Mutation evidence source hashes must match candidate")
        if any(item.patch_digest != self.patch_digest for item in self.mutations):
            raise ValueError("Mutation evidence patch digests must match candidate")
        all_cleaned = all(
            item.pre_patch_workspace_cleaned
            and item.post_patch_workspace_cleaned is not False
            for item in self.mutations
        )
        if (self.cleanup == "PASS") != all_cleaned:
            raise ValueError("Cleanup status differs from workspace observations")
        if ((self.repository_immutability == "PASS")
                != self.original_repository_unchanged):
            raise ValueError("Repository immutability differs from observation")
        return self

    @property
    def qualified_mutation_count(self) -> int:
        return sum(item.counts_toward_proof for item in self.mutations)

    @property
    def blocked_mutation_count(self) -> int:
        return sum(item.verified for item in self.mutations)

    @property
    def verified(self) -> bool:
        return (
            self.qualified_mutation_count == len(self.mutations)
            and self.blocked_mutation_count == len(self.mutations)
            and self.cleanup == "PASS"
            and self.repository_immutability == "PASS"
        )
