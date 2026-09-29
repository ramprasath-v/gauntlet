"""Exact, integrity-checked retention for decoded repair candidates."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from gauntlet.remediation.models import (
    GeneratedRepairCandidate, StrictModel, StructuredRegressionTest,
    StructuredSourceEdit,
)


LEGACY_CANDIDATE_ARTIFACT_SCHEMA_VERSION = "gauntlet.repair-candidate.v1"
STRUCTURED_V2_CANDIDATE_ARTIFACT_SCHEMA_VERSION = "gauntlet.repair-candidate.v2"
CANDIDATE_ARTIFACT_SCHEMA_VERSION = "gauntlet.repair-candidate.v3"
CANDIDATE_FIELDS = (
    "rationale", "source_edit", "regression_test", "optional_policy_artifact",
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def candidate_identity(
    candidate: GeneratedRepairCandidate,
) -> tuple[str, dict[str, str]]:
    fields = candidate.model_dump(mode="json")
    return (
        _digest(candidate.model_dump_json()),
        {
            name: _digest(json.dumps(value, ensure_ascii=True))
            for name, value in fields.items()
        },
    )


class LegacyGeneratedRepairCandidate(StrictModel):
    rationale: str
    patch: str
    regression_test: str
    optional_policy_artifact: str | None = None


class LegacyStructuredSourceEditV2(StrictModel):
    """Historical v2 source-edit contract retained for evidence loading."""

    target_path: str
    target_symbol: str
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    start_line: int
    delete_line_count: int
    expected_original_lines: list[str]
    replacement_lines: list[str]


class LegacyGeneratedRepairCandidateV2(StrictModel):
    rationale: str
    source_edit: LegacyStructuredSourceEditV2
    regression_test: StructuredRegressionTest
    optional_policy_artifact: str | None = None


def _legacy_candidate_identity(
    candidate: LegacyGeneratedRepairCandidate,
) -> tuple[str, dict[str, str]]:
    fields = candidate.model_dump(mode="json")
    return (
        _digest(candidate.model_dump_json()),
        {
            name: _digest(json.dumps(value, ensure_ascii=True))
            for name, value in fields.items()
        },
    )


class CandidateArtifactReference(StrictModel):
    schema_version: Literal[
        "gauntlet.repair-candidate.v1", "gauntlet.repair-candidate.v2",
        "gauntlet.repair-candidate.v3",
    ]
    candidate_id: str
    attempt_number: int = Field(ge=1, le=3)
    path: str
    candidate_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    integrity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("candidate_id")
    @classmethod
    def valid_candidate_id(cls, value: str) -> str:
        UUID(value)
        return value

    @field_validator("path")
    @classmethod
    def safe_relative_path(cls, value: str) -> str:
        path = Path(value)
        if path.is_absolute() or ".." in path.parts or not value:
            raise ValueError("Candidate artifact reference must be a safe relative path")
        return path.as_posix()


class _ArtifactIdentity(StrictModel):
    candidate_id: str
    run_id: str
    attempt_number: int = Field(ge=1, le=3)
    provider: str
    model: str
    created_at: datetime
    trace_id: str
    boundary_id: str
    evidence_ids: list[str] = Field(min_length=1)
    target_path: str
    target_symbol: str
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_field_digests: dict[str, str]
    integrity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("candidate_id", "run_id")
    @classmethod
    def valid_uuid(cls, value: str) -> str:
        UUID(value)
        return value


class LegacyRepairCandidateArtifact(_ArtifactIdentity):
    schema_version: Literal["gauntlet.repair-candidate.v1"]
    rationale: str
    patch: str
    regression_test: str
    optional_policy_artifact: str | None = None

    def legacy_candidate(self) -> LegacyGeneratedRepairCandidate:
        return LegacyGeneratedRepairCandidate(
            rationale=self.rationale,
            patch=self.patch,
            regression_test=self.regression_test,
            optional_policy_artifact=self.optional_policy_artifact,
        )

    @model_validator(mode="after")
    def exact_content_and_integrity(self) -> "LegacyRepairCandidateArtifact":
        candidate_digest, field_digests = _legacy_candidate_identity(
            self.legacy_candidate()
        )
        if self.candidate_digest != candidate_digest:
            raise ValueError("Repair candidate integrity failed: candidate_digest")
        if self.candidate_field_digests != field_digests:
            raise ValueError("Repair candidate integrity failed: field digests")
        if self.integrity_digest != _artifact_digest(self):
            raise ValueError("Repair candidate integrity failed: integrity_digest")
        return self


class _StructuredArtifactFields(_ArtifactIdentity):
    rationale: str
    regression_test: StructuredRegressionTest
    optional_policy_artifact: str | None = None
    derived_patch: str | None = None
    derived_regression_test: str | None = None
    derived_patch_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    derived_regression_test_digest: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )

    def _validate_derived_integrity(self) -> None:
        derived = (
            self.derived_patch,
            self.derived_regression_test,
            self.derived_patch_digest,
            self.derived_regression_test_digest,
        )
        if any(value is not None for value in derived) and any(
            value is None for value in derived
        ):
            raise ValueError("Derived candidate evidence must be complete or absent")
        if self.derived_patch is not None:
            if self.derived_patch_digest != _digest(self.derived_patch):
                raise ValueError("Repair candidate integrity failed: derived patch")
            if self.derived_regression_test_digest != _digest(
                self.derived_regression_test or ""
            ):
                raise ValueError("Repair candidate integrity failed: derived regression")


class RepairCandidateArtifactV2(_StructuredArtifactFields):
    schema_version: Literal["gauntlet.repair-candidate.v2"]
    source_edit: LegacyStructuredSourceEditV2

    def candidate_v2(self) -> LegacyGeneratedRepairCandidateV2:
        return LegacyGeneratedRepairCandidateV2(
            rationale=self.rationale,
            source_edit=self.source_edit,
            regression_test=self.regression_test,
            optional_policy_artifact=self.optional_policy_artifact,
        )

    @model_validator(mode="after")
    def exact_content_and_integrity(self) -> "RepairCandidateArtifactV2":
        candidate_digest, field_digests = _legacy_candidate_identity(
            self.candidate_v2()
        )
        if self.candidate_digest != candidate_digest:
            raise ValueError("Repair candidate integrity failed: candidate_digest")
        if self.candidate_field_digests != field_digests:
            raise ValueError("Repair candidate integrity failed: field digests")
        self._validate_derived_integrity()
        if self.integrity_digest != _artifact_digest(self):
            raise ValueError("Repair candidate integrity failed: integrity_digest")
        return self


class RepairCandidateArtifact(_StructuredArtifactFields):
    schema_version: Literal["gauntlet.repair-candidate.v3"]
    source_edit: StructuredSourceEdit

    def candidate(self) -> GeneratedRepairCandidate:
        return GeneratedRepairCandidate(
            rationale=self.rationale,
            source_edit=self.source_edit,
            regression_test=self.regression_test,
            optional_policy_artifact=self.optional_policy_artifact,
        )

    @model_validator(mode="after")
    def exact_content_and_integrity(self) -> "RepairCandidateArtifact":
        candidate_digest, field_digests = candidate_identity(self.candidate())
        if self.candidate_digest != candidate_digest:
            raise ValueError("Repair candidate integrity failed: candidate_digest")
        if self.candidate_field_digests != field_digests:
            raise ValueError("Repair candidate integrity failed: field digests")
        self._validate_derived_integrity()
        if self.integrity_digest != _artifact_digest(self):
            raise ValueError("Repair candidate integrity failed: integrity_digest")
        return self


def _artifact_payload(
    artifact: (
        RepairCandidateArtifact | RepairCandidateArtifactV2
        | LegacyRepairCandidateArtifact
    ),
) -> str:
    return json.dumps(
        artifact.model_dump(mode="json", exclude={"integrity_digest"}),
        ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    )


def _artifact_digest(
    artifact: (
        RepairCandidateArtifact | RepairCandidateArtifactV2
        | LegacyRepairCandidateArtifact
    ),
) -> str:
    return _digest(_artifact_payload(artifact))


def persist_candidate_artifact(
    candidate: GeneratedRepairCandidate,
    *,
    path: Path,
    candidate_id: str,
    run_id: str,
    attempt_number: int,
    provider: str,
    model: str,
    trace_id: str,
    boundary_id: str,
    evidence_ids: list[str],
    target_path: str,
    target_symbol: str,
    source_hash: str,
    derived_patch: str | None = None,
    derived_regression_test: str | None = None,
) -> RepairCandidateArtifact:
    candidate_digest, field_digests = candidate_identity(candidate)
    values = dict(
        schema_version=CANDIDATE_ARTIFACT_SCHEMA_VERSION,
        candidate_id=candidate_id,
        run_id=run_id,
        attempt_number=attempt_number,
        provider=provider,
        model=model,
        created_at=datetime.now(timezone.utc),
        trace_id=trace_id,
        boundary_id=boundary_id,
        evidence_ids=evidence_ids,
        target_path=target_path,
        target_symbol=target_symbol,
        source_hash=source_hash,
        rationale=candidate.rationale,
        source_edit=candidate.source_edit,
        regression_test=candidate.regression_test,
        optional_policy_artifact=candidate.optional_policy_artifact,
        derived_patch=derived_patch,
        derived_regression_test=derived_regression_test,
        derived_patch_digest=(
            _digest(derived_patch) if derived_patch is not None else None
        ),
        derived_regression_test_digest=(
            _digest(derived_regression_test)
            if derived_regression_test is not None else None
        ),
        candidate_digest=candidate_digest,
        candidate_field_digests=field_digests,
    )
    provisional = RepairCandidateArtifact.model_construct(
        **values, integrity_digest="0" * 64
    )
    artifact = RepairCandidateArtifact(
        **values, integrity_digest=_artifact_digest(provisional)
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(artifact.model_dump_json(indent=2) + "\n")
    return artifact


def load_candidate_artifact(
    path: Path,
) -> (
    RepairCandidateArtifact | RepairCandidateArtifactV2
    | LegacyRepairCandidateArtifact
):
    raw = path.read_text()
    payload = json.loads(raw)
    if payload.get("schema_version") == LEGACY_CANDIDATE_ARTIFACT_SCHEMA_VERSION:
        return LegacyRepairCandidateArtifact.model_validate_json(raw)
    if payload.get("schema_version") == STRUCTURED_V2_CANDIDATE_ARTIFACT_SCHEMA_VERSION:
        return RepairCandidateArtifactV2.model_validate_json(raw)
    if payload.get("schema_version") == CANDIDATE_ARTIFACT_SCHEMA_VERSION:
        return RepairCandidateArtifact.model_validate_json(raw)
    raise ValueError("Unsupported repair candidate artifact schema version")


def candidate_artifact_location(
    run_evidence_path: Path, attempt_number: int, candidate_id: str,
) -> tuple[Path, str]:
    directory = run_evidence_path.parent / f"{run_evidence_path.stem}.candidates"
    path = directory / f"attempt-{attempt_number:02d}-{candidate_id}.json"
    return path, path.relative_to(run_evidence_path.parent).as_posix()
