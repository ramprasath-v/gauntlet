"""Exact, integrity-checked retention for decoded repair candidates."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from gauntlet.remediation.models import GeneratedRepairCandidate, StrictModel


CANDIDATE_ARTIFACT_SCHEMA_VERSION = "gauntlet.repair-candidate.v1"
CANDIDATE_FIELDS = (
    "rationale", "patch", "regression_test", "optional_policy_artifact",
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


class CandidateArtifactReference(StrictModel):
    schema_version: Literal["gauntlet.repair-candidate.v1"]
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


class RepairCandidateArtifact(StrictModel):
    schema_version: Literal["gauntlet.repair-candidate.v1"]
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
    rationale: str
    patch: str
    regression_test: str
    optional_policy_artifact: str | None = None
    candidate_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_field_digests: dict[str, str]
    integrity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("candidate_id", "run_id")
    @classmethod
    def valid_uuid(cls, value: str) -> str:
        UUID(value)
        return value

    def candidate(self) -> GeneratedRepairCandidate:
        return GeneratedRepairCandidate(
            rationale=self.rationale,
            patch=self.patch,
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
        if self.integrity_digest != _artifact_digest(self):
            raise ValueError("Repair candidate integrity failed: integrity_digest")
        return self


def _artifact_payload(artifact: RepairCandidateArtifact) -> str:
    return json.dumps(
        artifact.model_dump(mode="json", exclude={"integrity_digest"}),
        ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    )


def _artifact_digest(artifact: RepairCandidateArtifact) -> str:
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
        **candidate.model_dump(),
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


def load_candidate_artifact(path: Path) -> RepairCandidateArtifact:
    return RepairCandidateArtifact.model_validate_json(path.read_text())


def candidate_artifact_location(
    run_evidence_path: Path, attempt_number: int, candidate_id: str,
) -> tuple[Path, str]:
    directory = run_evidence_path.parent / f"{run_evidence_path.stem}.candidates"
    path = directory / f"attempt-{attempt_number:02d}-{candidate_id}.json"
    return path, path.relative_to(run_evidence_path.parent).as_posix()
