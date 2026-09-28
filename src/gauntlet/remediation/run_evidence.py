"""Versioned, integrity-checked persistence for M4.2 run evidence."""
import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import TypeAdapter, model_validator

from gauntlet.remediation.models import StrictModel
from gauntlet.remediation.candidate_artifact import load_candidate_artifact
from gauntlet.remediation.retry_models import RepairRunResult


RUN_EVIDENCE_SCHEMA_VERSION = "gauntlet.repair-run.v1"
_RUN_ADAPTER = TypeAdapter(RepairRunResult)


def _payload(result: RepairRunResult) -> str:
    return json.dumps(
        result.model_dump(mode="json"), ensure_ascii=True, sort_keys=True,
        separators=(",", ":"),
    )


def _legacy_payload(result: RepairRunResult) -> str:
    payload = result.model_dump(mode="json")
    for attempt in payload["attempts"]:
        attempt.pop("candidate_artifact", None)
    return json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    )


class RepairRunEnvelope(StrictModel):
    schema_version: Literal["gauntlet.repair-run.v1"]
    result: RepairRunResult
    result_digest: str

    @model_validator(mode="after")
    def valid_integrity(self) -> "RepairRunEnvelope":
        expected = hashlib.sha256(_payload(self.result).encode()).hexdigest()
        legacy_expected = hashlib.sha256(_legacy_payload(self.result).encode()).hexdigest()
        if self.result_digest not in {expected, legacy_expected}:
            raise ValueError("Repair run evidence integrity failed: result_digest")
        return self


def persist_repair_run(
    result: RepairRunResult, path: Path
) -> RepairRunEnvelope:
    envelope = RepairRunEnvelope(
        schema_version=RUN_EVIDENCE_SCHEMA_VERSION,
        result=result,
        result_digest=hashlib.sha256(_payload(result).encode()).hexdigest(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(envelope.model_dump_json(indent=2) + "\n")
    return envelope


def load_repair_run(path: Path) -> RepairRunResult:
    envelope = RepairRunEnvelope.model_validate_json(path.read_text())
    result = _RUN_ADAPTER.validate_python(envelope.result)
    root = path.parent.resolve()
    for attempt in result.attempts:
        reference = attempt.candidate_artifact
        if reference is None:
            continue
        artifact_path = (root / reference.path).resolve()
        if not artifact_path.is_relative_to(root):
            raise ValueError("Candidate artifact reference escapes run evidence root")
        artifact = load_candidate_artifact(artifact_path)
        if (
            artifact.schema_version != reference.schema_version
            or artifact.candidate_id != reference.candidate_id
            or artifact.attempt_number != reference.attempt_number
            or artifact.candidate_digest != reference.candidate_digest
            or artifact.integrity_digest != reference.integrity_digest
            or artifact.run_id != result.run_id
            or artifact.trace_id != result.trace_id
            or artifact.boundary_id != result.boundary_id
        ):
            raise ValueError("Repair run candidate artifact linkage failed")
    return result
