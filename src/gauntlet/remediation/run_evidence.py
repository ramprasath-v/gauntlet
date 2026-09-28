"""Versioned, integrity-checked persistence for M4.2 run evidence."""
import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import TypeAdapter, model_validator

from gauntlet.remediation.models import StrictModel
from gauntlet.remediation.retry_models import RepairRunResult


RUN_EVIDENCE_SCHEMA_VERSION = "gauntlet.repair-run.v1"
_RUN_ADAPTER = TypeAdapter(RepairRunResult)


def _payload(result: RepairRunResult) -> str:
    return json.dumps(
        result.model_dump(mode="json"), ensure_ascii=True, sort_keys=True,
        separators=(",", ":"),
    )


class RepairRunEnvelope(StrictModel):
    schema_version: Literal["gauntlet.repair-run.v1"]
    result: RepairRunResult
    result_digest: str

    @model_validator(mode="after")
    def valid_integrity(self) -> "RepairRunEnvelope":
        expected = hashlib.sha256(_payload(self.result).encode()).hexdigest()
        if self.result_digest != expected:
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
    return _RUN_ADAPTER.validate_python(envelope.result)
