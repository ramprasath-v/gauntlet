"""Versioned, integrity-checked persistence for the exact M3 to M4 handoff."""
import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import model_validator

from gauntlet.remediation.models import RepairProposal, StrictModel


HANDOFF_SCHEMA_VERSION = "gauntlet.repair-proposal.v1"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _proposal_payload(proposal: RepairProposal) -> str:
    return json.dumps(
        proposal.model_dump(mode="json"),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )


class RepairProposalEnvelope(StrictModel):
    schema_version: Literal["gauntlet.repair-proposal.v1"]
    proposal: RepairProposal
    proposal_digest: str
    patch_digest: str
    regression_test_digest: str

    @model_validator(mode="after")
    def valid_integrity(self) -> "RepairProposalEnvelope":
        expected = {
            "proposal_digest": _digest(_proposal_payload(self.proposal)),
            "patch_digest": _digest(self.proposal.patch),
            "regression_test_digest": _digest(self.proposal.regression_test),
        }
        for field, value in expected.items():
            if getattr(self, field) != value:
                raise ValueError(f"RepairProposal handoff integrity failed: {field}")
        return self


def persist_repair_proposal(proposal: RepairProposal, path: Path) -> RepairProposalEnvelope:
    envelope = RepairProposalEnvelope(
        schema_version=HANDOFF_SCHEMA_VERSION,
        proposal=proposal,
        proposal_digest=_digest(_proposal_payload(proposal)),
        patch_digest=_digest(proposal.patch),
        regression_test_digest=_digest(proposal.regression_test),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(envelope.model_dump_json(indent=2) + "\n")
    return envelope


def load_repair_proposal(path: Path) -> RepairProposal:
    return RepairProposalEnvelope.model_validate_json(path.read_text()).proposal
