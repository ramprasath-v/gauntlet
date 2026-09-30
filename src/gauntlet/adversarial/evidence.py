"""Integrity-bound format for an eventual live adversarial generation run."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from gauntlet.adversarial.models import AdversarialScenario
from gauntlet.contracts.models import ContractStatus, SecurityContract, StrictModel


ADVERSARIAL_EVIDENCE_VERSION = "gauntlet.adversarial-generation.v1"


class ScenarioResultEvidence(StrictModel):
    scenario: AdversarialScenario
    scenario_text_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    trace_id: str
    contract_status: ContractStatus
    violation_evidence_ids: list[str]


class AdversarialGenerationEvidence(StrictModel):
    schema_version: Literal["gauntlet.adversarial-generation.v1"]
    run_id: str
    created_at: datetime
    platform: str
    provider: str
    model: str
    provider_request_count: int = Field(ge=0, le=1)
    contract: SecurityContract
    results: list[ScenarioResultEvidence] = Field(min_length=1, max_length=5)
    repository_digest_before: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository_digest_after: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository_immutability: Literal["PASS", "FAIL"]
    credential_scan: Literal["PASS", "FAIL"]
    integrity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def valid_integrity(self) -> "AdversarialGenerationEvidence":
        if any(result.scenario.run_id != self.run_id for result in self.results):
            raise ValueError("scenario run identity does not match evidence")
        if any(
            result.scenario.contract_id != self.contract.contract_id
            for result in self.results
        ):
            raise ValueError("scenario contract identity does not match evidence")
        if any(
            result.scenario.platform != self.platform
            or result.scenario.provider != self.provider
            or result.scenario.model != self.model
            for result in self.results
        ):
            raise ValueError("scenario provider provenance does not match evidence")
        if any(
            result.scenario_text_digest != _digest(result.scenario.input)
            for result in self.results
        ):
            raise ValueError("scenario text digest does not match evidence")
        unchanged = self.repository_digest_before == self.repository_digest_after
        if (self.repository_immutability == "PASS") != unchanged:
            raise ValueError("repository immutability does not match evidence digests")
        expected = _integrity_digest(self)
        if self.integrity_digest != expected:
            raise ValueError("adversarial generation evidence integrity failed")
        return self


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _integrity_digest(evidence: AdversarialGenerationEvidence) -> str:
    payload = evidence.model_dump(mode="json", exclude={"integrity_digest"})
    return _digest(json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ))


def build_adversarial_evidence(
    *,
    contract: SecurityContract,
    results: list,
    provider_request_count: int,
    repository_digest_before: str,
    repository_digest_after: str,
    credential_scan: Literal["PASS", "FAIL"],
) -> AdversarialGenerationEvidence:
    if not results:
        raise ValueError("adversarial evidence requires scenario results")
    scenario_results = [
        ScenarioResultEvidence(
            scenario=result.scenario,
            scenario_text_digest=_digest(result.scenario.input),
            trace_id=result.trace.trace_id,
            contract_status=result.evaluation.status,
            violation_evidence_ids=[
                evidence.evidence_id
                for evidence in result.evaluation.evidence
            ],
        )
        for result in results
    ]
    first = scenario_results[0].scenario
    values = dict(
        schema_version=ADVERSARIAL_EVIDENCE_VERSION,
        run_id=first.run_id,
        created_at=datetime.now(timezone.utc),
        platform=first.platform,
        provider=first.provider,
        model=first.model,
        provider_request_count=provider_request_count,
        contract=contract,
        results=scenario_results,
        repository_digest_before=repository_digest_before,
        repository_digest_after=repository_digest_after,
        repository_immutability=(
            "PASS" if repository_digest_before == repository_digest_after else "FAIL"
        ),
        credential_scan=credential_scan,
    )
    provisional = AdversarialGenerationEvidence.model_construct(
        **values, integrity_digest="0" * 64
    )
    return AdversarialGenerationEvidence(
        **values, integrity_digest=_integrity_digest(provisional)
    )


def persist_adversarial_evidence(
    evidence: AdversarialGenerationEvidence, path: Path,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(evidence.model_dump_json(indent=2) + "\n")
