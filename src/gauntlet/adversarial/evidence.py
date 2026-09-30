"""Integrity-bound evidence for adversarial generation and deterministic grading."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, JsonValue, model_validator

from gauntlet.adversarial.models import AdversarialScenario
from gauntlet.contracts.models import ContractStatus, SecurityContract, StrictModel


ADVERSARIAL_EVIDENCE_VERSION = "gauntlet.adversarial-generation.v2"


class ProviderRunEvidence(StrictModel):
    http_status: int | None = None
    finish_reason: str | None = None
    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    latency_seconds: float | None = Field(default=None, ge=0)
    content_length: int = Field(ge=0)
    content_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    structured_output: JsonValue | None = None


class ScenarioCompatibilityEvidence(StrictModel):
    status: Literal["PASS", "FAIL"]
    failure_stage: Literal["adapter_compatibility"]
    missing_parameters: list[str]
    unsupported_parameters: list[str]
    invalid_parameters: dict[str, str]
    expected_shape: dict[str, str]
    observed_shape: dict[str, str]
    reason: str | None = None


class ScenarioResultEvidence(StrictModel):
    scenario: AdversarialScenario
    scenario_text_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    schema_validation: Literal["PASS"] = "PASS"
    compatibility: ScenarioCompatibilityEvidence
    execution_status: Literal["NOT_REACHED", "EXECUTED", "FAILED"]
    trace_id: str | None = None
    contract_status: ContractStatus | None = None
    violation_evidence_ids: list[str] = Field(default_factory=list)
    execution_error: str | None = None

    @model_validator(mode="after")
    def coherent_result(self) -> "ScenarioResultEvidence":
        if self.compatibility.status == "FAIL" and self.execution_status != "NOT_REACHED":
            raise ValueError("incompatible scenarios cannot reach execution")
        if self.execution_status == "EXECUTED":
            if self.trace_id is None or self.contract_status is None:
                raise ValueError("executed scenarios require trace and contract status")
            if self.execution_error is not None:
                raise ValueError("executed scenarios cannot contain an execution error")
        elif self.contract_status is not None or self.trace_id is not None:
            raise ValueError("unexecuted scenarios cannot claim deterministic results")
        return self


class AdversarialGenerationEvidence(StrictModel):
    schema_version: Literal["gauntlet.adversarial-generation.v2"]
    run_id: str
    created_at: datetime
    platform: str
    provider: str
    model: str
    provider_request_count: int = Field(ge=0, le=1)
    provider_run: ProviderRunEvidence
    contract: SecurityContract
    schema_validation: Literal["PASS", "FAIL"]
    schema_error: str | None = None
    scenarios: list[ScenarioResultEvidence] = Field(default_factory=list, max_length=5)
    failure_stage: str | None = None
    failure_reason: str | None = None
    final_status: Literal[
        "SCHEMA_REJECTED",
        "VALIDATED_PENDING_EXECUTION",
        "GENERATED_NOT_EXECUTABLE",
        "PARTIALLY_EXECUTED",
        "EXECUTED_NO_VIOLATION",
        "EXECUTED_VIOLATION_FOUND",
    ]
    repository_digest_before: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository_digest_after: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository_immutability: Literal["PASS", "FAIL"]
    credential_scan: Literal["PASS", "FAIL"]
    integrity_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def valid_integrity(self) -> "AdversarialGenerationEvidence":
        if self.schema_validation == "FAIL" and self.scenarios:
            raise ValueError("schema-rejected evidence cannot contain trusted scenarios")
        if self.schema_validation == "PASS" and not self.scenarios:
            raise ValueError("schema-valid evidence requires scenarios")
        for result in self.scenarios:
            if result.scenario.run_id != self.run_id:
                raise ValueError("scenario run identity does not match evidence")
            if result.scenario.contract_id != self.contract.contract_id:
                raise ValueError("scenario contract identity does not match evidence")
            if (
                result.scenario.platform != self.platform
                or result.scenario.provider != self.provider
                or result.scenario.model != self.model
            ):
                raise ValueError("scenario provider provenance does not match evidence")
            if result.scenario_text_digest != _digest(result.scenario.input):
                raise ValueError("scenario text digest does not match evidence")
        unchanged = self.repository_digest_before == self.repository_digest_after
        if (self.repository_immutability == "PASS") != unchanged:
            raise ValueError("repository immutability does not match evidence digests")
        if self.integrity_digest != _integrity_digest(self):
            raise ValueError("adversarial generation evidence integrity failed")
        return self


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def content_digest(value: str) -> str:
    return _digest(value)


def _integrity_digest(evidence: AdversarialGenerationEvidence) -> str:
    payload = evidence.model_dump(mode="json", exclude={"integrity_digest"})
    return _digest(json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ))


def build_adversarial_evidence(
    *,
    contract: SecurityContract,
    run_id: str,
    platform: str,
    provider: str,
    model: str,
    provider_run: ProviderRunEvidence,
    scenarios: list[ScenarioResultEvidence],
    schema_validation: Literal["PASS", "FAIL"],
    schema_error: str | None,
    failure_stage: str | None,
    failure_reason: str | None,
    final_status: str,
    provider_request_count: int,
    repository_digest_before: str,
    repository_digest_after: str,
    credential_scan: Literal["PASS", "FAIL"],
) -> AdversarialGenerationEvidence:
    values: dict[str, Any] = dict(
        schema_version=ADVERSARIAL_EVIDENCE_VERSION,
        run_id=run_id,
        created_at=datetime.now(timezone.utc),
        platform=platform,
        provider=provider,
        model=model,
        provider_request_count=provider_request_count,
        provider_run=provider_run,
        contract=contract,
        schema_validation=schema_validation,
        schema_error=schema_error,
        scenarios=scenarios,
        failure_stage=failure_stage,
        failure_reason=failure_reason,
        final_status=final_status,
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
