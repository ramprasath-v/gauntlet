"""One-call P300 adversarial generation with failure-retaining evidence."""

import json
import re
import time
from pathlib import Path
from typing import Callable
from uuid import uuid4

from pydantic import ValidationError

from gauntlet.adversarial.evidence import (
    AdversarialGenerationEvidence,
    ProviderRunEvidence,
    ScenarioCompatibilityEvidence,
    ScenarioResultEvidence,
    build_adversarial_evidence,
    content_digest,
    persist_adversarial_evidence,
)
from gauntlet.adversarial.generator import (
    AdversarialScenarioGenerator,
    AdversarialScenarioProvider,
)
from gauntlet.adversarial.models import AdversarialGenerationRequest
from gauntlet.adversarial.p300 import (
    execute_p300_scenario,
    validate_p300_scenario_compatibility,
)
from gauntlet.contracts.models import ContractStatus, SecurityContract
from gauntlet.sandbox.workspace import repository_digest
from victims.refund_support.agent import RefundSupportAgent


def _schema_error(error: Exception) -> str:
    if isinstance(error, ValidationError):
        return json.dumps(error.errors(include_input=False), sort_keys=True)[:4_000]
    return f"{type(error).__name__}: {error}"[:4_000]


def _structured_output(raw: str):
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _provider_run(provider, raw: str, latency: float) -> ProviderRunEvidence:
    client = getattr(provider, "client", None)
    metadata = getattr(client, "last_response_metadata", None)
    return ProviderRunEvidence(
        http_status=getattr(metadata, "http_status", None),
        finish_reason=getattr(metadata, "finish_reason", None),
        prompt_tokens=getattr(metadata, "prompt_tokens", None),
        completion_tokens=getattr(metadata, "completion_tokens", None),
        total_tokens=getattr(metadata, "total_tokens", None),
        latency_seconds=latency,
        content_length=len(raw),
        content_digest=content_digest(raw),
        structured_output=_structured_output(raw),
    )


def _credential_free(serialized: str, credential_values: tuple[str, ...]) -> bool:
    if any(secret and secret in serialized for secret in credential_values):
        return False
    return re.search(
        r"(?i)(authorization\s*[:=]|bearer\s+[A-Za-z0-9._~+/=-]+|"
        r"api[_-]?key\s*[:=]|access[_-]?token\s*[:=])",
        serialized,
    ) is None


async def run_p300_adversarial_generation(
    *,
    provider: AdversarialScenarioProvider,
    request: AdversarialGenerationRequest,
    contract: SecurityContract,
    repository_root: Path,
    evidence_path: Path,
    credential_values: tuple[str, ...] = (),
    agent_factory: Callable[[], RefundSupportAgent] = RefundSupportAgent,
) -> AdversarialGenerationEvidence:
    """Call once, grade each compatible scenario, and always retain output."""
    before = repository_digest(repository_root)
    run_id = str(uuid4())
    started = time.perf_counter()
    raw = await provider.generate_scenarios(request)
    latency = time.perf_counter() - started
    provider_run = _provider_run(provider, raw, latency)
    generator = AdversarialScenarioGenerator(provider)

    try:
        scenarios = generator.parse(request, raw, run_id=run_id)
    except (ValidationError, ValueError) as error:
        after = repository_digest(repository_root)
        evidence = build_adversarial_evidence(
            contract=contract,
            run_id=run_id,
            platform=provider.platform_name,
            provider=provider.provider_name,
            model=provider.model_name,
            provider_run=provider_run,
            scenarios=[],
            schema_validation="FAIL",
            schema_error=_schema_error(error),
            failure_stage="generic_schema_validation",
            failure_reason="provider output did not satisfy the scenario schema",
            final_status="SCHEMA_REJECTED",
            provider_request_count=1,
            repository_digest_before=before,
            repository_digest_after=after,
            credential_scan="PASS",
        )
        serialized = evidence.model_dump_json()
        if not _credential_free(serialized, credential_values):
            raise ValueError("credential scan failed; adversarial evidence not persisted")
        persist_adversarial_evidence(evidence, evidence_path)
        return evidence

    records: list[ScenarioResultEvidence] = []
    for scenario in scenarios:
        compatibility = validate_p300_scenario_compatibility(scenario, contract)
        compatibility_evidence = ScenarioCompatibilityEvidence(
            **compatibility.model_dump(exclude={"scenario_id", "contract_id"})
        )
        if compatibility.status == "FAIL":
            records.append(ScenarioResultEvidence(
                scenario=scenario,
                scenario_text_digest=content_digest(scenario.input),
                compatibility=compatibility_evidence,
                execution_status="NOT_REACHED",
                execution_error=compatibility.reason,
            ))
            continue
        records.append(ScenarioResultEvidence(
            scenario=scenario,
            scenario_text_digest=content_digest(scenario.input),
            compatibility=compatibility_evidence,
            execution_status="NOT_REACHED",
        ))

    checkpoint_after = repository_digest(repository_root)
    checkpoint = build_adversarial_evidence(
        contract=contract,
        run_id=run_id,
        platform=provider.platform_name,
        provider=provider.provider_name,
        model=provider.model_name,
        provider_run=provider_run,
        scenarios=records,
        schema_validation="PASS",
        schema_error=None,
        failure_stage=(
            "adapter_compatibility"
            if any(record.compatibility.status == "FAIL" for record in records)
            else None
        ),
        failure_reason=(
            "one or more generated scenarios are not adapter-compatible"
            if any(record.compatibility.status == "FAIL" for record in records)
            else None
        ),
        final_status="VALIDATED_PENDING_EXECUTION",
        provider_request_count=1,
        repository_digest_before=before,
        repository_digest_after=checkpoint_after,
        credential_scan="PASS",
    )
    if not _credential_free(checkpoint.model_dump_json(), credential_values):
        raise ValueError("credential scan failed; adversarial evidence not persisted")
    persist_adversarial_evidence(checkpoint, evidence_path)

    final_records: list[ScenarioResultEvidence] = []
    for record in records:
        if record.compatibility.status == "FAIL":
            final_records.append(record)
            continue
        scenario = record.scenario
        try:
            result = execute_p300_scenario(
                scenario, contract, agent=agent_factory()
            )
        except Exception as error:  # deterministic failure is retained, not repaired
            final_records.append(ScenarioResultEvidence(
                scenario=scenario,
                scenario_text_digest=content_digest(scenario.input),
                compatibility=record.compatibility,
                execution_status="FAILED",
                execution_error=f"{type(error).__name__}: {error}"[:4_000],
            ))
            continue
        final_records.append(ScenarioResultEvidence(
            scenario=scenario,
            scenario_text_digest=content_digest(scenario.input),
            compatibility=record.compatibility,
            execution_status="EXECUTED",
            trace_id=result.trace.trace_id,
            contract_status=result.evaluation.status,
            violation_evidence_ids=[
                item.evidence_id for item in result.evaluation.evidence
            ],
        ))

    records = final_records
    executed = [record for record in records if record.execution_status == "EXECUTED"]
    if not executed:
        final_status = "GENERATED_NOT_EXECUTABLE"
    elif len(executed) != len(records):
        final_status = "PARTIALLY_EXECUTED"
    elif any(record.contract_status == ContractStatus.VIOLATED for record in executed):
        final_status = "EXECUTED_VIOLATION_FOUND"
    else:
        final_status = "EXECUTED_NO_VIOLATION"
    failures = [record for record in records if record.execution_status != "EXECUTED"]
    failure_stage = None
    failure_reason = None
    if failures:
        failure_stage = (
            "adapter_compatibility" if any(
                record.compatibility.status == "FAIL" for record in failures
            ) else "deterministic_execution"
        )
        failure_reason = f"{len(failures)} of {len(records)} scenarios did not execute"

    after = repository_digest(repository_root)
    evidence = build_adversarial_evidence(
        contract=contract,
        run_id=run_id,
        platform=provider.platform_name,
        provider=provider.provider_name,
        model=provider.model_name,
        provider_run=provider_run,
        scenarios=records,
        schema_validation="PASS",
        schema_error=None,
        failure_stage=failure_stage,
        failure_reason=failure_reason,
        final_status=final_status,
        provider_request_count=1,
        repository_digest_before=before,
        repository_digest_after=after,
        credential_scan="PASS",
    )
    serialized = evidence.model_dump_json()
    if not _credential_free(serialized, credential_values):
        raise ValueError("credential scan failed; adversarial evidence not persisted")
    persist_adversarial_evidence(evidence, evidence_path)
    return evidence
