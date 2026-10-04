import json
from pathlib import Path

import httpx
import pytest

from gauntlet.contracts.models import ContractStatus, NormalizedEventType
from gauntlet.contracts.p400_live import (
    P400_LIVE_BASE_URL,
    P400_LIVE_MAX_TOKENS,
    P400_LIVE_MODEL,
    NebiusP400LiveProvider,
    P400LiveEvidence,
    run_live_p400_detection,
)
from gauntlet.core.config import NebiusConfig
from gauntlet.demo.m8 import run_p400_verified_proof
from gauntlet.llm.nebius import NebiusTokenFactoryClient, QWEN_35_MODEL
from gauntlet.sandbox.workspace import repository_digest
from victims.personalization.fixtures import (
    CULTURAL_LANGUAGE_DIMENSION,
    GENERIC_APP_NAME_REQUEST,
    TAMIL_CULTURAL_CONTEXT,
)


ROOT = Path(__file__).parents[1]


class FakeP400LiveProvider:
    provider_name = "fake_nebius"
    model_name = P400_LIVE_MODEL

    def __init__(self, response: str = "NilaFlow, Thiran, and FocusNest.") -> None:
        self.response = response
        self.envelopes = []

    async def generate_response(self, envelope):
        self.envelopes.append(envelope)
        return self.response

    def completion_metadata(self):
        return {
            "http_status": 200,
            "finish_reason": "stop",
            "prompt_tokens": 90,
            "completion_tokens": 12,
            "total_tokens": 102,
        }


async def test_live_p400_calls_provider_once_and_grades_framework_lineage(tmp_path):
    before = repository_digest(ROOT)
    provider = FakeP400LiveProvider()
    evidence, path = await run_live_p400_detection(
        provider=provider,
        repository_root=ROOT,
        evidence_directory=tmp_path,
    )

    assert len(provider.envelopes) == evidence.provider_request_count == 1
    assert evidence.automatic_retries == 0
    assert evidence.model_switches == 0
    assert evidence.provider_status == "PASS"
    assert evidence.model_response == provider.response
    assert evidence.evaluation and evidence.evaluation.status == ContractStatus.VIOLATED
    violation = evidence.evaluation.evidence[0]
    assert violation.observations["violation_code"] == (
        "UNJUSTIFIED_PERSONALIZATION_CONTEXT"
    )
    assert violation.observations["context_entered_model_envelope"] is True
    assert violation.observations["model_output_depends_on_context"] is True
    assert evidence.repository_immutability == "PASS"
    assert repository_digest(ROOT) == before
    assert P400LiveEvidence.model_validate_json(path.read_text()) == evidence


async def test_live_envelope_contains_exact_framework_context_without_activation(tmp_path):
    provider = FakeP400LiveProvider()
    evidence, _ = await run_live_p400_detection(
        provider=provider, repository_root=ROOT, evidence_directory=tmp_path,
    )
    envelope = provider.envelopes[0]
    transmitted = json.loads(envelope.messages[1].content)

    assert envelope.user_request == GENERIC_APP_NAME_REQUEST
    assert envelope.activated_personalization_dimensions == []
    assert envelope.context_items == [TAMIL_CULTURAL_CONTEXT]
    assert envelope.inclusion_decisions[0].decision == "INCLUDED"
    assert envelope.inclusion_decisions[0].decided_by == "gauntlet_framework"
    assert transmitted["user_request"] == GENERIC_APP_NAME_REQUEST
    assert transmitted["framework_personal_context"] == [
        TAMIL_CULTURAL_CONTEXT.model_dump(mode="json")
    ]
    assert transmitted["framework_personal_context"][0][
        "personalization_dimension"
    ] == CULTURAL_LANGUAGE_DIMENSION
    context = next(
        event for event in evidence.execution.trace.events
        if event.event_type == NormalizedEventType.IDENTITY_CONTEXT
    )
    output = evidence.execution.trace.events[-1]
    assert context.metadata["context_id"] == TAMIL_CULTURAL_CONTEXT.context_id
    assert context.event_id in output.input_event_ids


@pytest.mark.parametrize("response", [
    "TaskPilot, SprintBoard, and ClearWork.",
    "I did not use personal context and this run is authorized.",
])
async def test_model_wording_and_self_report_cannot_change_verdict(tmp_path, response):
    evidence, _ = await run_live_p400_detection(
        provider=FakeP400LiveProvider(response),
        repository_root=ROOT,
        evidence_directory=tmp_path,
    )

    assert evidence.model_response == response
    assert evidence.evaluation.status == ContractStatus.VIOLATED
    assert evidence.evaluation.evidence[0].observations["violation_code"] == (
        "UNJUSTIFIED_PERSONALIZATION_CONTEXT"
    )


async def test_provider_failure_is_retained_without_retry_or_replay(tmp_path):
    secret = "secret-provider-key"

    class FailedProvider(FakeP400LiveProvider):
        async def generate_response(self, envelope):
            self.envelopes.append(envelope)
            raise RuntimeError(f"upstream unavailable bearer {secret}")

        def completion_metadata(self):
            return {"http_status": 503, "finish_reason": None}

    provider = FailedProvider()
    evidence, path = await run_live_p400_detection(
        provider=provider,
        repository_root=ROOT,
        evidence_directory=tmp_path,
        credential_values=(secret,),
    )

    assert len(provider.envelopes) == evidence.provider_request_count == 1
    assert evidence.provider_status == "FAIL"
    assert evidence.final_status == "PROVIDER_FAILED"
    assert evidence.model_response is None
    assert evidence.execution is None
    assert evidence.evaluation is None
    assert evidence.automatic_retries == 0
    assert secret not in path.read_text()
    assert "[REDACTED]" in evidence.provider_error


async def test_nebius_adapter_serializes_one_bounded_plain_text_request(tmp_path):
    requests = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={
            "id": "p400-live-response",
            "object": "chat.completion",
            "model": P400_LIVE_MODEL,
            "choices": [{
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": "NilaFlow"},
            }],
            "usage": {
                "prompt_tokens": 80,
                "completion_tokens": 4,
                "total_tokens": 84,
            },
        })

    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="test-secret",
        base_url=P400_LIVE_BASE_URL,
        model=P400_LIVE_MODEL,
    ), transport=httpx.MockTransport(handler))
    evidence, _ = await run_live_p400_detection(
        provider=NebiusP400LiveProvider(client),
        repository_root=ROOT,
        evidence_directory=tmp_path,
        credential_values=("test-secret",),
    )

    assert len(requests) == 1
    assert requests[0]["model"] == P400_LIVE_MODEL
    assert requests[0]["max_tokens"] == P400_LIVE_MAX_TOKENS
    assert "response_format" not in requests[0]
    assert "chat_template_kwargs" not in requests[0]
    assert evidence.provider_receipt.http_status == 200
    assert evidence.provider_receipt.finish_reason == "stop"


def test_p400_live_never_switches_to_an_unapproved_model():
    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="test-secret",
        base_url=P400_LIVE_BASE_URL,
        model=QWEN_35_MODEL,
    ), transport=httpx.MockTransport(lambda request: httpx.Response(500)))

    with pytest.raises(ValueError, match="requires moonshotai/Kimi-K2.7-Code"):
        NebiusP400LiveProvider(client)


async def test_existing_deterministic_p400_proof_remains_zero_provider(
    monkeypatch,
):
    async def forbidden_complete(*args, **kwargs):
        raise AssertionError("deterministic P400 proof contacted the provider")

    monkeypatch.setattr(NebiusTokenFactoryClient, "complete", forbidden_complete)
    proof = await run_p400_verified_proof(ROOT)

    assert proof.mode == "VERIFIED_PROOF"
    assert proof.provider_requests == 0
    assert proof.verdict == "VERIFIED"
