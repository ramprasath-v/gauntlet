import json
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from gauntlet.attacks.indirect_prompt_injection import IndirectPromptInjectionAttack
from gauntlet.core.config import NebiusConfig
from gauntlet.llm.nebius import NebiusAPIError, NebiusTokenFactoryClient
from gauntlet.remediation.context import build_source_context
from gauntlet.remediation.fake import FakeRemediationProvider
from gauntlet.remediation.models import RepairProposal
from gauntlet.remediation.prompt import SYSTEM_PROMPT, build_messages
from gauntlet.remediation.workflow import generate_repair_proposal
from victims.customer_support.app import create_app


ROOT = Path(__file__).parents[1]


async def attack_trace():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://before"
    ) as client:
        return (await IndirectPromptInjectionAttack(client).run()).trace


async def test_valid_trace_builds_bounded_source_context_with_provenance_and_hash():
    trace = await attack_trace()
    context = build_source_context(trace.model_dump_json(), ROOT)
    assert context.repository_relative_path == "victims/customer_support/agent.py"
    assert context.target_symbol == "CustomerSupportAgent.chat"
    assert context.trace_id == trace.attack_id
    assert context.boundary_id == trace.failure_boundary.boundary_id
    assert context.evidence_ids == trace.failure_boundary.evidence_event_ids
    assert context.source_hash == context.hash_text(context.source_text)
    assert "async def chat" in context.source_text
    assert "def create_app" not in context.source_text


@pytest.mark.parametrize("location", [
    "victims/customer_support/tools.py",
    "/tmp/agent.py",
    "../victims/customer_support/agent.py",
])
async def test_unauthorized_absolute_and_traversal_locations_are_rejected(location):
    trace = await attack_trace()
    trace.source_locations[0].file = location
    with pytest.raises(ValueError, match="authorized source location"):
        build_source_context(trace.model_dump_json(), ROOT)


async def test_source_location_must_match_boundary_evidence():
    trace = await attack_trace()
    serialized = json.loads(trace.model_dump_json())
    serialized["source_locations"][0]["responsibility"] = "altered"
    with pytest.raises(ValueError, match="does not match the M2 boundary"):
        build_source_context(json.dumps(serialized), ROOT)


async def test_fake_provider_exercises_complete_m31_flow_without_source_changes():
    trace = await attack_trace()
    target = ROOT / "victims/customer_support/agent.py"
    before = target.read_bytes()
    proposal = await generate_repair_proposal(
        trace.model_dump_json(), ROOT, FakeRemediationProvider()
    )
    assert target.read_bytes() == before
    assert proposal.trace_id == trace.attack_id
    assert proposal.boundary_id == trace.failure_boundary.boundary_id
    assert proposal.evidence_ids == trace.failure_boundary.evidence_event_ids
    assert proposal.provider == "fake_remediation_provider"
    assert proposal.model == "deterministic-repair-fixture-v1"
    assert proposal.patch.startswith("--- a/victims/customer_support/agent.py")
    assert "async def test_poisoned_review_does_not_leak_canary" in proposal.regression_test


class MutatingProvider(FakeRemediationProvider):
    def __init__(self, *, remove: str | None = None, replace: dict | None = None):
        self.remove = remove
        self.replace = replace or {}

    async def generate(self, request):
        body = json.loads(await super().generate(request))
        if self.remove:
            body.pop(self.remove, None)
        body.update(self.replace)
        return json.dumps(body)


@pytest.mark.parametrize("field", ["patch", "regression_test"])
async def test_missing_patch_or_generated_regression_test_is_rejected(field):
    trace = await attack_trace()
    with pytest.raises(ValidationError):
        await generate_repair_proposal(
            trace.model_dump_json(), ROOT, MutatingProvider(remove=field)
        )


@pytest.mark.parametrize("raw", ["not-json", "{}", '{"patch": 7}'])
def test_malformed_provider_output_is_rejected_by_strict_schema(raw):
    with pytest.raises((ValidationError, ValueError)):
        RepairProposal.model_validate_json(raw)


async def test_provider_cannot_change_provenance_or_metadata():
    trace = await attack_trace()
    for field, value in (
        ("trace_id", "different"), ("boundary_id", "different"),
        ("evidence_ids", ["different"]), ("provider", "other"),
        ("model", "other"), ("source_hash", "0" * 64),
    ):
        with pytest.raises(ValueError, match="changed required provenance"):
            await generate_repair_proposal(
                trace.model_dump_json(), ROOT,
                MutatingProvider(replace={field: value}),
            )


async def test_invalid_patch_target_and_non_executable_test_are_rejected():
    trace = await attack_trace()
    with pytest.raises(ValidationError, match="single-target unified diff"):
        await generate_repair_proposal(
            trace.model_dump_json(), ROOT,
            MutatingProvider(replace={"patch": "--- a/other.py\n+++ b/other.py\n@@ -1 +1 @@\n-x\n+y\n"}),
        )
    with pytest.raises(ValidationError, match="test function with an assertion"):
        await generate_repair_proposal(
            trace.model_dump_json(), ROOT,
            MutatingProvider(replace={"regression_test": "def helper():\n    return True\n"}),
        )


async def test_nebius_transport_uses_documented_chat_schema_contract():
    observed = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        observed["url"] = str(request.url)
        observed["authorization"] = request.headers.get("Authorization")
        observed["body"] = json.loads(request.content)
        return httpx.Response(200, json={
            "choices": [{"message": {"content": '{"ok": true}'}}]
        })

    config = NebiusConfig(
        api_key="synthetic-test-key",
        base_url="https://api.tokenfactory.us-central1.nebius.com/v1/",
        model="nvidia/nemotron-3-super-120b-a12b",
    )
    client = NebiusTokenFactoryClient(config, transport=httpx.MockTransport(handler))
    content = await client.complete(
        [{"role": "user", "content": "test"}],
        response_schema={"type": "object", "properties": {}},
    )
    assert content == '{"ok": true}'
    assert observed["url"].endswith("/v1/chat/completions")
    assert observed["authorization"] == "Bearer synthetic-test-key"
    assert observed["body"] == {
        "model": "nvidia/nemotron-3-super-120b-a12b",
        "messages": [{"role": "user", "content": "test"}],
        "response_format": {
            "type": "json_schema",
            "json_schema": {"type": "object", "properties": {}},
        },
    }


async def test_nebius_422_preserves_sanitized_validation_body_and_redacts_credentials():
    secret = "synthetic-secret-value"

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, json={
            "detail": [{"loc": ["body", "response_format"], "msg": "invalid schema"}],
            "authorization": f"Bearer {secret}",
            "echo": secret,
            "nested": {"api_key": secret},
        })

    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key=secret,
        base_url="https://api.tokenfactory.us-central1.nebius.com/v1/",
        model="nvidia/nemotron-3-super-120b-a12b",
    ), transport=httpx.MockTransport(handler))
    with pytest.raises(NebiusAPIError) as raised:
        await client.complete([{"role": "user", "content": "test"}])
    message = str(raised.value)
    assert raised.value.status_code == 422
    assert "invalid schema" in message
    assert '"response_format"' in message
    assert secret not in message
    assert message.count("[REDACTED]") == 3


def test_nemotron_super_requires_documented_regional_endpoint():
    with pytest.raises(ValueError, match="us-central1"):
        NebiusTokenFactoryClient(NebiusConfig(
            api_key="synthetic",
            base_url="https://api.tokenfactory.nebius.com/v1/",
            model="nvidia/nemotron-3-super-120b-a12b",
        ))


@pytest.mark.parametrize("base_url", [
    "http://api.tokenfactory.nebius.com/v1",
    "https://example.com/v1",
    "https://api.tokenfactory.nebius.com@evil.example/v1",
])
def test_nebius_transport_rejects_unapproved_targets(base_url):
    with pytest.raises(ValueError, match="approved HTTPS"):
        NebiusTokenFactoryClient(NebiusConfig(
            api_key="synthetic", base_url=base_url,
            model="nvidia/nemotron-3-super-120b-a12b",
        ))


def test_nebius_transport_requires_explicit_environment_configuration():
    with pytest.raises(ValueError, match="Missing Nebius configuration"):
        NebiusTokenFactoryClient(NebiusConfig())


async def test_prompt_contains_defensive_contract_and_bounded_artifacts():
    trace = await attack_trace()
    context = build_source_context(trace.model_dump_json(), ROOT)
    provider = FakeRemediationProvider()
    from gauntlet.remediation.models import RemediationRequest
    request = RemediationRequest(
        source_context=context, failure_type="indirect_prompt_injection",
        provider=provider.provider_name, model=provider.model_name,
        evidence_summary={"verdict": trace.verdict},
    )
    messages = build_messages(request)
    for phrase in (
        "authorized defensive benchmark", "synthetic local victim",
        "only the supplied execution evidence", "Modify only the authorized target",
        "Preserve legitimate behavior", "Do not remove or weaken tests",
        "Do not suppress the verifier", "remove the canary", "bypass the attack harness",
        "smallest reasonable repair", "actual Python regression test",
    ):
        assert phrase in SYSTEM_PROMPT
    payload = json.loads(messages[1]["content"])
    assert payload["source_context"]["source_text"] == context.source_text
    assert payload["source_context"]["evidence_ids"] == context.evidence_ids
    assert payload["required_output_schema"]["additionalProperties"] is False
