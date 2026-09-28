import ast
import json
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from gauntlet.attacks.indirect_prompt_injection import IndirectPromptInjectionAttack
from gauntlet.core.config import NebiusConfig
from gauntlet.llm.nebius import (
    NEMOTRON_LIGHTNING_MODEL,
    NEMOTRON_REASONING_DISABLED,
    NebiusAPIError, NebiusCompletionError, NebiusTokenFactoryClient,
)
from gauntlet.remediation.context import build_source_context
from gauntlet.remediation.fake import FakeRemediationProvider
from gauntlet.remediation.models import (
    RegressionTestSyntaxError, RemediationRequest, RepairProposal,
)
from gauntlet.remediation.parsing import RepairProposalJSONError, parse_repair_proposal
from gauntlet.remediation.prompt import SYSTEM_PROMPT, build_messages
from gauntlet.remediation.provider import NebiusNemotronRemediationProvider
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
    schema = RepairProposal.model_json_schema()

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
        [{"role": "system", "content": "existing repair contract"},
         {"role": "user", "content": "test"}],
        response_schema=schema,
        reasoning_directive=NEMOTRON_REASONING_DISABLED,
        max_tokens=4_096,
    )
    assert content == '{"ok": true}'
    assert observed["url"].endswith("/v1/chat/completions")
    assert observed["authorization"] == "Bearer synthetic-test-key"
    assert observed["body"] == {
        "model": "nvidia/nemotron-3-super-120b-a12b",
        "messages": [
            {"role": "system", "content": "/no_think\nexisting repair contract"},
            {"role": "user", "content": "test"},
        ],
        "max_tokens": 4_096,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "repair_proposal",
                "schema": schema,
            },
        },
    }


async def test_remediation_provider_serializes_no_think_and_bounded_output_without_schema_change():
    observed = {}
    schema = RepairProposal.model_json_schema()

    async def handler(request: httpx.Request) -> httpx.Response:
        observed.update(json.loads(request.content))
        return httpx.Response(200, json={
            "choices": [{"message": {"content": '{"ok": true}'}}]
        })

    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="synthetic",
        base_url="https://api.tokenfactory.us-central1.nebius.com/v1/",
        model="nvidia/nemotron-3-super-120b-a12b",
    ), transport=httpx.MockTransport(handler))
    provider = NebiusNemotronRemediationProvider(client)
    trace = await attack_trace()
    context = build_source_context(trace.model_dump_json(), ROOT)
    request = RemediationRequest(
        source_context=context,
        failure_type="indirect_prompt_injection",
        provider=provider.provider_name,
        model=provider.model_name,
        evidence_summary={"verdict": trace.verdict},
    )

    await provider.generate(request)

    assert observed["messages"][0] == {
        "role": "system", "content": "/no_think\n" + SYSTEM_PROMPT,
    }
    assert observed["max_tokens"] == 4_096
    assert observed["response_format"] == {
        "type": "json_schema",
        "json_schema": {"name": "repair_proposal", "schema": schema},
    }


async def test_lightning_provider_disables_thinking_without_no_think_directive():
    observed = {}
    schema = RepairProposal.model_json_schema()

    async def handler(request: httpx.Request) -> httpx.Response:
        observed.update(json.loads(request.content))
        return httpx.Response(200, json={
            "choices": [{"message": {"content": '{"ok": true}'}}]
        })

    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="synthetic",
        base_url="https://api.tokenfactory.nebius.com/v1/",
        model=NEMOTRON_LIGHTNING_MODEL,
    ), transport=httpx.MockTransport(handler))
    provider = NebiusNemotronRemediationProvider(client)
    trace = await attack_trace()
    context = build_source_context(trace.model_dump_json(), ROOT)
    request = RemediationRequest(
        source_context=context,
        failure_type="indirect_prompt_injection",
        provider=provider.provider_name,
        model=provider.model_name,
        evidence_summary={"verdict": trace.verdict},
    )

    await provider.generate(request)

    assert observed["model"] == NEMOTRON_LIGHTNING_MODEL
    assert observed["messages"][0] == {"role": "system", "content": SYSTEM_PROMPT}
    assert not observed["messages"][0]["content"].startswith("/no_think")
    assert observed["chat_template_kwargs"] == {"enable_thinking": False}
    assert observed["max_tokens"] == 4_096
    assert observed["response_format"] == {
        "type": "json_schema",
        "json_schema": {"name": "repair_proposal", "schema": schema},
    }


async def test_non_nemotron_model_gets_no_model_specific_reasoning_control():
    observed = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        observed.update(json.loads(request.content))
        return httpx.Response(200, json={
            "choices": [{"message": {"content": '{"ok": true}'}}]
        })

    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="synthetic",
        base_url="https://api.tokenfactory.us-central1.nebius.com/v1/",
        model="Qwen/Qwen3.5-397B-A17B",
    ), transport=httpx.MockTransport(handler))
    provider = NebiusNemotronRemediationProvider(client)
    trace = await attack_trace()
    context = build_source_context(trace.model_dump_json(), ROOT)
    request = RemediationRequest(
        source_context=context,
        failure_type="indirect_prompt_injection",
        provider=provider.provider_name,
        model=provider.model_name,
        evidence_summary={"verdict": trace.verdict},
    )

    await provider.generate(request)

    assert observed["messages"][0]["content"] == SYSTEM_PROMPT
    assert "chat_template_kwargs" not in observed
    assert "reasoning_effort" not in observed


async def test_lightning_rejects_reasoning_enabled_for_remediation():
    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="synthetic",
        base_url="https://api.tokenfactory.nebius.com/v1/",
        model=NEMOTRON_LIGHTNING_MODEL,
    ), transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})))
    with pytest.raises(ValueError, match="enable_thinking=false"):
        await client.complete(
            [{"role": "user", "content": "test"}],
            chat_template_kwargs={"enable_thinking": True},
        )


@pytest.mark.parametrize("directive", ["off", "none", "detailed thinking off", ""])
async def test_nebius_rejects_undocumented_reasoning_directives(directive):
    request_made = False

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_made
        request_made = True
        return httpx.Response(200, json={})

    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="synthetic",
        base_url="https://api.tokenfactory.us-central1.nebius.com/v1/",
        model="nvidia/nemotron-3-super-120b-a12b",
    ), transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError, match="must be /think or /no_think"):
        await client.complete(
            [{"role": "user", "content": "test"}],
            reasoning_directive=directive,
        )
    assert request_made is False


async def test_nebius_serializer_wraps_schema_rejected_by_previous_live_attempt():
    schema = RepairProposal.model_json_schema()
    malformed_previous_envelope = {
        "type": "json_schema",
        "json_schema": schema,
    }
    assert "name" not in malformed_previous_envelope["json_schema"]
    assert "schema" not in malformed_previous_envelope["json_schema"]
    observed = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        observed.update(json.loads(request.content))
        return httpx.Response(200, json={
            "choices": [{"message": {"content": '{"ok": true}'}}]
        })

    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="synthetic",
        base_url="https://api.tokenfactory.us-central1.nebius.com/v1/",
        model="nvidia/nemotron-3-super-120b-a12b",
    ), transport=httpx.MockTransport(handler))
    await client.complete(
        [{"role": "user", "content": "test"}], response_schema=schema
    )
    assert observed["response_format"] == {
        "type": "json_schema",
        "json_schema": {
            "name": "repair_proposal",
            "schema": schema,
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


def completion_client(envelope, *, status_code=200, api_key="synthetic"):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=envelope)

    return NebiusTokenFactoryClient(NebiusConfig(
        api_key=api_key,
        base_url="https://api.tokenfactory.us-central1.nebius.com/v1/",
        model="nvidia/nemotron-3-super-120b-a12b",
    ), transport=httpx.MockTransport(handler))


async def test_normal_completion_retains_safe_metadata_and_exact_http_status(caplog):
    client = completion_client({
        "id": "completion-123", "object": "chat.completion", "model": "returned-model",
        "choices": [{
            "index": 0, "finish_reason": "stop",
            "message": {"role": "assistant", "content": '{"ok": true}'},
        }],
        "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
    }, status_code=201)
    assert await client.complete([{"role": "user", "content": "test"}]) == '{"ok": true}'
    metadata = client.last_response_metadata
    assert metadata.http_status == 201
    assert metadata.response_id == "completion-123"
    assert metadata.object_type == "chat.completion"
    assert metadata.returned_model == "returned-model"
    assert metadata.choice_count == 1
    assert metadata.selected_choice_index == 0
    assert metadata.finish_reason == "stop"
    assert metadata.message_role == "assistant"
    assert metadata.message_field_types == {"role": "str", "content": "str"}
    assert metadata.content_type == "str"
    assert metadata.content_length == 12
    assert (metadata.prompt_tokens, metadata.completion_tokens, metadata.total_tokens) == (11, 7, 18)
    assert '"http_status": 201' in caplog.text


@pytest.mark.parametrize(("envelope", "classification"), [
    ({}, "MISSING_CHOICES"),
    ({"choices": []}, "EMPTY_CHOICES"),
    ({"choices": [{}]}, "MISSING_MESSAGE"),
    ({"choices": [{"finish_reason": "stop", "message": {"content": None}}]}, "CONTENT_NULL"),
    ({"choices": [{"finish_reason": "stop", "message": {"content": ""}}]}, "CONTENT_EMPTY"),
    ({"choices": [{"finish_reason": "stop", "message": {}}]}, "CONTENT_MISSING"),
    ({"choices": [{"finish_reason": "stop", "message": {"content": []}}]}, "CONTENT_NON_STRING"),
    ({"choices": [{"finish_reason": "stop", "message": {
        "content": None, "refusal": "request refused",
    }}]}, "REFUSAL_PRESENT"),
    ({"choices": [{"finish_reason": "length", "message": {"content": None}}]},
     "LENGTH_TERMINATED_WITHOUT_CONTENT"),
    ({"choices": [{"finish_reason": "stop", "message": {
        "content": None, "reasoning": "private reasoning",
    }}]}, "REASONING_WITHOUT_CONTENT"),
    ({"choices": [{"finish_reason": "stop", "message": {
        "content": None, "reasoning_content": "private reasoning",
    }}]}, "REASONING_WITHOUT_CONTENT"),
    ({"choices": [{"finish_reason": "tool_calls", "message": {
        "content": None, "tool_calls": [{"id": "call-1"}],
    }}]}, "TOOL_CALLS_WITHOUT_CONTENT"),
])
async def test_completion_failure_classifications(envelope, classification):
    client = completion_client(envelope)
    with pytest.raises(NebiusCompletionError) as raised:
        await client.complete([{"role": "user", "content": "test"}])
    assert raised.value.classification == classification
    assert raised.value.metadata.http_status == 200


async def test_empty_completion_diagnostic_reports_types_not_generated_text_or_credentials(caplog):
    secret = "synthetic-credential"
    client = completion_client({
        "id": secret,
        "model": f"Bearer {secret}",
        "choices": [{
            "index": 2, "finish_reason": "stop",
            "message": {
                "role": "assistant", "content": None,
                "refusal": secret, "reasoning_content": secret,
                "tool_calls": [{"arguments": secret}],
            },
        }],
        "usage": {"prompt_tokens": 3, "completion_tokens": 0, "total_tokens": 3},
    }, api_key=secret)
    with pytest.raises(NebiusCompletionError) as raised:
        await client.complete([{"role": "user", "content": "test"}])
    diagnostic = str(raised.value)
    metadata = raised.value.metadata
    assert secret not in diagnostic
    assert secret not in caplog.text
    assert "private reasoning" not in diagnostic
    assert metadata.refusal_present and metadata.refusal_type == "str"
    assert metadata.reasoning_content_present and metadata.reasoning_content_type == "str"
    assert metadata.tool_calls_present and metadata.tool_calls_count == 1
    assert metadata.completion_tokens == 0


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
        "standards-compliant JSON", "never place a literal control character",
        "complete, executable, pytest-compatible", "syntactically valid Python statement",
        "Preserve all required newlines and indentation", "JSON-escape source newlines",
        "do not compress multiple Python statements", "parse successfully with Python",
        "Put no Markdown fences", "prose inside regression_test", "Formatting example only",
    ):
        assert phrase in SYSTEM_PROMPT
    payload = json.loads(messages[1]["content"])
    assert payload["source_context"]["source_text"] == context.source_text
    assert payload["source_context"]["evidence_ids"] == context.evidence_ids
    assert payload["required_output_schema"]["additionalProperties"] is False


async def test_nebius_content_extraction_preserves_inner_json_text_exactly():
    correctly_escaped = r'{"patch":"line one\nline two"}'
    literal_newline = '{"patch":"line one\nline two"}'
    outputs = [correctly_escaped, literal_newline]

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "choices": [{"message": {"content": outputs.pop(0)}}]
        })

    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="synthetic",
        base_url="https://api.tokenfactory.us-central1.nebius.com/v1/",
        model="nvidia/nemotron-3-super-120b-a12b",
    ), transport=httpx.MockTransport(handler))
    assert await client.complete([{"role": "user", "content": "test"}]) == correctly_escaped
    assert await client.complete([{"role": "user", "content": "test"}]) == literal_newline


async def test_escaped_python_newlines_survive_response_extraction_and_one_json_decode():
    provider_json = r'{"regression_test":"import asyncio\nfrom example import thing\n"}'

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "choices": [{"message": {"content": provider_json}}]
        })

    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="synthetic",
        base_url="https://api.tokenfactory.nebius.com/v1/",
        model=NEMOTRON_LIGHTNING_MODEL,
    ), transport=httpx.MockTransport(handler))
    extracted = await client.complete([{"role": "user", "content": "test"}])
    source = json.loads(extracted)["regression_test"]

    assert extracted == provider_json
    assert source == "import asyncio\nfrom example import thing\n"
    ast.parse(source)


async def test_valid_multiline_pytest_source_passes_strict_proposal_validation():
    trace = await attack_trace()
    source = (
        "import asyncio\n"
        "from example import thing\n\n"
        "def test_example():\n"
        "    assert callable(thing)\n"
    )
    proposal = await generate_repair_proposal(
        trace.model_dump_json(), ROOT,
        MutatingProvider(replace={"regression_test": source}),
    )
    assert proposal.regression_test == source
    ast.parse(proposal.regression_test)


async def test_invalid_joined_import_is_rejected_with_safe_syntax_diagnostics():
    trace = await attack_trace()
    invalid = (
        "import asyncio from foo import thing\n"
        "def test_example():\n"
        "    assert thing\n"
    )
    proposal = None
    with pytest.raises(ValidationError) as raised:
        proposal = await generate_repair_proposal(
            trace.model_dump_json(), ROOT,
            MutatingProvider(replace={"regression_test": invalid}),
        )

    detail = raised.value.errors(include_input=False)[0]
    diagnostic = detail["ctx"]["error"]
    assert isinstance(diagnostic, RegressionTestSyntaxError)
    assert diagnostic.syntax_message
    assert diagnostic.line == 1
    assert diagnostic.offset is not None
    assert diagnostic.source_length == len(invalid)
    assert r"\n" in diagnostic.diagnostic_window
    assert "\n" not in diagnostic.diagnostic_window
    assert len(json.loads(diagnostic.diagnostic_window)) <= 97
    assert invalid not in str(raised.value)
    assert "input_value=" not in str(raised.value)
    assert proposal is None


def test_syntax_diagnostic_window_escapes_controls_and_redacts_credentials():
    invalid = "API_KEY='top-secret'\n\timport asyncio from foo import thing\n"
    with pytest.raises(ValidationError) as raised:
        RepairProposal.model_validate({
            "repair_id": "00000000-0000-0000-0000-000000000001",
            "trace_id": "trace", "boundary_id": "boundary",
            "evidence_ids": ["evidence"], "provider": "provider",
            "model": "model", "target_path": "target.py",
            "target_symbol": "target", "source_hash": "0" * 64,
            "failure_type": "failure", "rationale": "rationale",
            "patch": "--- a/target.py\n+++ b/target.py\n@@ -1 +1 @@\n-x\n+y\n",
            "regression_test": invalid,
        })
    diagnostic = raised.value.errors(include_input=False)[0]["ctx"]["error"]
    assert isinstance(diagnostic, RegressionTestSyntaxError)
    assert r"\n" in diagnostic.diagnostic_window
    assert r"\t" in diagnostic.diagnostic_window
    assert "\n" not in diagnostic.diagnostic_window
    assert "\t" not in diagnostic.diagnostic_window
    assert "top-secret" not in str(diagnostic)
    assert "[REDACTED]" in str(diagnostic)


async def test_multiline_patch_and_regression_test_accept_only_json_escaped_newlines():
    trace = await attack_trace()
    context = build_source_context(trace.model_dump_json(), ROOT)
    provider = FakeRemediationProvider()
    request = RemediationRequest(
        source_context=context, failure_type="indirect_prompt_injection",
        provider=provider.provider_name, model=provider.model_name,
        evidence_summary={"verdict": trace.verdict},
    )
    raw = await provider.generate(request)
    assert r"\n" in raw
    proposal = parse_repair_proposal(raw)
    assert "\n" in proposal.patch
    assert "\n" in proposal.regression_test
    assert proposal.patch.startswith("--- a/")
    compile(proposal.regression_test, "<generated-regression>", "exec")


def test_literal_control_character_is_rejected_with_escaped_bounded_diagnostic():
    raw = '{"patch":"line one\nline two","authorization":"Bearer top-secret"}'
    with pytest.raises(RepairProposalJSONError) as raised:
        parse_repair_proposal(raw)
    error = raised.value
    assert error.code_point == "U+000A"
    assert error.line == 1
    assert error.column == 19
    assert error.content_length == len(raw)
    assert r"\n" in error.diagnostic_window
    assert "\n" not in error.diagnostic_window
    assert "top-secret" not in str(error)
    assert "[REDACTED]" in str(error)


def test_malformed_provider_output_never_creates_repair_proposal():
    malformed = '{"patch":"literal\ttab"}'
    proposal = None
    with pytest.raises(RepairProposalJSONError) as raised:
        proposal = parse_repair_proposal(malformed)
    assert raised.value.code_point == "U+0009"
    assert proposal is None
