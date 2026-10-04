import ast
import json
from pathlib import Path
from uuid import UUID

import httpx
import pytest
from pydantic import ValidationError

from gauntlet.attacks.indirect_prompt_injection import IndirectPromptInjectionAttack
from gauntlet.core.config import NebiusConfig
from gauntlet.llm.nebius import (
    KIMI_K27_CODE_MODEL,
    NEMOTRON_LIGHTNING_MODEL,
    NEMOTRON_REASONING_DISABLED,
    NebiusAPIError, NebiusCompletionError, NebiusTokenFactoryClient,
)
from gauntlet.remediation.context import build_source_context
from gauntlet.remediation.fake import FakeRemediationProvider
from gauntlet.remediation.models import (
    GeneratedEditCandidate, GeneratedRepairCandidate, GeneratedTestCandidate,
    RegressionTestSyntaxError, RemediationRequest,
    RepairContext, RepairFailure, RepairProposal, StructuredRegressionTest,
    StructuredSourceEdit, combine_repair_candidate,
)
from gauntlet.remediation.parsing import (
    GeneratedEditCandidateJSONError, GeneratedRepairCandidateJSONError,
    GeneratedTestCandidateJSONError, parse_generated_edit_candidate,
    parse_generated_repair_candidate, parse_generated_test_candidate,
)
from gauntlet.remediation.prompt import (
    EDIT_SYSTEM_PROMPT, TEST_SYSTEM_PROMPT, build_edit_messages,
    build_test_messages,
)
from gauntlet.remediation.provider import NebiusNemotronRemediationProvider
from gauntlet.remediation.validation import (
    validate_candidate, validate_regression_test, validate_source_edit,
)
from gauntlet.remediation.workflow import generate_repair_proposal
from victims.customer_support.app import create_app


ROOT = Path(__file__).parents[1]


async def attack_trace():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://before"
    ) as client:
        return (await IndirectPromptInjectionAttack(client).run()).trace


def remediation_request(trace, context, provider):
    return RemediationRequest(
        source_context=context,
        repair_context=RepairContext(
            trace_id=context.trace_id,
            boundary_id=context.boundary_id,
            evidence_ids=context.evidence_ids,
            provider=provider.provider_name,
            model=provider.model_name,
            target_path=context.repository_relative_path,
            target_symbol=context.target_symbol,
            source_hash=context.source_hash,
            failure_type="indirect_prompt_injection",
        ),
        evidence_summary={"verdict": trace.verdict},
    )


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


def test_generated_edit_schema_contains_only_model_owned_content():
    schema = GeneratedEditCandidate.model_json_schema()
    generated_fields = {"rationale", "source_edit", "optional_policy_artifact"}
    trusted_fields = {
        "repair_id", "trace_id", "boundary_id", "evidence_ids", "provider",
        "model", "target_path", "target_symbol", "source_hash", "failure_type",
        "patch", "regression_test",
    }
    assert set(schema["properties"]) == generated_fields
    assert set(schema["required"]) == generated_fields - {"optional_policy_artifact"}
    assert schema["additionalProperties"] is False
    assert trusted_fields.isdisjoint(schema["properties"])


def test_generated_test_schema_contains_only_model_owned_content():
    schema = GeneratedTestCandidate.model_json_schema()
    assert set(schema["properties"]) == {"regression_test"}
    assert set(schema["required"]) == {"regression_test"}
    assert schema["additionalProperties"] is False


def test_generated_repair_schema_contains_only_model_owned_content():
    schema = GeneratedRepairCandidate.model_json_schema()
    generated_fields = {
        "rationale", "source_edit", "regression_test", "optional_policy_artifact",
    }
    trusted_fields = {
        "repair_id", "trace_id", "boundary_id", "evidence_ids", "provider",
        "model", "target_path", "target_symbol", "source_hash", "failure_type",
    }
    assert set(schema["properties"]) == generated_fields
    assert set(schema["required"]) == generated_fields - {"optional_policy_artifact"}
    assert schema["additionalProperties"] is False
    assert trusted_fields.isdisjoint(schema["properties"])


def valid_candidate(context, **changes):
    values = {
        "rationale": "Enforce the untrusted data boundary.",
        "source_edit": StructuredSourceEdit(
            target_path=context.repository_relative_path,
            target_symbol=context.target_symbol,
            source_hash=context.source_hash,
            start_line=2,
            delete_line_count=0,
            replacement_lines=["        # model-proposed boundary marker"],
        ),
        "regression_test": StructuredRegressionTest(lines=[
            "def test_security_boundary():", "    assert True",
        ]),
        "optional_policy_artifact": None,
    }
    if isinstance(changes.get("regression_test"), str):
        changes["regression_test"] = StructuredRegressionTest(
            lines=changes["regression_test"].splitlines()
        )
    values.update(changes)
    return GeneratedRepairCandidate(**values)


async def test_observed_malformed_python_decodes_then_becomes_repair_failure_without_source_change():
    trace = await attack_trace()
    context = build_source_context(trace.model_dump_json(), ROOT)
    trusted = remediation_request(trace, context, FakeRemediationProvider()).repair_context
    target = ROOT / context.repository_relative_path
    before = target.read_bytes()
    malformed = "import pytestimport refrom unittest.mock import patch, AsyncMockfrom foo import bar"

    raw = valid_candidate(context, regression_test=malformed).model_dump_json()
    candidate = parse_generated_repair_candidate(raw)
    assert candidate.regression_test.lines == [malformed]
    result = validate_candidate(candidate, trusted, ROOT)

    assert isinstance(result, RepairFailure)
    assert result.failure_stage == "regression_syntax"
    assert result.failure_code == "invalid_python"
    assert result.diagnostics["line"] == 1
    assert result.diagnostics["offset"] == 21
    assert result.diagnostics["source_length"] == len(malformed) + 1
    assert isinstance(UUID(result.failure_id), UUID)
    assert isinstance(UUID(result.candidate_id), UUID)
    assert result.trace_id == context.trace_id
    assert result.boundary_id == context.boundary_id
    assert result.source_hash == context.source_hash
    assert malformed not in result.model_dump_json()
    assert target.read_bytes() == before


async def test_candidate_validator_classifies_structure_and_patch_failures_in_order():
    trace = await attack_trace()
    context = build_source_context(trace.model_dump_json(), ROOT)
    trusted = remediation_request(trace, context, FakeRemediationProvider()).repair_context

    missing_test = validate_candidate(
        valid_candidate(context, regression_test="def helper():\n    assert True\n"),
        trusted, ROOT,
    )
    assert isinstance(missing_test, RepairFailure)
    assert (missing_test.failure_stage, missing_test.failure_code) == (
        "regression_structure", "missing_test_function",
    )

    missing_assertion = validate_candidate(
        valid_candidate(context, regression_test="def test_boundary():\n    return True\n"),
        trusted, ROOT,
    )
    assert isinstance(missing_assertion, RepairFailure)
    assert (missing_assertion.failure_stage, missing_assertion.failure_code) == (
        "regression_structure", "missing_assertion",
    )

    malformed_patch = validate_candidate(
        valid_candidate(context, source_edit=valid_candidate(context).source_edit.model_copy(
            update={"start_line": 100_000}
        )), trusted, ROOT,
    )
    assert isinstance(malformed_patch, RepairFailure)
    assert (malformed_patch.failure_stage, malformed_patch.failure_code) == (
        "patch_authorization", "edit_range_outside_symbol",
    )


@pytest.mark.parametrize(("changes", "code"), [
    ({"rationale": "   "}, "empty_rationale"),
    ({"optional_policy_artifact": "\t"}, "empty_policy_artifact"),
])
async def test_candidate_validator_rejects_empty_semantic_content(changes, code):
    trace = await attack_trace()
    context = build_source_context(trace.model_dump_json(), ROOT)
    trusted = remediation_request(trace, context, FakeRemediationProvider()).repair_context
    result = validate_candidate(valid_candidate(context, **changes), trusted, ROOT)
    assert isinstance(result, RepairFailure)
    assert result.failure_stage == "candidate_validation"
    assert result.failure_code == code


async def test_repair_failure_serialization_is_bounded_redacted_and_secret_free():
    trace = await attack_trace()
    context = build_source_context(trace.model_dump_json(), ROOT)
    trusted = remediation_request(trace, context, FakeRemediationProvider()).repair_context
    secret = "synthetic-provider-secret"
    candidate = valid_candidate(
        context,
        regression_test=(
            f"API_KEY='{secret}'\n\timport pytestimport refrom unittest.mock import patch"
        ),
    )
    result = validate_candidate(candidate, trusted, ROOT)
    serialized = result.model_dump_json()

    assert isinstance(result, RepairFailure)
    assert secret not in serialized
    assert "[REDACTED]" in serialized
    assert secret not in serialized
    assert set(result.candidate_field_digests) == {
        "rationale", "source_edit", "regression_test", "optional_policy_artifact",
    }
    assert result.candidate_field_lengths["regression_test"] > 0
    assert len(result.diagnostics["window"]) <= 110


def test_repair_failure_supports_m3_and_m4_execution_stages():
    stages = RepairFailure.model_json_schema()["properties"]["failure_stage"]["enum"]
    assert stages == [
        "candidate_validation", "source_identity", "regression_syntax", "regression_structure",
        "patch_format", "patch_authorization", "patch_apply", "compile",
        "regression_execution", "security_test", "utility_test", "existing_suite",
    ]


async def test_fake_provider_exercises_complete_m31_flow_without_source_changes():
    trace = await attack_trace()
    target = ROOT / "victims/customer_support/agent.py"
    before = target.read_bytes()
    proposal = await generate_repair_proposal(
        trace.model_dump_json(), ROOT, FakeRemediationProvider()
    )
    assert isinstance(proposal, RepairProposal)
    assert target.read_bytes() == before
    assert proposal.trace_id == trace.attack_id
    assert proposal.boundary_id == trace.failure_boundary.boundary_id
    assert proposal.evidence_ids == trace.failure_boundary.evidence_event_ids
    assert proposal.provider == "fake_remediation_provider"
    assert proposal.model == "deterministic-repair-fixture-v1"
    assert UUID(proposal.repair_id)
    assert proposal.target_path == "victims/customer_support/agent.py"
    assert proposal.target_symbol == "CustomerSupportAgent.chat"
    assert proposal.source_hash == build_source_context(
        trace.model_dump_json(), ROOT
    ).source_hash
    assert proposal.failure_type == "indirect_prompt_injection"
    assert proposal.patch.startswith("--- a/victims/customer_support/agent.py")
    assert "async def test_poisoned_review_does_not_leak_canary" in proposal.regression_test


class MutatingProvider(FakeRemediationProvider):
    EDIT_KEYS = {"rationale", "source_edit", "optional_policy_artifact"}
    TEST_KEYS = {"regression_test"}

    def __init__(self, *, remove: str | None = None, replace: dict | None = None):
        self.remove = remove
        self.replace = replace or {}

    def _mutate(self, body, *, part_keys):
        if self.remove and self.remove in body:
            body.pop(self.remove, None)
        replacement = {
            key: value for key, value in self.replace.items()
            if key in part_keys or key not in self.EDIT_KEYS | self.TEST_KEYS
        }
        if isinstance(replacement.get("regression_test"), str):
            replacement["regression_test"] = {
                "lines": replacement["regression_test"].splitlines()
            }
        body.update(replacement)
        return json.dumps(body)

    async def generate_edit(self, request):
        body = json.loads(await super().generate_edit(request))
        return self._mutate(body, part_keys=self.EDIT_KEYS)

    async def generate_test(self, request, *, derived_patch):
        body = json.loads(
            await super().generate_test(request, derived_patch=derived_patch)
        )
        return self._mutate(body, part_keys=self.TEST_KEYS)


@pytest.mark.parametrize("field", ["source_edit", "regression_test"])
async def test_missing_patch_or_generated_regression_test_is_rejected(field):
    trace = await attack_trace()
    with pytest.raises(ValidationError):
        await generate_repair_proposal(
            trace.model_dump_json(), ROOT, MutatingProvider(remove=field)
        )


@pytest.mark.parametrize("raw", ["not-json", "{}", '{"source_edit": 7}'])
def test_malformed_provider_output_is_rejected_by_strict_schema(raw):
    with pytest.raises((ValidationError, ValueError)):
        GeneratedRepairCandidate.model_validate_json(raw)


async def test_model_cannot_supply_or_override_trusted_provenance():
    trace = await attack_trace()
    for field, value in (
        ("trace_id", "different"), ("boundary_id", "different"),
        ("evidence_ids", ["different"]), ("provider", "other"),
        ("model", "other"), ("source_hash", "0" * 64),
        ("repair_id", "not-a-uuid"), ("target_path", "other.py"),
        ("target_symbol", "other"), ("failure_type", "other"),
    ):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            await generate_repair_proposal(
                trace.model_dump_json(), ROOT,
                MutatingProvider(replace={field: value}),
            )


async def test_invalid_patch_target_and_non_executable_test_become_repair_failures():
    trace = await attack_trace()
    context = build_source_context(trace.model_dump_json(), ROOT)
    source_edit = valid_candidate(context).source_edit
    unauthorized = await generate_repair_proposal(
        trace.model_dump_json(), ROOT,
        MutatingProvider(replace={
            "source_edit": source_edit.model_copy(
                update={"target_path": "other.py"}
            ).model_dump(mode="json")
        }),
    )
    assert isinstance(unauthorized, RepairFailure)
    assert unauthorized.failure_stage == "patch_authorization"
    assert unauthorized.failure_code == "unauthorized_edit_target"

    missing_test = await generate_repair_proposal(
        trace.model_dump_json(), ROOT,
        MutatingProvider(replace={
            "regression_test": {"lines": ["def helper():", "    return True"]}
        }),
    )
    assert isinstance(missing_test, RepairFailure)
    assert missing_test.failure_stage == "regression_structure"
    assert missing_test.failure_code == "missing_test_function"


async def test_nebius_transport_uses_documented_chat_schema_contract():
    observed = {}
    schema = GeneratedRepairCandidate.model_json_schema()

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
    edit_schema = GeneratedEditCandidate.model_json_schema()
    test_schema = GeneratedTestCandidate.model_json_schema()

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        name = body["response_format"]["json_schema"]["name"]
        observed[name] = body
        content = payloads[name]
        return httpx.Response(200, json={
            "choices": [{"message": {"content": content}}]
        })

    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="synthetic",
        base_url="https://api.tokenfactory.us-central1.nebius.com/v1/",
        model="nvidia/nemotron-3-super-120b-a12b",
    ), transport=httpx.MockTransport(handler))
    provider = NebiusNemotronRemediationProvider(client)
    trace = await attack_trace()
    context = build_source_context(trace.model_dump_json(), ROOT)
    request = remediation_request(trace, context, provider)
    fake = FakeRemediationProvider()
    payloads = {
        "edit_candidate": await fake.generate_edit(request),
        "test_candidate": await fake.generate_test(request, derived_patch="---"),
    }

    await provider.generate_edit(request)
    await provider.generate_test(request, derived_patch="---")

    assert observed["edit_candidate"]["messages"][0] == {
        "role": "system", "content": "/no_think\n" + EDIT_SYSTEM_PROMPT,
    }
    assert observed["edit_candidate"]["max_tokens"] == 2_048
    assert observed["edit_candidate"]["response_format"] == {
        "type": "json_schema",
        "json_schema": {"name": "edit_candidate", "schema": edit_schema},
    }
    assert observed["test_candidate"]["messages"][0] == {
        "role": "system", "content": "/no_think\n" + TEST_SYSTEM_PROMPT,
    }
    assert observed["test_candidate"]["max_tokens"] == 2_048
    assert observed["test_candidate"]["response_format"] == {
        "type": "json_schema",
        "json_schema": {"name": "test_candidate", "schema": test_schema},
    }


async def test_lightning_provider_disables_thinking_without_no_think_directive():
    observed = {}
    edit_schema = GeneratedEditCandidate.model_json_schema()
    test_schema = GeneratedTestCandidate.model_json_schema()

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        name = body["response_format"]["json_schema"]["name"]
        observed[name] = body
        content = payloads[name]
        return httpx.Response(200, json={
            "choices": [{"message": {"content": content}}]
        })

    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="synthetic",
        base_url="https://api.tokenfactory.nebius.com/v1/",
        model=NEMOTRON_LIGHTNING_MODEL,
    ), transport=httpx.MockTransport(handler))
    provider = NebiusNemotronRemediationProvider(client)
    trace = await attack_trace()
    context = build_source_context(trace.model_dump_json(), ROOT)
    request = remediation_request(trace, context, provider)
    fake = FakeRemediationProvider()
    payloads = {
        "edit_candidate": await fake.generate_edit(request),
        "test_candidate": await fake.generate_test(request, derived_patch="---"),
    }

    await provider.generate_edit(request)
    await provider.generate_test(request, derived_patch="---")

    for name, prompt, schema in (
        ("edit_candidate", EDIT_SYSTEM_PROMPT, edit_schema),
        ("test_candidate", TEST_SYSTEM_PROMPT, test_schema),
    ):
        body = observed[name]
        assert body["model"] == NEMOTRON_LIGHTNING_MODEL
        assert body["messages"][0] == {"role": "system", "content": prompt}
        assert not body["messages"][0]["content"].startswith("/no_think")
        assert body["chat_template_kwargs"] == {"enable_thinking": False}
        assert body["max_tokens"] == 2_048
        assert body["response_format"] == {
            "type": "json_schema",
            "json_schema": {"name": name, "schema": schema},
        }


async def test_qwen_provider_disables_thinking_for_bounded_structured_output():
    observed = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        observed[body["response_format"]["json_schema"]["name"]] = body
        return httpx.Response(200, json={
            "choices": [{"message": {"content": payloads[body["response_format"]["json_schema"]["name"]]}}]
        })

    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="synthetic",
        base_url="https://api.tokenfactory.us-central1.nebius.com/v1/",
        model="Qwen/Qwen3.5-397B-A17B",
    ), transport=httpx.MockTransport(handler))
    provider = NebiusNemotronRemediationProvider(client)
    trace = await attack_trace()
    context = build_source_context(trace.model_dump_json(), ROOT)
    request = remediation_request(trace, context, provider)
    fake = FakeRemediationProvider()
    payloads = {
        "edit_candidate": await fake.generate_edit(request),
        "test_candidate": await fake.generate_test(request, derived_patch="---"),
    }

    await provider.generate_edit(request)
    await provider.generate_test(request, derived_patch="---")

    assert observed["edit_candidate"]["messages"][0]["content"] == EDIT_SYSTEM_PROMPT
    assert observed["test_candidate"]["messages"][0]["content"] == TEST_SYSTEM_PROMPT
    assert observed["edit_candidate"]["chat_template_kwargs"] == {
        "enable_thinking": False
    }
    assert observed["test_candidate"]["chat_template_kwargs"] == {
        "enable_thinking": False
    }
    assert observed["edit_candidate"]["max_tokens"] == 2_048
    assert observed["test_candidate"]["max_tokens"] == 2_048
    assert "reasoning_effort" not in observed["edit_candidate"]


async def test_kimi_provider_preserves_frozen_structured_contract_without_unsupported_reasoning_control():
    observed = {}
    edit_schema = GeneratedEditCandidate.model_json_schema()
    test_schema = GeneratedTestCandidate.model_json_schema()

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        name = body["response_format"]["json_schema"]["name"]
        observed[name] = body
        return httpx.Response(200, json={
            "choices": [{"message": {"content": payloads[name]}}]
        })

    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="synthetic",
        base_url="https://api.tokenfactory.nebius.com/v1/",
        model=KIMI_K27_CODE_MODEL,
    ), transport=httpx.MockTransport(handler))
    provider = NebiusNemotronRemediationProvider(client)
    trace = await attack_trace()
    context = build_source_context(trace.model_dump_json(), ROOT)
    request = remediation_request(trace, context, provider)
    fake = FakeRemediationProvider()
    payloads = {
        "edit_candidate": await fake.generate_edit(request),
        "test_candidate": await fake.generate_test(request, derived_patch="---"),
    }

    await provider.generate_edit(request)
    await provider.generate_test(request, derived_patch="---")

    for name, prompt, schema in (
        ("edit_candidate", EDIT_SYSTEM_PROMPT, edit_schema),
        ("test_candidate", TEST_SYSTEM_PROMPT, test_schema),
    ):
        body = observed[name]
        assert body["model"] == KIMI_K27_CODE_MODEL
        assert body["messages"][0] == {"role": "system", "content": prompt}
        assert body["max_tokens"] == 2_048
        assert body["response_format"] == {
            "type": "json_schema",
            "json_schema": {"name": name, "schema": schema},
        }
        assert "chat_template_kwargs" not in body
        assert "reasoning_effort" not in body


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
    schema = GeneratedRepairCandidate.model_json_schema()
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


async def test_edit_prompt_contains_defensive_contract_and_bounded_artifacts():
    trace = await attack_trace()
    context = build_source_context(trace.model_dump_json(), ROOT)
    provider = FakeRemediationProvider()
    request = remediation_request(trace, context, provider)
    messages = build_edit_messages(request)
    assert messages[0] == {"role": "system", "content": EDIT_SYSTEM_PROMPT}
    for phrase in (
        "authorized defensive benchmark", "synthetic local victim",
        "only the supplied execution evidence", "Modify only the authorized target",
        "Preserve legitimate behavior", "Do not remove or weaken tests",
        "Do not suppress the verifier", "remove the canary", "bypass or modify the attack harness",
        "smallest", "reasonable repair",
        "standards-compliant JSON",
        "remediation CONTENT, not trusted provenance", "Do not hard-code P100",
        "Do not disable all tool data", "deterministic test-double switch",
        "below 800 output tokens", "Limit rationale",
        "at most 120", "Do not copy the complete target file",
        "one contiguous structured source edit",
        "mechanically derive a unified diff",
        "No source-edit line-array element",
    ):
        assert phrase in EDIT_SYSTEM_PROMPT
    payload = json.loads(messages[1]["content"])
    assert payload["source_context"]["source_text"] == context.source_text
    assert payload["source_context"]["evidence_ids"] == context.evidence_ids
    assert payload["repair_context"]["target_path"] == context.repository_relative_path
    assert payload["required_output_schema"]["additionalProperties"] is False
    assert "derived_patch" not in payload


async def test_test_prompt_contains_defensive_contract_and_bounded_artifacts():
    trace = await attack_trace()
    context = build_source_context(trace.model_dump_json(), ROOT)
    provider = FakeRemediationProvider()
    request = remediation_request(trace, context, provider)
    messages = build_test_messages(request, derived_patch="--- a/x\n+++ b/x\n")
    assert messages[0] == {"role": "system", "content": TEST_SYSTEM_PROMPT}
    for phrase in (
        "authorized defensive benchmark",
        "trusted, already-validated source repair",
        "Write a test that proves the security property",
        "Do not re-propose a repair", "Do not modify the\npatch",
        "Do not suppress the\nverifier",
        "standards-compliant JSON",
        "complete, executable", "pytest-compatible Python 3 source",
        "one physical source line per array element", "without line terminators",
        "at most 40 lines", "Use only imports exercised by the test",
        "one focused test\nfunction",
        "Put no Markdown fences", "Do not add unused",
        "below 1,200 output tokens",
        "No line-array element may contain LF or CR",
    ):
        assert phrase in TEST_SYSTEM_PROMPT
    payload = json.loads(messages[1]["content"])
    assert payload["derived_patch"] == "--- a/x\n+++ b/x\n"
    assert payload["required_output_schema"]["additionalProperties"] is False


def test_prompts_use_structured_lines_without_patch_or_multiline_test_strings():
    edit_schema = GeneratedEditCandidate.model_json_schema()
    assert set(edit_schema["properties"]) == {
        "rationale", "source_edit", "optional_policy_artifact",
    }
    assert "source_edit.start_line" in EDIT_SYSTEM_PROMPT
    assert "expected_original_lines" not in EDIT_SYSTEM_PROMPT
    assert "replacement_lines" in EDIT_SYSTEM_PROMPT
    assert '"patch"' not in EDIT_SYSTEM_PROMPT
    source_edit_schema = edit_schema["$defs"]["StructuredSourceEdit"]
    assert "expected_original_lines" not in source_edit_schema["properties"]
    test_schema = GeneratedTestCandidate.model_json_schema()
    assert set(test_schema["properties"]) == {"regression_test"}
    assert test_schema["$defs"]["StructuredRegressionTest"]["properties"][
        "lines"
    ]["maxItems"] == 40
    assert "regression_test.lines" in TEST_SYSTEM_PROMPT
    assert '"patch"' not in TEST_SYSTEM_PROMPT
    for forbidden in (
        "victims/clean_customer_support", "CleanCustomerSupportAgent",
        "This product is excellent", "Kestrel-7749",
    ):
        assert forbidden not in EDIT_SYSTEM_PROMPT
        assert forbidden not in TEST_SYSTEM_PROMPT


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
    assert isinstance(proposal, RepairProposal)
    assert proposal.regression_test == source
    ast.parse(proposal.regression_test)


async def test_invalid_joined_import_becomes_safe_regression_syntax_failure():
    trace = await attack_trace()
    invalid = (
        "import asyncio from foo import thing\n"
        "def test_example():\n"
        "    assert thing\n"
    )
    result = await generate_repair_proposal(
        trace.model_dump_json(), ROOT,
        MutatingProvider(replace={"regression_test": invalid}),
    )

    assert isinstance(result, RepairFailure)
    assert result.failure_stage == "regression_syntax"
    assert result.failure_code == "invalid_python"
    assert result.diagnostics["syntax_message"]
    assert result.diagnostics["line"] == 1
    assert result.diagnostics["offset"] is not None
    assert result.diagnostics["source_length"] == len(invalid)
    assert r"\n" in result.diagnostics["window"]
    assert "\n" not in result.diagnostics["window"]
    assert len(json.loads(result.diagnostics["window"])) <= 97
    assert invalid not in result.model_dump_json()


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


async def test_structured_lines_materialize_exact_patch_and_regression_newlines():
    trace = await attack_trace()
    context = build_source_context(trace.model_dump_json(), ROOT)
    provider = FakeRemediationProvider()
    request = remediation_request(trace, context, provider)
    edit_raw = await provider.generate_edit(request)
    edit_candidate = parse_generated_edit_candidate(edit_raw)
    assert all("\n" not in line and "\r" not in line
               for line in edit_candidate.source_edit.replacement_lines)
    materialized = {}
    derived = validate_source_edit(
        edit_candidate, request.repair_context, ROOT, materialized_output=materialized
    )
    assert isinstance(derived, str)
    test_raw = await provider.generate_test(
        request, derived_patch=materialized["patch"]
    )
    test_candidate = parse_generated_test_candidate(test_raw)
    assert all("\n" not in line and "\r" not in line
               for line in test_candidate.regression_test.lines)
    candidate = combine_repair_candidate(edit_candidate, test_candidate)
    proposal = validate_candidate(candidate, request.repair_context, ROOT)
    assert isinstance(proposal, RepairProposal)
    assert proposal.patch.startswith("--- a/")
    assert "\n+++ b/" in proposal.patch
    assert proposal.regression_test == (
        "\n".join(test_candidate.regression_test.lines) + "\n"
    )
    compile(proposal.regression_test, "<generated-regression>", "exec")


def test_literal_control_character_is_rejected_with_escaped_bounded_diagnostic():
    raw = '{"patch":"line one\nline two","authorization":"Bearer top-secret"}'
    with pytest.raises(GeneratedRepairCandidateJSONError) as raised:
        parse_generated_repair_candidate(raw)
    error = raised.value
    assert error.code_point == "U+000A"
    assert error.line == 1
    assert error.column == 19
    assert error.content_length == len(raw)
    assert r"\n" in error.diagnostic_window
    assert "\n" not in error.diagnostic_window
    assert "top-secret" not in str(error)
    assert "[REDACTED]" in str(error)


def test_malformed_provider_output_never_creates_generated_repair():
    malformed = '{"patch":"literal\ttab"}'
    proposal = None
    with pytest.raises(GeneratedRepairCandidateJSONError) as raised:
        proposal = parse_generated_repair_candidate(malformed)
    assert raised.value.code_point == "U+0009"
    assert proposal is None
