import json
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from gauntlet.attacks.indirect_prompt_injection import IndirectPromptInjectionAttack
from gauntlet.core.config import NebiusConfig
from gauntlet.llm.nebius import (
    NEMOTRON_LIGHTNING_MODEL, QWEN_35_MODEL, NebiusTokenFactoryClient,
)
from gauntlet.remediation.candidate_artifact import (
    load_candidate_artifact, load_validated_edit_artifact,
)
from gauntlet.remediation.fake import FakeRemediationProvider
from gauntlet.remediation.models import (
    GeneratedEditCandidate, GeneratedTestCandidate, StructuredRegressionTest,
    StructuredSourceEdit,
)
from gauntlet.remediation.parsing import (
    parse_generated_edit_candidate, parse_generated_test_candidate,
)
from gauntlet.remediation.provider import NebiusNemotronRemediationProvider
from gauntlet.remediation.retry import M42RepairOrchestrator
from gauntlet.remediation.retry_models import (
    RepairRunFailed, RepairRunSucceeded, SafeProviderCompletion,
)
from gauntlet.remediation.run_evidence import load_repair_run
from gauntlet.sandbox.workspace import repository_digest
from victims.customer_support.app import create_app


ROOT = Path(__file__).parents[1]
TARGET = "victims/customer_support/agent.py"


@pytest.fixture
async def serialized_trace() -> str:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://before"
    ) as client:
        trace = (await IndirectPromptInjectionAttack(client).run()).trace
    return trace.model_dump_json()


class ScriptedRetryProvider:
    provider_name = "offline_scripted_provider"
    model_name = "nvidia/Nemotron-3_5-Lightning"

    def __init__(self, edit_outputs, test_outputs):
        self.edit_outputs = list(edit_outputs)
        self.test_outputs = list(test_outputs)
        self.edit_calls = 0
        self.test_calls = 0
        self.edit_revisions = []
        self.test_revisions = []
        self._metadata = None

    async def _next(self, request, outputs, call_index):
        output = outputs[call_index]
        if callable(output):
            output = await output(request)
        self._metadata = SafeProviderCompletion(
            http_status=200,
            response_id=f"offline-{call_index}",
            returned_model=self.model_name,
            finish_reason="stop",
            content_type="str",
            content_length=len(output),
            prompt_tokens=100,
            completion_tokens=200,
            total_tokens=300,
        )
        return output

    async def generate_edit(self, request):
        output = await self._next(request, self.edit_outputs, self.edit_calls)
        self.edit_calls += 1
        return output

    async def generate_test(self, request, *, derived_patch):
        output = await self._next(request, self.test_outputs, self.test_calls)
        self.test_calls += 1
        return output

    async def generate_edit_revision(
        self, request, *, previous_edit, failure_feedback
    ):
        self.edit_revisions.append({
            "previous_edit": previous_edit,
            "failure_feedback": failure_feedback,
        })
        return await self.generate_edit(request)

    async def generate_test_revision(
        self, request, *, derived_patch, previous_test, failure_feedback
    ):
        self.test_revisions.append({
            "previous_test": previous_test,
            "failure_feedback": failure_feedback,
        })
        return await self.generate_test(request, derived_patch=derived_patch)

    def safe_completion_metadata(self):
        return self._metadata


@pytest.mark.parametrize("model", [NEMOTRON_LIGHTNING_MODEL, QWEN_35_MODEL])
def test_m42_accepts_approved_live_remediation_models(model):
    provider = ScriptedRetryProvider([], [])
    provider.model_name = model

    orchestrator = M42RepairOrchestrator(ROOT, provider)

    assert orchestrator.provider.model_name == model


def test_m42_rejects_unapproved_provider_configuration():
    provider = ScriptedRetryProvider([], [])
    provider.model_name = "nvidia/nemotron-3-super-120b-a12b"
    with pytest.raises(ValueError, match="explicitly approved"):
        M42RepairOrchestrator(ROOT, provider)


async def valid_edit_raw(request) -> str:
    return await FakeRemediationProvider().generate_edit(request)


async def valid_test_raw(request) -> str:
    return await FakeRemediationProvider().generate_test(request, derived_patch="")


async def changed_edit_raw(request, **changes) -> str:
    edit = parse_generated_edit_candidate(await valid_edit_raw(request))
    return edit.model_copy(update=changes).model_dump_json()


async def changed_test_raw(request, **changes) -> str:
    test = parse_generated_test_candidate(await valid_test_raw(request))
    if isinstance(changes.get("regression_test"), str):
        changes["regression_test"] = StructuredRegressionTest(
            lines=changes["regression_test"].splitlines()
        )
    return test.model_copy(update=changes).model_dump_json()


async def invalid_syntax_test(request, marker="one"):
    return await changed_test_raw(
        request,
        regression_test=(
            f"# malformed-candidate-{marker}\n"
            "def test_bad(:\n    assert True\n"
        ),
    )


async def trivial_test_raw(request):
    return await changed_test_raw(
        request,
        regression_test="def test_candidate_runs():\n    assert True\n",
    )


def edit_for_changed_source(request, changed: str) -> StructuredSourceEdit:
    source = (ROOT / TARGET).read_text()
    original_lines = source.splitlines()
    changed_lines = changed.splitlines()
    bounded_lines = request.source_context.source_text.splitlines()
    symbol_start = next(
        index for index in range(len(original_lines))
        if original_lines[index:index + len(bounded_lines)] == bounded_lines
    )
    prefix = 0
    while (prefix < len(original_lines) and prefix < len(changed_lines)
           and original_lines[prefix] == changed_lines[prefix]):
        prefix += 1
    suffix = 0
    while (suffix < len(original_lines) - prefix
           and suffix < len(changed_lines) - prefix
           and original_lines[-1 - suffix] == changed_lines[-1 - suffix]):
        suffix += 1
    original_end = len(original_lines) - suffix
    changed_end = len(changed_lines) - suffix
    return StructuredSourceEdit(
        target_path=request.repair_context.target_path,
        target_symbol=request.repair_context.target_symbol,
        source_hash=request.repair_context.source_hash,
        start_line=prefix - symbol_start + 1,
        delete_line_count=original_end - prefix,
        replacement_lines=changed_lines[prefix:changed_end],
    )


async def compile_failure_edit(request):
    source = (ROOT / TARGET).read_text()
    changed = source.replace(
        "    async def chat(self, message: str) -> ChatResponse:",
        "    async def chat(self, message: str) -> ChatResponse",
    )
    return await changed_edit_raw(
        request, source_edit=edit_for_changed_source(request, changed)
    )


async def regression_failure_test(request):
    return await changed_test_raw(
        request,
        regression_test="def test_generated_repair():\n    assert False\n",
    )


async def security_failure_edit(request):
    source = (ROOT / TARGET).read_text()
    changed = source.replace(
        "    async def chat(self, message: str) -> ChatResponse:\n",
        "    async def chat(self, message: str) -> ChatResponse:\n"
        "        # candidate leaves the boundary vulnerable\n",
    )
    return await changed_edit_raw(
        request, source_edit=edit_for_changed_source(request, changed)
    )


async def utility_failure_edit(request):
    source = (ROOT / TARGET).read_text()
    changed = source.replace(
        "privileged_context=not self.enforce_tool_data_boundary,",
        "privileged_context=False,",
    ).replace(
        "enforce_data_only_boundary=self.enforce_tool_data_boundary))",
        "enforce_data_only_boundary=True))",
    ).replace(
        "review = search_reviews(product_id)",
        "review = None if product_id == \"P200\" else search_reviews(product_id)",
    )
    return await changed_edit_raw(
        request, source_edit=edit_for_changed_source(request, changed)
    )


async def out_of_symbol_edit(request):
    valid = parse_generated_edit_candidate(await valid_edit_raw(request))
    return valid.model_copy(update={
        "source_edit": valid.source_edit.model_copy(
            update={"start_line": 100_000}
        )
    }).model_dump_json()


async def test_call_two_does_not_run_when_call_one_validation_fails(
    serialized_trace
):
    provider = ScriptedRetryProvider(
        edit_outputs=[out_of_symbol_edit] * 3,
        test_outputs=[],
    )

    result = await M42RepairOrchestrator(ROOT, provider).run(serialized_trace)

    assert isinstance(result, RepairRunFailed)
    assert provider.edit_calls == 3
    assert provider.test_calls == 0
    assert all(attempt.edit_validation == "FAIL" for attempt in result.attempts)
    assert all(attempt.test_provider_call == "NOT_RUN" for attempt in result.attempts)
    assert all(attempt.proposal_execution == "NOT_RUN" for attempt in result.attempts)
    assert result.final_failure.failure_stage == "patch_authorization"
    assert result.final_failure.failure_code == "edit_range_outside_symbol"


async def test_validation_failure_retries_test_only_and_persists_verified_run(
    serialized_trace, tmp_path
):
    provider = ScriptedRetryProvider(
        edit_outputs=[valid_edit_raw],
        test_outputs=[invalid_syntax_test, valid_test_raw],
    )
    evidence_path = tmp_path / "repair-run.json"
    before = repository_digest(ROOT)

    result = await M42RepairOrchestrator(ROOT, provider).run(
        serialized_trace, evidence_path=evidence_path
    )

    assert isinstance(result, RepairRunSucceeded)
    assert result.successful_attempt == 2
    assert provider.edit_calls == 1
    assert provider.test_calls == 2
    assert provider.edit_revisions == []
    assert len(provider.test_revisions) == 1
    assert result.attempts[0].test_validation == "FAIL"
    assert result.attempts[0].edit_reused is False
    assert result.attempts[0].proposal_execution == "NOT_RUN"
    assert result.attempts[1].test_validation == "PASS"
    assert result.attempts[1].edit_reused is True
    assert result.attempts[1].edit_provider_call == "PASS"
    assert result.attempts[1].patch_proof == "VERIFIED"
    assert result.attempts[0].candidate_digest != result.attempts[1].candidate_digest
    assert result.attempts[1].previous_failure_id == result.attempts[0].failure.failure_id
    assert result.patch_proof.verified
    assert load_repair_run(evidence_path) == result
    assert repository_digest(ROOT) == before

    first_reference = result.attempts[0].candidate_artifact
    second_reference = result.attempts[1].candidate_artifact
    assert first_reference is not None
    assert second_reference is not None
    first_artifact = load_candidate_artifact(
        evidence_path.parent / first_reference.path
    )
    second_artifact = load_candidate_artifact(
        evidence_path.parent / second_reference.path
    )
    assert first_artifact.candidate_id == result.attempts[0].candidate_id
    assert first_artifact.candidate_digest == result.attempts[0].candidate_digest
    assert first_artifact.regression_test.lines == [
        "# malformed-candidate-one", "def test_bad(:", "    assert True",
    ]
    assert first_artifact.derived_patch is not None
    assert first_artifact.derived_regression_test == (
        "# malformed-candidate-one\ndef test_bad(:\n    assert True\n"
    )
    assert result.attempts[0].repair_id is None
    second_candidate = second_artifact.candidate()
    assert second_candidate.rationale == result.final_proposal.rationale
    assert "\n".join(second_candidate.regression_test.lines) + "\n" == (
        result.final_proposal.regression_test
    )
    assert second_artifact.derived_patch == result.final_proposal.patch
    assert second_artifact.derived_regression_test == result.final_proposal.regression_test

    serialized_feedback = json.dumps(provider.test_revisions)
    assert "hidden_reasoning" not in serialized_feedback
    feedback = provider.test_revisions[0]["failure_feedback"]
    assert feedback["failure_stage"] == "regression_syntax"
    assert feedback["failed_call"] == "test"


async def test_validated_edit_is_retained_when_all_test_calls_fail(
    serialized_trace, tmp_path
):
    class LengthTerminatingTestProvider(ScriptedRetryProvider):
        async def generate_test(self, request, *, derived_patch):
            self.test_calls += 1
            self._metadata = SafeProviderCompletion(
                http_status=200,
                response_id=f"offline-length-{self.test_calls}",
                returned_model=self.model_name,
                finish_reason="length",
                content_type="null",
                content_length=None,
                prompt_tokens=100,
                completion_tokens=2_048,
                total_tokens=2_148,
            )
            raise RuntimeError("synthetic length termination")

    provider = LengthTerminatingTestProvider(
        edit_outputs=[valid_edit_raw], test_outputs=[],
    )
    evidence_path = tmp_path / "incomplete-run.json"
    before = repository_digest(ROOT)

    result = await M42RepairOrchestrator(ROOT, provider).run(
        serialized_trace, evidence_path=evidence_path
    )

    assert isinstance(result, RepairRunFailed)
    assert provider.edit_calls == 1
    assert provider.test_calls == 3
    assert all(
        attempt.test_provider_completion is not None
        and attempt.test_provider_completion.finish_reason == "length"
        and attempt.test_provider_completion.completion_tokens == 2_048
        for attempt in result.attempts
    )
    assert all(
        attempt.failure is not None
        and attempt.failure.diagnostics["truncated"] is True
        for attempt in result.attempts
    )
    assert all(attempt.candidate_artifact is None for attempt in result.attempts)
    references = [attempt.edit_artifact for attempt in result.attempts]
    assert all(reference is not None for reference in references)
    assert len({reference.path for reference in references if reference}) == 1
    reference = references[0]
    assert reference is not None
    artifact = load_validated_edit_artifact(
        evidence_path.parent / reference.path
    )
    assert artifact.validation_result == "PASS"
    assert artifact.source_edit.start_line >= 1
    assert artifact.source_edit.replacement_lines
    assert artifact.trusted_original_lines
    assert artifact.derived_patch.startswith("--- a/")
    assert not hasattr(artifact, "regression_test")
    assert load_repair_run(evidence_path) == result
    assert repository_digest(ROOT) == before

    artifact_path = evidence_path.parent / reference.path
    artifact_path.write_text(
        artifact_path.read_text().replace("--- a/", "--- a/tampered-", 1)
    )
    with pytest.raises(ValidationError, match="integrity failed"):
        load_repair_run(evidence_path)


@pytest.mark.parametrize(
    ("first_edit", "first_test", "stage", "failed_call"),
    [
        (compile_failure_edit, valid_test_raw, "compile", "edit"),
        (valid_edit_raw, regression_failure_test, "regression_execution", "test"),
        (security_failure_edit, trivial_test_raw, "security_test", "edit"),
        (utility_failure_edit, trivial_test_raw, "utility_test", "edit"),
    ],
)
async def test_execution_failure_feedback_retries_from_fresh_workspace_to_proof(
    serialized_trace, first_edit, first_test, stage, failed_call
):
    provider = ScriptedRetryProvider(
        edit_outputs=[first_edit, valid_edit_raw],
        test_outputs=[first_test, valid_test_raw],
    )
    result = await M42RepairOrchestrator(ROOT, provider).run(serialized_trace)

    assert isinstance(result, RepairRunSucceeded)
    assert result.total_attempts == 2
    assert result.attempts[0].failure.failure_stage == stage
    assert result.attempts[0].proposal_execution == "FAIL"
    assert result.attempts[1].patch_proof == "VERIFIED"
    assert result.attempts[0].candidate_digest != result.attempts[1].candidate_digest
    assert result.attempts[0].workspace_id
    assert result.attempts[1].workspace_id
    assert result.attempts[0].workspace_id != result.attempts[1].workspace_id
    if failed_call == "edit":
        assert provider.edit_calls == 2
        assert provider.test_calls == 2
        assert result.attempts[1].edit_reused is False
        assert provider.test_revisions == []
        revisions = provider.edit_revisions
    else:
        assert provider.edit_calls == 1
        assert provider.test_calls == 2
        assert result.attempts[1].edit_reused is True
        assert provider.edit_revisions == []
        revisions = provider.test_revisions
    assert len(revisions) == 1
    feedback = revisions[0]["failure_feedback"]
    assert feedback["failure_stage"] == stage
    assert feedback["failed_call"] == failed_call
    assert feedback["previous_candidate_digest"] == result.attempts[0].candidate_digest


async def test_three_failures_stop_without_attempt_four(serialized_trace, tmp_path):
    async def second(request):
        return await invalid_syntax_test(request, "two")

    async def third(request):
        return await invalid_syntax_test(request, "three")

    provider = ScriptedRetryProvider(
        edit_outputs=[valid_edit_raw],
        test_outputs=[invalid_syntax_test, second, third],
    )
    evidence_path = tmp_path / "failed-run.json"
    result = await M42RepairOrchestrator(ROOT, provider).run(
        serialized_trace, evidence_path=evidence_path
    )

    assert isinstance(result, RepairRunFailed)
    assert provider.edit_calls == 1
    assert provider.test_calls == 3
    assert result.total_attempts == 3
    assert len(result.attempts) == 3
    assert len(provider.test_revisions) == 2
    assert provider.edit_revisions == []
    assert all(item.edit_reused or item.attempt == 1 for item in result.attempts)
    assert len({item.candidate_digest for item in result.attempts}) == 3
    assert all(item.patch_proof != "VERIFIED" for item in result.attempts)
    assert result.final_failure == result.attempts[-1].failure
    assert result.original_repository_unchanged
    assert load_repair_run(evidence_path) == result


async def test_identical_retry_candidate_is_rejected_before_execution(
    serialized_trace
):
    async def same_invalid(request):
        return await invalid_syntax_test(request)

    provider = ScriptedRetryProvider(
        edit_outputs=[valid_edit_raw],
        test_outputs=[invalid_syntax_test, same_invalid, valid_test_raw],
    )
    result = await M42RepairOrchestrator(ROOT, provider).run(serialized_trace)

    assert isinstance(result, RepairRunSucceeded)
    assert provider.edit_calls == 1
    assert provider.test_calls == 3
    assert result.attempts[0].candidate_digest == result.attempts[1].candidate_digest
    assert result.attempts[1].failure.failure_code == "duplicate_candidate"
    assert result.attempts[1].proposal_execution == "NOT_RUN"
    assert result.attempts[2].candidate_digest != result.attempts[1].candidate_digest
    assert result.attempts[2].patch_proof == "VERIFIED"


async def test_attempt_one_success_makes_exactly_two_provider_calls(serialized_trace):
    provider = ScriptedRetryProvider(
        edit_outputs=[valid_edit_raw], test_outputs=[valid_test_raw]
    )
    result = await M42RepairOrchestrator(ROOT, provider).run(serialized_trace)

    assert isinstance(result, RepairRunSucceeded)
    assert provider.edit_calls == 1
    assert provider.test_calls == 1
    assert provider.edit_revisions == []
    assert provider.test_revisions == []
    assert result.total_attempts == 1
    attempt = result.attempts[0]
    assert attempt.edit_provider_call == "PASS"
    assert attempt.edit_decode == "PASS"
    assert attempt.edit_validation == "PASS"
    assert attempt.edit_reused is False
    assert attempt.test_provider_call == "PASS"
    assert attempt.test_decode == "PASS"
    assert attempt.test_validation == "PASS"
    assert attempt.proposal_execution == "PASS"
    assert attempt.patch_proof == "VERIFIED"
    assert attempt.edit_provider_completion is not None
    assert attempt.test_provider_completion is not None


async def test_lightning_calls_keep_frozen_schema_reasoning_and_token_contract(
    serialized_trace
):
    base_request = M42RepairOrchestrator(
        ROOT, ScriptedRetryProvider([], [])
    )._request(serialized_trace)
    edit_payload = await FakeRemediationProvider().generate_edit(base_request)
    test_payload = await FakeRemediationProvider().generate_test(
        base_request, derived_patch="---"
    )
    observed = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        name = body["response_format"]["json_schema"]["name"]
        observed[name] = body
        content = edit_payload if name == "edit_candidate" else test_payload
        return httpx.Response(200, json={
            "id": "offline-call", "model": NEMOTRON_LIGHTNING_MODEL,
            "choices": [{
                "index": 0, "finish_reason": "stop",
                "message": {"role": "assistant", "content": content},
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        })

    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="synthetic",
        base_url="https://api.tokenfactory.nebius.com/v1/",
        model=NEMOTRON_LIGHTNING_MODEL,
    ), transport=httpx.MockTransport(handler))
    provider = NebiusNemotronRemediationProvider(client)
    request = base_request.model_copy(update={
        "repair_context": base_request.repair_context.model_copy(update={
            "provider": provider.provider_name, "model": provider.model_name,
        })
    })

    await provider.generate_edit(request)
    await provider.generate_test(request, derived_patch="---")
    await provider.generate_edit_revision(
        request,
        previous_edit=json.loads(edit_payload),
        failure_feedback={"failure_stage": "compile", "failure_code": "compile_error"},
    )

    for name, schema in (
        ("edit_candidate", GeneratedEditCandidate),
        ("test_candidate", GeneratedTestCandidate),
    ):
        body = observed[name]
        assert body["model"] == NEMOTRON_LIGHTNING_MODEL
        assert body["chat_template_kwargs"] == {"enable_thinking": False}
        assert body["max_tokens"] == 2_048
        assert body["response_format"] == {
            "type": "json_schema",
            "json_schema": {
                "name": name,
                "schema": schema.model_json_schema(),
            },
        }
    revision = json.loads(
        observed["edit_candidate"]["messages"][1]["content"]
    )["revision"]
    assert revision["previous_failure"]["failure_stage"] == "compile"
    assert "Produce a new revised source edit" in revision["instruction"]
    assert "Correct only what is necessary" in revision["instruction"]
    assert "concise output budgets" in revision["instruction"]


async def test_run_evidence_tamper_is_rejected(serialized_trace, tmp_path):
    path = tmp_path / "run.json"
    result = await M42RepairOrchestrator(
        ROOT, ScriptedRetryProvider(
            edit_outputs=[valid_edit_raw], test_outputs=[valid_test_raw]
        )
    ).run(serialized_trace, evidence_path=path)
    assert isinstance(result, RepairRunSucceeded)
    path.write_text(path.read_text().replace('"status": "VERIFIED"', '"status": "FAILED"', 1))
    with pytest.raises((ValidationError, ValueError)):
        load_repair_run(path)
