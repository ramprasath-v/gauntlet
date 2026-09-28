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
from gauntlet.remediation.candidate_artifact import load_candidate_artifact
from gauntlet.remediation.fake import FakeRemediationProvider
from gauntlet.remediation.models import (
    GeneratedRepairCandidate, StructuredRegressionTest, StructuredSourceEdit,
)
from gauntlet.remediation.parsing import parse_generated_repair_candidate
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

    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = 0
        self.revisions = []
        self._metadata = None

    async def _next(self, request):
        output = self.outputs[self.calls]
        self.calls += 1
        if callable(output):
            output = await output(request)
        self._metadata = SafeProviderCompletion(
            http_status=200,
            response_id=f"offline-{self.calls}",
            returned_model=self.model_name,
            finish_reason="stop",
            content_type="str",
            content_length=len(output),
            prompt_tokens=100,
            completion_tokens=200,
            total_tokens=300,
        )
        return output

    async def generate(self, request):
        return await self._next(request)

    async def generate_revision(
        self, request, *, previous_candidate, failure_feedback
    ):
        self.revisions.append({
            "previous_candidate": previous_candidate,
            "failure_feedback": failure_feedback,
        })
        return await self._next(request)

    def safe_completion_metadata(self):
        return self._metadata


@pytest.mark.parametrize("model", [NEMOTRON_LIGHTNING_MODEL, QWEN_35_MODEL])
def test_m42_accepts_approved_live_remediation_models(model):
    provider = ScriptedRetryProvider([])
    provider.model_name = model

    orchestrator = M42RepairOrchestrator(ROOT, provider)

    assert orchestrator.provider.model_name == model


def test_m42_rejects_unapproved_provider_configuration():
    provider = ScriptedRetryProvider([])
    provider.model_name = "nvidia/nemotron-3-super-120b-a12b"
    with pytest.raises(ValueError, match="explicitly approved"):
        M42RepairOrchestrator(ROOT, provider)


async def valid_raw(request) -> str:
    return await FakeRemediationProvider().generate(request)


async def changed_raw(request, **changes) -> str:
    candidate = parse_generated_repair_candidate(await valid_raw(request))
    if isinstance(changes.get("regression_test"), str):
        changes["regression_test"] = StructuredRegressionTest(
            lines=changes["regression_test"].splitlines()
        )
    return candidate.model_copy(update=changes).model_dump_json()


async def invalid_syntax(request, marker="one"):
    return await changed_raw(
        request,
        regression_test=(
            f"# malformed-candidate-{marker}\n"
            "def test_bad(:\n    assert True\n"
        ),
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
        expected_original_lines=original_lines[prefix:original_end],
        replacement_lines=changed_lines[prefix:changed_end],
    )


async def compile_failure(request):
    source = (ROOT / TARGET).read_text()
    changed = source.replace(
        "    async def chat(self, message: str) -> ChatResponse:",
        "    async def chat(self, message: str) -> ChatResponse",
    )
    return await changed_raw(request, source_edit=edit_for_changed_source(request, changed))


async def regression_failure(request):
    return await changed_raw(
        request,
        regression_test="def test_generated_repair():\n    assert False\n",
    )


async def security_failure(request):
    source = (ROOT / TARGET).read_text()
    changed = source.replace(
        "    async def chat(self, message: str) -> ChatResponse:\n",
        "    async def chat(self, message: str) -> ChatResponse:\n"
        "        # candidate leaves the boundary vulnerable\n",
    )
    return await changed_raw(
        request, source_edit=edit_for_changed_source(request, changed),
        regression_test="def test_candidate_runs():\n    assert True\n",
    )


async def utility_failure(request):
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
    return await changed_raw(
        request, source_edit=edit_for_changed_source(request, changed),
        regression_test="def test_candidate_runs():\n    assert True\n",
    )


async def test_validation_failure_retries_new_candidate_and_persists_verified_run(
    serialized_trace, tmp_path
):
    provider = ScriptedRetryProvider([invalid_syntax, valid_raw])
    evidence_path = tmp_path / "repair-run.json"
    before = repository_digest(ROOT)

    result = await M42RepairOrchestrator(ROOT, provider).run(
        serialized_trace, evidence_path=evidence_path
    )

    assert isinstance(result, RepairRunSucceeded)
    assert result.successful_attempt == 2
    assert provider.calls == 2
    assert result.attempts[0].candidate_validation == "FAIL"
    assert result.attempts[0].proposal_execution == "NOT_RUN"
    assert result.attempts[1].candidate_validation == "PASS"
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
    assert result.attempts[0].candidate_validation == "FAIL"
    second_candidate = second_artifact.candidate()
    assert second_candidate.rationale == result.final_proposal.rationale
    assert "\n".join(second_candidate.regression_test.lines) + "\n" == (
        result.final_proposal.regression_test
    )
    assert second_artifact.derived_patch == result.final_proposal.patch
    assert second_artifact.derived_regression_test == result.final_proposal.regression_test

    serialized_feedback = json.dumps(provider.revisions)
    assert "hidden_reasoning" not in serialized_feedback
    assert provider.revisions[0]["failure_feedback"]["failure_stage"] == "regression_syntax"


@pytest.mark.parametrize(
    ("first_candidate", "stage"),
    [
        (compile_failure, "compile"),
        (regression_failure, "regression_execution"),
        (security_failure, "security_test"),
        (utility_failure, "utility_test"),
    ],
)
async def test_execution_failure_feedback_retries_from_fresh_workspace_to_proof(
    serialized_trace, first_candidate, stage
):
    provider = ScriptedRetryProvider([first_candidate, valid_raw])
    result = await M42RepairOrchestrator(ROOT, provider).run(serialized_trace)

    assert isinstance(result, RepairRunSucceeded)
    assert provider.calls == 2
    assert result.total_attempts == 2
    assert result.attempts[0].failure.failure_stage == stage
    assert result.attempts[0].proposal_execution == "FAIL"
    assert result.attempts[1].patch_proof == "VERIFIED"
    assert result.attempts[0].candidate_digest != result.attempts[1].candidate_digest
    assert result.attempts[0].workspace_id
    assert result.attempts[1].workspace_id
    assert result.attempts[0].workspace_id != result.attempts[1].workspace_id
    feedback = provider.revisions[0]["failure_feedback"]
    assert feedback["failure_stage"] == stage
    assert feedback["previous_candidate_digest"] == result.attempts[0].candidate_digest


async def test_three_failures_stop_without_attempt_four(serialized_trace, tmp_path):
    async def second(request):
        return await invalid_syntax(request, "two")

    async def third(request):
        return await invalid_syntax(request, "three")

    provider = ScriptedRetryProvider([invalid_syntax, second, third])
    evidence_path = tmp_path / "failed-run.json"
    result = await M42RepairOrchestrator(ROOT, provider).run(
        serialized_trace, evidence_path=evidence_path
    )

    assert isinstance(result, RepairRunFailed)
    assert provider.calls == 3
    assert result.total_attempts == 3
    assert len(result.attempts) == 3
    assert len(provider.revisions) == 2
    assert len({item.candidate_digest for item in result.attempts}) == 3
    assert all(item.patch_proof != "VERIFIED" for item in result.attempts)
    assert result.final_failure == result.attempts[-1].failure
    assert result.original_repository_unchanged
    assert load_repair_run(evidence_path) == result


async def test_identical_retry_candidate_is_rejected_before_execution(
    serialized_trace
):
    async def same_invalid(request):
        return await invalid_syntax(request)

    provider = ScriptedRetryProvider([invalid_syntax, same_invalid, valid_raw])
    result = await M42RepairOrchestrator(ROOT, provider).run(serialized_trace)

    assert isinstance(result, RepairRunSucceeded)
    assert provider.calls == 3
    assert result.attempts[0].candidate_digest == result.attempts[1].candidate_digest
    assert result.attempts[1].failure.failure_code == "duplicate_candidate"
    assert result.attempts[1].proposal_execution == "NOT_RUN"
    assert result.attempts[2].candidate_digest != result.attempts[1].candidate_digest
    assert result.attempts[2].patch_proof == "VERIFIED"


async def test_attempt_one_success_makes_exactly_one_provider_call(serialized_trace):
    provider = ScriptedRetryProvider([valid_raw])
    result = await M42RepairOrchestrator(ROOT, provider).run(serialized_trace)

    assert isinstance(result, RepairRunSucceeded)
    assert provider.calls == 1
    assert provider.revisions == []
    assert result.total_attempts == 1
    assert result.attempts[0].provider_call == "PASS"
    assert result.attempts[0].candidate_decode == "PASS"
    assert result.attempts[0].candidate_validation == "PASS"
    assert result.attempts[0].proposal_execution == "PASS"
    assert result.attempts[0].patch_proof == "VERIFIED"


async def test_lightning_revision_keeps_frozen_schema_reasoning_and_token_contract(
    serialized_trace
):
    observed = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        observed.update(json.loads(request.content))
        return httpx.Response(200, json={
            "id": "offline-revision", "model": NEMOTRON_LIGHTNING_MODEL,
            "choices": [{
                "index": 0, "finish_reason": "stop",
                "message": {"role": "assistant", "content": "{}"},
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        })

    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="synthetic",
        base_url="https://api.tokenfactory.nebius.com/v1/",
        model=NEMOTRON_LIGHTNING_MODEL,
    ), transport=httpx.MockTransport(handler))
    provider = NebiusNemotronRemediationProvider(client)
    request = M42RepairOrchestrator(ROOT, ScriptedRetryProvider([]))._request(
        serialized_trace
    ).model_copy(update={
        "repair_context": M42RepairOrchestrator(
            ROOT, ScriptedRetryProvider([])
        )._request(serialized_trace).repair_context.model_copy(update={
            "provider": provider.provider_name, "model": provider.model_name,
        })
    })

    await provider.generate_revision(
        request,
        previous_candidate={
            "rationale": "old", "patch": "old", "regression_test": "old",
            "optional_policy_artifact": None,
        },
        failure_feedback={"failure_stage": "patch_apply"},
    )

    assert observed["model"] == NEMOTRON_LIGHTNING_MODEL
    assert observed["chat_template_kwargs"] == {"enable_thinking": False}
    assert observed["max_tokens"] == 4_096
    assert observed["response_format"] == {
        "type": "json_schema",
        "json_schema": {
            "name": "repair_proposal",
            "schema": GeneratedRepairCandidate.model_json_schema(),
        },
    }
    revision = json.loads(observed["messages"][1]["content"])["revision"]
    assert revision["previous_failure"]["failure_stage"] == "patch_apply"
    assert "Produce a new revised candidate" in revision["instruction"]
    assert "Correct only what is necessary" in revision["instruction"]
    assert "concise output budgets" in revision["instruction"]


async def test_run_evidence_tamper_is_rejected(serialized_trace, tmp_path):
    path = tmp_path / "run.json"
    result = await M42RepairOrchestrator(
        ROOT, ScriptedRetryProvider([valid_raw])
    ).run(serialized_trace, evidence_path=path)
    assert isinstance(result, RepairRunSucceeded)
    path.write_text(path.read_text().replace('"status": "VERIFIED"', '"status": "FAILED"', 1))
    with pytest.raises((ValidationError, ValueError)):
        load_repair_run(path)
