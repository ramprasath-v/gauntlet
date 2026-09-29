import hashlib
from pathlib import Path

import httpx
import pytest

from gauntlet.attacks.indirect_prompt_injection import IndirectPromptInjectionAttack
from gauntlet.core.config import NebiusConfig
from gauntlet.demo.m72 import (
    LIVE_EVIDENCE_VERSION, LiveRunEvidence, M72LiveOrchestrator, _request,
)
from gauntlet.demo.m72_web import create_live_demo_app, render_live_page
from gauntlet.llm.nebius import KIMI_K27_CODE_MODEL, NebiusTokenFactoryClient
from gauntlet.remediation.fake import FakeRemediationProvider
from gauntlet.remediation.models import GeneratedRepairCandidate, combine_repair_candidate
from gauntlet.remediation.retry_models import SafeProviderCompletion
from gauntlet.remediation.provider import NebiusNemotronRemediationProvider
from gauntlet.sandbox.m4_executor import M41RepairExecutor
from gauntlet.sandbox.m4_runner import M41CommandRunner
from gauntlet.sandbox.m5_executor import M51MutationExecutor
from gauntlet.sandbox.m5_runner import M51CommandRunner
from gauntlet.sandbox.models import CommandCategory, CommandResult
from gauntlet.sandbox.workspace import repository_digest
from victims.customer_support.app import create_app


ROOT = Path(__file__).parents[1]


class DeterministicLiveProvider:
    provider_name = "nebius_token_factory"
    model_name = KIMI_K27_CODE_MODEL

    def __init__(self, output=None, error=None):
        self.output = output
        self.error = error
        self.calls = 0
        self.metadata = None

    async def generate_live_demo_candidate(self, request):
        self.calls += 1
        if self.error:
            raise self.error
        if self.output is None:
            fixture = FakeRemediationProvider()
            candidate = combine_repair_candidate(
                fixture._edit_candidate(request), fixture._test_candidate()
            )
            value = candidate.model_dump_json()
        elif isinstance(self.output, GeneratedRepairCandidate):
            value = self.output.model_dump_json()
        else:
            value = self.output
        self.metadata = SafeProviderCompletion(
            http_status=200, response_id="offline", returned_model=self.model_name,
            finish_reason="stop", content_type="str", content_length=len(value),
            prompt_tokens=100, completion_tokens=100, total_tokens=200,
        )
        return value

    def safe_completion_metadata(self):
        return self.metadata


def failed_result(workspace, category, label):
    return CommandResult(
        category=category, argv=["offline", label], exit_code=1,
        stdout="", stderr=f"{label} failed", duration_seconds=0,
        workspace_id=workspace.workspace_id,
        working_directory=str(workspace.path),
    )


class P100LeaksRunner(M41CommandRunner):
    async def p100_security(self, workspace, target_path):
        return failed_result(workspace, CommandCategory.SECURITY, "p100")


class P200RegressesRunner(M41CommandRunner):
    async def p200_utility(self, workspace, target_path):
        return failed_result(workspace, CommandCategory.UTILITY, "p200")


class MutationBypassRunner(M51CommandRunner):
    async def post_patch_mutation(self, workspace, mutation_id):
        if mutation_id == "M5-P100-INLINE":
            return failed_result(workspace, CommandCategory.SECURITY, mutation_id)
        return await super().post_patch_mutation(workspace, mutation_id)


def executor_factory(runner_type):
    return lambda root: M41RepairExecutor(root, runner=runner_type())


def mutation_factory(runner_type):
    return lambda root: M51MutationExecutor(root, runner=runner_type())


async def execute(tmp_path, provider=None, **kwargs):
    provider = provider or DeterministicLiveProvider()
    path = tmp_path / "run.json"
    result = await M72LiveOrchestrator(ROOT, provider, **kwargs).run(
        evidence_path=path
    )
    return result, provider, path


async def test_live_orchestration_uses_one_deterministic_provider_request(tmp_path):
    before = repository_digest(ROOT)
    result, provider, path = await execute(tmp_path)
    assert provider.calls == result.provider_request_count == 1
    assert result.schema_version == LIVE_EVIDENCE_VERSION
    assert result.final_verdict == "VERIFIED"
    assert result.patch_assessment.full_candidate_verified
    assert result.mutation_assessment.verified
    assert path.is_file()
    assert LiveRunEvidence.model_validate_json(path.read_text()) == result
    assert repository_digest(ROOT) == before


async def test_successful_candidate_reaches_full_independent_verification(tmp_path):
    result, _, _ = await execute(tmp_path)
    assert result.candidate_validation == "PASS"
    assert result.patch_assessment.p100_security.status == "PASS"
    assert result.patch_assessment.p200_utility.status == "PASS"
    assert result.mutation_assessment.blocked_mutation_count == 4
    assert result.repository_immutability == "PASS"


async def test_invalid_candidate_is_not_verified(tmp_path):
    result, provider, _ = await execute(
        tmp_path, DeterministicLiveProvider(output="{}")
    )
    assert provider.calls == 1
    assert result.final_verdict == "NOT_VERIFIED"
    assert result.failure_stage == "VALIDATE"
    assert result.patch_assessment is None


async def test_p100_still_leaking_is_not_verified(tmp_path):
    result, _, _ = await execute(
        tmp_path, m4_factory=executor_factory(P100LeaksRunner)
    )
    assert result.patch_assessment.p100_security.status == "FAIL"
    assert result.final_verdict == "NOT_VERIFIED"
    assert result.failure_stage == "RE_ATTACK"


async def test_mutation_bypass_is_not_verified(tmp_path):
    result, _, _ = await execute(
        tmp_path, m5_factory=mutation_factory(MutationBypassRunner)
    )
    assert result.mutation_assessment.blocked_mutation_count == 3
    assert result.final_verdict == "NOT_VERIFIED"
    assert result.failure_stage == "MUTATE"


async def test_p200_regression_is_not_verified(tmp_path):
    result, _, _ = await execute(
        tmp_path, m4_factory=executor_factory(P200RegressesRunner)
    )
    assert result.patch_assessment.p200_utility.status == "FAIL"
    assert result.final_verdict == "NOT_VERIFIED"
    assert result.failure_stage == "UTILITY"


async def test_provider_failure_is_redacted_and_replay_remains_available(tmp_path):
    secret = "api_key=never-commit-this"
    result, provider, _ = await execute(
        tmp_path, DeterministicLiveProvider(error=RuntimeError(secret))
    )
    assert provider.calls == 1
    assert result.final_verdict == "NOT_VERIFIED"
    assert "never-commit-this" not in result.failure_message
    app = create_live_demo_app(ROOT, lambda: provider, evidence_directory=tmp_path)
    routes = {route.path for route in app.routes}
    assert "/verified-replay" in routes


async def test_browser_assets_and_evidence_never_contain_credentials(tmp_path):
    marker = "super-secret-nebius-token"
    result, _, path = await execute(
        tmp_path, DeterministicLiveProvider(error=RuntimeError(f"Bearer {marker}"))
    )
    assert marker not in render_live_page()
    assert marker not in path.read_text()
    assert result.provider_request_count == 1


def test_m71_replay_remains_unchanged_and_offline():
    replay = (ROOT / "demo/gauntlet-m7.html").read_bytes()
    before = hashlib.sha256(replay).hexdigest()
    page = render_live_page()
    after = hashlib.sha256((ROOT / "demo/gauntlet-m7.html").read_bytes()).hexdigest()
    assert before == after
    assert "VIEW VERIFIED REPLAY" in page
    assert "fetch('/api/live-runs'" in page
    assert "NEBIUS_API_KEY" not in page


async def test_original_repository_and_historical_evidence_remain_immutable(tmp_path):
    source_before = repository_digest(ROOT)
    evidence_path = ROOT / "evidence/live-m42-repair-run.json"
    evidence_before = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    result, _, _ = await execute(tmp_path)
    assert result.repository_immutability == "PASS"
    assert repository_digest(ROOT) == source_before
    assert hashlib.sha256(evidence_path.read_bytes()).hexdigest() == evidence_before


async def test_kimi_live_request_uses_one_strict_combined_schema_call():
    captured = {}

    async def handler(request):
        captured.update(__import__("json").loads(request.content))
        return httpx.Response(200, json={
            "id": "offline-m72", "model": KIMI_K27_CODE_MODEL,
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "{}"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2,
                      "total_tokens": 12},
        })

    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="offline-test-key",
        base_url="https://api.tokenfactory.nebius.com/v1/",
        model=KIMI_K27_CODE_MODEL,
    ), transport=httpx.MockTransport(handler))
    provider = NebiusNemotronRemediationProvider(client)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://before"
    ) as attack_client:
        trace = (await IndirectPromptInjectionAttack(attack_client).run()).trace
    request = _request(trace.model_dump_json(), ROOT, provider)

    assert await provider.generate_live_demo_candidate(request) == "{}"
    assert captured["model"] == KIMI_K27_CODE_MODEL
    assert captured["max_tokens"] == 2048
    assert captured["response_format"]["type"] == "json_schema"
    assert captured["response_format"]["json_schema"]["name"] == "repair_candidate"
    assert "source_edit" in str(captured["response_format"]["json_schema"]["schema"])
    assert "chat_template_kwargs" not in captured
