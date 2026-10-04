from pathlib import Path
import json

import httpx
import pytest

from gauntlet.contracts.p400_live import P400LiveEvidence, build_p400_live_envelope
from gauntlet.contracts.p400_live_repair import P400LiveRepairEvidence
from gauntlet.contracts.p400_true_live import (
    P400_NEMOTRON_BASE_URL,
    P400_NEMOTRON_MODEL,
    P400LiveProofEvidence,
    P400NemotronProvider,
)
from gauntlet.core.config import NebiusConfig
from gauntlet.demo.m8_web import create_m8_demo_app
from gauntlet.llm.nebius import KIMI_K27_CODE_MODEL, NebiusTokenFactoryClient
from gauntlet.remediation.models import GeneratedEditCandidate, StructuredSourceEdit
from gauntlet.remediation.retry_models import SafeProviderCompletion
from gauntlet.remediation.contract_verification import TrustedGateExecutionError
from gauntlet.sandbox.workspace import repository_digest


ROOT = Path(__file__).parents[1]


class FakeNemotron:
    provider_name = "nebius_token_factory"
    model_name = P400_NEMOTRON_MODEL

    def __init__(self, response: str = "Here are five concise app names.") -> None:
        self.response = response
        self.requests = []

    async def generate_response(self, envelope) -> str:
        self.requests.append(envelope)
        return self.response

    def completion_metadata(self):
        return {
            "http_status": 200,
            "finish_reason": "stop",
            "prompt_tokens": 100,
            "completion_tokens": 20,
            "total_tokens": 120,
        }


class FailingNemotron(FakeNemotron):
    async def generate_response(self, envelope) -> str:
        self.requests.append(envelope)
        raise RuntimeError("synthetic provider failure")


class FakeKimiPatch:
    provider_name = "nebius_token_factory"
    model_name = KIMI_K27_CODE_MODEL

    def __init__(self, *, reject: bool = False) -> None:
        self.reject = reject
        self.requests = []

    async def generate_edit(self, request) -> str:
        self.requests.append(request)
        source = request.source_context
        lines = source.source_text.splitlines()
        if self.reject:
            edit = StructuredSourceEdit(
                target_path=source.repository_relative_path,
                target_symbol=source.target_symbol,
                source_hash=source.source_hash,
                start_line=next(
                    index for index, line in enumerate(lines, 1)
                    if "event_type=NormalizedEventType.DATA_READ" in line
                ),
                delete_line_count=1,
                replacement_lines=[
                    "                event_type=NormalizedEventType.DATA_READ,"
                ],
            )
        else:
            loop = lines.index("        for item in context_items:") + 1
            start = lines.index("        context_event_ids: list[str] = []") + 1
            output = lines.index("        output = NormalizedExecutionEvent(") + 1
            loop_body = lines[loop:output - 1]
            edit = StructuredSourceEdit(
                target_path=source.repository_relative_path,
                target_symbol=source.target_symbol,
                source_hash=source.source_hash,
                start_line=start,
                delete_line_count=output - start,
                replacement_lines=[
                    "        from gauntlet.contracts.context_authorization import (",
                    "            authorize_context_item,",
                    "        )",
                    "        authorized_context_items = tuple(",
                    "            item for item in context_items",
                    "            if authorize_context_item(",
                    "                item,",
                    "                authorization_grants,",
                    "                active_principal=principal,",
                    "                active_purpose=active_purpose,",
                    "                activated_dimensions=(",
                    "                    activated_personalization_dimensions",
                    "                ),",
                    "            ).authorized",
                    "        )",
                    "        context_event_ids: list[str] = []",
                    "        for item in authorized_context_items:",
                    *loop_body,
                ],
            )
        return GeneratedEditCandidate(
            rationale="Enforce the contract before context enters the model.",
            source_edit=edit,
            optional_policy_artifact=None,
        ).model_dump_json()

    def safe_completion_metadata(self):
        return SafeProviderCompletion(
            http_status=200,
            response_id="fake-kimi-p400",
            returned_model=self.model_name,
            finish_reason="stop",
            content_type="str",
            content_length=500,
            prompt_tokens=200,
            completion_tokens=100,
            total_tokens=300,
        )


async def _post(app, path: str):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://m8-local"
    ) as client:
        return await client.post(path)


async def _get(app, path: str):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://m8-local"
    ) as client:
        return await client.get(path)


@pytest.mark.asyncio
async def test_nemotron_attack_adapter_uses_regional_endpoint_and_no_think():
    requests = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={
            "id": "fake-p400-nemotron",
            "object": "chat.completion",
            "model": P400_NEMOTRON_MODEL,
            "choices": [{
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": "App names"},
            }],
            "usage": {
                "prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12,
            },
        })

    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="synthetic-secret",
        base_url=P400_NEMOTRON_BASE_URL,
        model=P400_NEMOTRON_MODEL,
    ), transport=httpx.MockTransport(handler))
    provider = P400NemotronProvider(client)
    output = await provider.generate_response(build_p400_live_envelope(run_id="run"))

    assert output == "App names"
    assert len(requests) == 1
    assert str(requests[0].url) == P400_NEMOTRON_BASE_URL + "chat/completions"
    payload = json.loads(requests[0].content)
    assert payload["model"] == P400_NEMOTRON_MODEL
    assert payload["max_tokens"] == 2_048
    assert payload["messages"][0]["content"].startswith("/no_think\n")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "attack_wording",
    ["Tamil-inspired names", "Five neutral productivity names"],
)
async def test_true_live_p400_attack_patch_proof_is_three_single_calls(
    tmp_path, attack_wording,
):
    before = repository_digest(ROOT)
    attack = FakeNemotron(attack_wording)
    patch = FakeKimiPatch()
    proof = FakeNemotron("Five repaired-sandbox app names")
    app = create_m8_demo_app(
        ROOT,
        p400_attack_provider_factory=lambda: (attack, ()),
        p400_patch_provider_factory=lambda: (patch, ()),
        p400_proof_provider_factory=lambda: (proof, ()),
        p400_live_evidence_directory=tmp_path,
    )

    attack_response = await _post(app, "/api/p400/live-runs")
    assert attack_response.status_code == 200
    attacked = attack_response.json()
    assert attacked["model"] == P400_NEMOTRON_MODEL
    assert attacked["provider_requests"] == 1
    assert attacked["verdict"] == "VIOLATED"
    assert attacked["violation_code"] == "UNJUSTIFIED_PERSONALIZATION_CONTEXT"
    assert attacked["context_entered_model"] is True
    assert attacked["verdict_owner"] == "Gauntlet deterministic evaluator"
    assert attacked["model_response"] == attack_wording
    assert len(attack.requests) == 1

    run_id = attacked["run_id"]
    patch_response = await _post(app, f"/api/p400/live-runs/{run_id}/patch")
    assert patch_response.status_code == 200
    patched = patch_response.json()
    assert patched["model"] == KIMI_K27_CODE_MODEL
    assert patched["provider_requests"] == 1
    assert patched["candidate_received"] is True
    assert patched["candidate_validation"] == "PASS"
    assert patched["accepted_for_verification"] is True
    assert len(patch.requests) == 1

    proof_response = await _post(app, f"/api/p400/live-runs/{run_id}/proof")
    assert proof_response.status_code == 200, proof_response.text
    proved = proof_response.json()
    assert proved["model"] == P400_NEMOTRON_MODEL
    assert proved["provider_requests"] == 1
    assert proved["transmitted_context_ids"] == []
    assert proved["model_response"] == "Five repaired-sandbox app names"
    assert proved["live_post_repair"] == "PASS"
    assert proved["deterministic_matrix_status"] == "PASS"
    assert proved["final_status"] == "VERIFIED"
    assert all(proved["matrix"].values())
    assert len(proof.requests) == 1
    assert proof.requests[0].transmitted_context_items == []
    assert repository_digest(ROOT) == before
    attack_paths = list((tmp_path / "attack").glob("live-*.json"))
    repair_paths = list((tmp_path / "repair").glob("live-*.json"))
    proof_paths = list((tmp_path / "proof").glob("live-*.json"))
    assert len(attack_paths) == len(repair_paths) == len(proof_paths) == 1
    P400LiveEvidence.model_validate_json(attack_paths[0].read_text())
    P400LiveRepairEvidence.model_validate_json(repair_paths[0].read_text())
    P400LiveProofEvidence.model_validate_json(proof_paths[0].read_text())


@pytest.mark.asyncio
async def test_rejected_live_patch_cannot_call_proof(tmp_path):
    attack = FakeNemotron()
    patch = FakeKimiPatch(reject=True)
    proof = FakeNemotron()
    app = create_m8_demo_app(
        ROOT,
        p400_attack_provider_factory=lambda: (attack, ()),
        p400_patch_provider_factory=lambda: (patch, ()),
        p400_proof_provider_factory=lambda: (proof, ()),
        p400_live_evidence_directory=tmp_path,
    )
    attacked = (await _post(app, "/api/p400/live-runs")).json()
    patched = (
        await _post(app, f"/api/p400/live-runs/{attacked['run_id']}/patch")
    ).json()
    assert patched["candidate_validation"] == "FAIL"
    assert patched["accepted_for_verification"] is False
    blocked = await _post(
        app, f"/api/p400/live-runs/{attacked['run_id']}/proof"
    )
    assert blocked.status_code == 409
    assert len(proof.requests) == 0


@pytest.mark.asyncio
async def test_trusted_gate_exception_is_exposed_as_sanitized_patch_diagnostic(
    tmp_path, monkeypatch,
):
    async def fail_cross_subject(workspace, *, contract):
        raise TrustedGateExecutionError(
            "cross_subject_verify", RuntimeError("sandbox module raised safely")
        )

    monkeypatch.setattr(
        "gauntlet.contracts.p400_live_repair.verify_all_p400_families",
        fail_cross_subject,
    )
    attack = FakeNemotron()
    patch = FakeKimiPatch()
    app = create_m8_demo_app(
        ROOT,
        p400_attack_provider_factory=lambda: (attack, ()),
        p400_patch_provider_factory=lambda: (patch, ()),
        p400_live_evidence_directory=tmp_path,
    )
    attacked = (await _post(app, "/api/p400/live-runs")).json()
    response = await _post(
        app, f"/api/p400/live-runs/{attacked['run_id']}/patch"
    )
    assert response.status_code == 200
    rejected = response.json()
    assert rejected["candidate_received"] is True
    assert rejected["candidate_id"]
    assert rejected["edit_artifact"].endswith(".json")
    assert rejected["candidate_validation"] == "PASS"
    assert rejected["accepted_for_verification"] is False
    assert rejected["failure_stage"] == "sandbox_verification"
    assert rejected["failure_substage"] == "cross_subject_verify"
    assert rejected["error_type"] == "RuntimeError"
    assert rejected["failure_message"] == "sandbox module raised safely"
    assert len(patch.requests) == 1


@pytest.mark.asyncio
async def test_provider_failure_is_truthful_and_never_falls_back(tmp_path):
    attack = FailingNemotron()
    patch = FakeKimiPatch()
    app = create_m8_demo_app(
        ROOT,
        p400_attack_provider_factory=lambda: (attack, ()),
        p400_patch_provider_factory=lambda: (patch, ()),
        p400_live_evidence_directory=tmp_path,
    )
    response = await _post(app, "/api/p400/live-runs")
    assert response.status_code == 200
    failed = response.json()
    assert failed["provider_status"] == "FAIL"
    assert failed["verdict"] == "NOT_RUN"
    assert failed["model_response"] is None
    blocked = await _post(app, f"/api/p400/live-runs/{failed['run_id']}/patch")
    assert blocked.status_code == 409
    assert len(attack.requests) == 1
    assert len(patch.requests) == 0


@pytest.mark.asyncio
async def test_p400_selection_is_zero_call_and_true_live_controls_are_rendered():
    attack = FakeNemotron()
    patch = FakeKimiPatch()
    proof = FakeNemotron()
    app = create_m8_demo_app(
        ROOT,
        p400_attack_provider_factory=lambda: (attack, ()),
        p400_patch_provider_factory=lambda: (patch, ()),
        p400_proof_provider_factory=lambda: (proof, ()),
    )
    page = (await _get(app, "/")).text
    assert 'id="run-p400-live-attack"' in page
    assert 'id="run-p400-live-patch" disabled' in page
    assert 'id="run-p400-live-proof" disabled' in page
    assert "NVIDIA Nemotron Super via Nebius Token Factory" in page
    assert "Kimi-K2.7-Code via Nebius Token Factory" in page
    assert "LOAD RECORDED EVIDENCE" in page
    assert "/api/p400/live-runs/'+p400LiveRunId+'/proof" in page
    assert attack.requests == []
    assert patch.requests == []
    assert proof.requests == []
