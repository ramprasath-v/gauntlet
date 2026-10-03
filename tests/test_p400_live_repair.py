from hashlib import sha256
import json
from pathlib import Path

import httpx
import pytest

from gauntlet.contracts.p400_live import P400_LIVE_MODEL
from gauntlet.contracts.p400_live_repair import (
    P400LiveRepairEvidence,
    build_live_p400_repair_request,
    load_p400_live_attack,
    run_live_p400_repair,
)
from gauntlet.demo.m8 import run_p400_verified_proof
from gauntlet.core.config import NebiusConfig
from gauntlet.llm.nebius import NebiusTokenFactoryClient
from gauntlet.remediation.models import (
    GeneratedEditCandidate,
    StructuredSourceEdit,
)
from gauntlet.remediation.contract_handoff import to_remediation_request
from gauntlet.remediation.prompt import build_edit_messages
from gauntlet.remediation.provider import (
    EDIT_SCHEMA_NAME,
    NebiusNemotronRemediationProvider,
)
from gauntlet.sandbox.workspace import repository_digest


ROOT = Path(__file__).parents[1]
LIVE_ATTACK = (
    ROOT / "evidence" / "p400-live"
    / "live-f43d28c4-c2ba-4884-a532-e3dd98d42b1d.json"
)


def _file_digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


class CandidateProvider:
    provider_name = "fake_nebius"
    model_name = P400_LIVE_MODEL

    def __init__(self, kind: str = "success") -> None:
        self.kind = kind
        self.requests = []

    async def generate_edit(self, request):
        self.requests.append(request)
        if self.kind == "malformed":
            return "not-json"
        source = request.source_context
        lines = source.source_text.splitlines()
        loop = lines.index("        for item in context_items:") + 1
        start = lines.index("        context_event_ids: list[str] = []") + 1
        output = lines.index("        output = NormalizedExecutionEvent(") + 1
        loop_body = lines[loop:output - 1]
        replacement = [
            "        authorized_context_items = tuple(",
            "            item for item in context_items",
            "            if item.source_trust == TrustClassification.TRUSTED",
            "            and any(",
            "                grant.context_id == item.context_id",
            "                and grant.attribute_id == item.attribute_id",
            "                and grant.subject_id == item.subject_id == principal",
            "                and grant.provenance_id == item.provenance_id",
            "                and grant.policy_id == item.policy_id",
            "                and grant.allowed_purpose == active_purpose",
            "                and grant.grant_state == \"ACTIVE\"",
            "                and item.personalization_dimension",
            "                    in activated_personalization_dimensions",
            "                for grant in authorization_grants",
            "            )",
            "        )",
            "        context_event_ids: list[str] = []",
            "        for item in authorized_context_items:",
            *loop_body,
        ]
        updates = dict(
            target_path=source.repository_relative_path,
            target_symbol=source.target_symbol,
            source_hash=source.source_hash,
            start_line=start,
            delete_line_count=output - start,
            replacement_lines=replacement,
        )
        if self.kind == "unauthorized_path":
            updates["target_path"] = "victims/refund_support/agent.py"
        elif self.kind == "unauthorized_symbol":
            updates["target_symbol"] = "PersonalizationAgent.other"
        elif self.kind == "stale_hash":
            updates["source_hash"] = "0" * 64
        elif self.kind == "range_split":
            updates.update(
                start_line=next(
                    index for index, line in enumerate(lines, 1)
                    if "event_type=NormalizedEventType.DATA_READ" in line
                ),
                delete_line_count=1,
                replacement_lines=["                event_type=NormalizedEventType.DATA_READ,"],
            )
        elif self.kind == "invalid_syntax":
            updates.update(
                start_line=start,
                delete_line_count=output - start,
                replacement_lines=[
                    "        context_event_ids: list[str] = []",
                    "        for item in context_items",
                    *loop_body,
                ],
            )
        elif self.kind == "suppress_all":
            updates.update(
                start_line=start,
                delete_line_count=output - start,
                replacement_lines=[
                    "        context_event_ids: list[str] = []",
                    "        for item in ():",
                    *loop_body,
                ],
            )
        return GeneratedEditCandidate(
            rationale="Enforce the supplied contract at the context boundary.",
            source_edit=StructuredSourceEdit(**updates),
            optional_policy_artifact=None,
        ).model_dump_json()

    def safe_completion_metadata(self):
        return None


async def _run(tmp_path, kind="success"):
    provider = CandidateProvider(kind)
    evidence, path = await run_live_p400_repair(
        live_attack_path=LIVE_ATTACK,
        provider=provider,
        repository_root=ROOT,
        evidence_directory=tmp_path,
    )
    return provider, evidence, path


async def test_one_call_live_repair_uses_generic_request_and_all_p400_gates(tmp_path):
    attack_digest = _file_digest(LIVE_ATTACK)
    before = repository_digest(ROOT)
    provider, evidence, path = await _run(tmp_path)
    restored = P400LiveRepairEvidence.model_validate_json(path.read_text())

    assert restored == evidence
    assert len(provider.requests) == evidence.provider_request_count == 1
    assert evidence.automatic_retries == 0
    assert evidence.model_switches == 0
    assert evidence.contract_request == build_live_p400_repair_request(
        live_attack=load_p400_live_attack(LIVE_ATTACK), repository_root=ROOT
    ).model_copy(update={"request_id": evidence.contract_request.request_id,
                         "source_context": evidence.contract_request.source_context})
    assert evidence.contract_request.source_context.repository_relative_path == (
        "victims/personalization/agent.py"
    )
    assert evidence.contract_request.source_context.target_symbol == (
        "PersonalizationAgent.respond"
    )
    assert evidence.candidate_validation == "PASS"
    assert evidence.sandbox_assessment is not None
    assert evidence.sandbox_assessment.verdict == "VERIFIED"
    assert evidence.live_repair_status == "VERIFIED"
    cases = {
        case.case_id: case
        for case in evidence.sandbox_assessment.reverification.cases
    }
    assert cases["P400-CROSS-SUBJECT"].expected_behavior_observed
    assert cases["unjustified_personalization_blocked"].expected_behavior_observed
    assert cases["poisoned_personal_context_blocked"].expected_behavior_observed
    assert cases["explicit_personalization_preserved"].expected_behavior_observed
    assert cases["authorized_personalization_preserved"].expected_behavior_observed
    assert cases["authorized_persistent_memory_preserved"].expected_behavior_observed
    assert cases["mixed_persistent_memory_filtered_item_by_item"].expected_behavior_observed
    assert evidence.repository_immutability == "PASS"
    assert evidence.historical_evidence_immutability == "PASS"
    assert repository_digest(ROOT) == before
    assert _file_digest(LIVE_ATTACK) == attack_digest


async def test_malformed_candidate_is_rejected_without_fallback(tmp_path):
    provider, evidence, _ = await _run(tmp_path, "malformed")

    assert len(provider.requests) == 1
    assert evidence.candidate_validation == "FAIL"
    assert evidence.validation_failure["failure_code"] == "malformed_edit_candidate"
    assert evidence.sandbox_assessment is None
    assert evidence.live_repair_status == "REJECTED"
    assert evidence.derived_patch is None


@pytest.mark.parametrize("kind", ["unauthorized_path", "unauthorized_symbol"])
async def test_unauthorized_target_is_rejected(tmp_path, kind):
    _, evidence, _ = await _run(tmp_path, kind)

    assert evidence.candidate_validation == "FAIL"
    assert evidence.validation_failure["failure_stage"] == "patch_authorization"
    assert evidence.validation_failure["failure_code"] == "unauthorized_edit_target"
    assert evidence.live_repair_status == "REJECTED"


async def test_stale_source_hash_is_rejected(tmp_path):
    _, evidence, _ = await _run(tmp_path, "stale_hash")

    assert evidence.candidate_validation == "FAIL"
    assert evidence.validation_failure["failure_stage"] == "source_identity"
    assert evidence.validation_failure["failure_code"] == (
        "candidate_source_hash_mismatch"
    )


async def test_range_split_is_rejected_without_correction(tmp_path):
    _, evidence, _ = await _run(tmp_path, "range_split")

    assert evidence.candidate_validation == "FAIL"
    assert evidence.validation_failure["failure_stage"] == "patch_authorization"
    assert evidence.validation_failure["failure_code"] in {
        "edit_range_splits_python_construct",
        "edit_range_splits_compound_statement",
    }


async def test_syntax_invalid_candidate_is_rejected_before_sandbox(tmp_path):
    _, evidence, _ = await _run(tmp_path, "invalid_syntax")

    assert evidence.candidate_validation == "FAIL"
    assert evidence.validation_failure["failure_stage"] == "candidate_validation"
    assert evidence.validation_failure["failure_code"] == (
        "reconstructed_source_invalid_python"
    )
    assert evidence.sandbox_assessment is None


async def test_suppression_patch_reaches_sandbox_and_fails_utility(tmp_path):
    _, evidence, _ = await _run(tmp_path, "suppress_all")

    assert evidence.candidate_validation == "PASS"
    assert evidence.sandbox_assessment is not None
    assert evidence.sandbox_assessment.compilation.passed
    assert evidence.sandbox_assessment.verdict == "NOT_VERIFIED"
    cases = {
        case.case_id: case
        for case in evidence.sandbox_assessment.reverification.cases
    }
    assert not cases["explicit_personalization_preserved"].expected_behavior_observed
    assert not cases["authorized_personalization_preserved"].expected_behavior_observed
    assert not cases["authorized_persistent_memory_preserved"].expected_behavior_observed
    assert evidence.live_repair_status == "REJECTED"


async def test_deterministic_known_good_proof_remains_separate_and_zero_provider(
    monkeypatch,
):
    async def forbidden_complete(*args, **kwargs):
        raise AssertionError("deterministic proof contacted a provider")

    monkeypatch.setattr(NebiusTokenFactoryClient, "complete", forbidden_complete)
    proof = await run_p400_verified_proof(ROOT)

    assert proof.mode == "VERIFIED_PROOF"
    assert proof.provider_requests == 0
    assert proof.verdict == "VERIFIED"


def test_live_repair_prompt_is_generic_and_contains_no_known_good_patch():
    request = build_live_p400_repair_request(
        live_attack=load_p400_live_attack(LIVE_ATTACK), repository_root=ROOT
    )
    remediation = to_remediation_request(
        request, provider="nebius_token_factory", model=P400_LIVE_MODEL
    )
    messages = build_edit_messages(remediation)
    serialized = json.dumps(messages)

    assert "contract_violation" in serialized
    assert "PersonalizationAgent.respond" in serialized
    assert request.source_context.source_hash in serialized
    assert "authorized_context_items" not in serialized
    assert "check cultural_language_preference" not in serialized.lower()
    assert "required_output_schema" in serialized


async def test_real_nebius_adapter_path_makes_one_structured_edit_call_only(tmp_path):
    requests = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={
            "id": "p400-live-repair-mock",
            "object": "chat.completion",
            "model": P400_LIVE_MODEL,
            "choices": [{
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": "not-json"},
            }],
            "usage": {
                "prompt_tokens": 200,
                "completion_tokens": 4,
                "total_tokens": 204,
            },
        })

    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key="test-secret",
        base_url="https://api.tokenfactory.nebius.com/v1/",
        model=P400_LIVE_MODEL,
    ), transport=httpx.MockTransport(handler))
    provider = NebiusNemotronRemediationProvider(client)
    evidence, _ = await run_live_p400_repair(
        live_attack_path=LIVE_ATTACK,
        provider=provider,
        repository_root=ROOT,
        evidence_directory=tmp_path,
        credential_values=("test-secret",),
    )

    assert len(requests) == evidence.provider_request_count == 1
    assert requests[0]["model"] == P400_LIVE_MODEL
    assert requests[0]["max_tokens"] == provider.max_edit_tokens
    assert requests[0]["response_format"]["type"] == "json_schema"
    assert requests[0]["response_format"]["json_schema"]["name"] == (
        EDIT_SCHEMA_NAME
    )
    assert evidence.candidate_validation == "FAIL"
    assert evidence.live_repair_status == "REJECTED"
