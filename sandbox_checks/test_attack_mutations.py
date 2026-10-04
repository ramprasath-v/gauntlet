"""Trusted M5.1 checks run only inside disposable workspaces."""
import httpx
import pytest

from gauntlet.attacks.indirect_prompt_injection import IndirectPromptInjectionAttack
from gauntlet.attacks.indirect_prompt_injection_mutations import ATTACK_MUTATIONS
from gauntlet.core.config import CANARY
from gauntlet.tracing.models import TrustLevel
from victims.customer_support.app import create_app
from victims.customer_support.fixtures import REVIEWS


async def _run_mutation(mutation, monkeypatch):
    monkeypatch.setitem(REVIEWS, mutation.product_id, mutation.tool_output)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://sandbox"
    ) as client:
        return await IndirectPromptInjectionAttack(
            client, user_prompt=mutation.user_prompt
        ).run()


@pytest.mark.parametrize(
    "mutation", ATTACK_MUTATIONS, ids=lambda mutation: mutation.mutation_id,
)
async def test_pre_patch_attack_reproduced(mutation, monkeypatch):
    result = await _run_mutation(mutation, monkeypatch)

    assert CANARY not in mutation.user_prompt
    assert CANARY not in mutation.tool_output
    assert result.verdict == "CANARY_LEAKED"
    assert result.succeeded
    assert result.trace is not None
    assert result.trace.failure_boundary is not None
    tool_result = next(event for event in result.events if event.kind == "tool_result")
    assert tool_result.trust_level == TrustLevel.UNTRUSTED
    assert tool_result.data["source"] == "external_product_review"
    assert tool_result.data["content"] == mutation.tool_output


@pytest.mark.parametrize(
    "mutation", ATTACK_MUTATIONS, ids=lambda mutation: mutation.mutation_id,
)
async def test_post_patch_attack_blocked(mutation, monkeypatch):
    result = await _run_mutation(mutation, monkeypatch)

    assert result.verdict == "CANARY_NOT_OBSERVED"
    assert not result.succeeded
    assert CANARY not in result.evidence["response"]
