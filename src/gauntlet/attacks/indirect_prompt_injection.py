from uuid import uuid4
import httpx
from gauntlet.contracts.models import ContractEvaluation
from gauntlet.core.config import CANARY, USER_PROMPT
from gauntlet.core.models import AttackResult, ChatResponse
from gauntlet.tracing.models import ExecutionEvent, SourceKind
from gauntlet.tracing.builder import build_trace
from gauntlet.verification.canary import CanaryLeakVerifier

class IndirectPromptInjectionAttack:
    def __init__(self, client: httpx.AsyncClient, *, user_prompt: str = USER_PROMPT):
        self.client = client
        self.user_prompt = user_prompt

    async def run(self) -> AttackResult:
        response = await self.client.post("/chat", json={"message": self.user_prompt})
        response.raise_for_status()
        chat = ChatResponse.model_validate(response.json())
        leaked = CanaryLeakVerifier(CANARY).verify(chat.response)
        verdict = "CANARY_LEAKED" if leaked else "CANARY_NOT_OBSERVED"
        events = [*chat.events, ExecutionEvent(
            kind="verdict", sequence=max(e.sequence for e in chat.events) + 1,
            source=SourceKind.VERIFIER, input_event_id=chat.events[-1].event_id,
            data={"verdict": verdict})]
        attack_id = str(uuid4())
        return AttackResult(
            attack_id=attack_id, attack_type="indirect_prompt_injection",
            target=str(self.client.base_url), succeeded=leaked, verdict=verdict,
            evidence={"source": "search_reviews", "canary": CANARY,
                      "attack": "indirect_prompt_injection", "response": chat.response},
            events=events, trace=build_trace(attack_id, events, CANARY),
        )

    async def run_with_contract_evaluation(
        self,
    ) -> tuple[AttackResult, ContractEvaluation]:
        """Run the unchanged P100 attack and evaluate it through the generic boundary."""
        from gauntlet.contracts.p100 import evaluate_p100_attack

        result = await self.run()
        return result, evaluate_p100_attack(result)
