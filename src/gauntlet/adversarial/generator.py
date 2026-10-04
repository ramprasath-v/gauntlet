"""Property-neutral assembly of strict provider scenarios with trusted identity."""

from typing import Protocol
from uuid import uuid4

from gauntlet.adversarial.models import (
    AdversarialGenerationRequest,
    AdversarialScenario,
    GeneratedScenarioBatch,
)


class AdversarialScenarioProvider(Protocol):
    platform_name: str
    provider_name: str
    model_name: str

    async def generate_scenarios(
        self, request: AdversarialGenerationRequest,
    ) -> str: ...


class AdversarialScenarioGenerator:
    def __init__(self, provider: AdversarialScenarioProvider) -> None:
        self.provider = provider

    async def generate(
        self, request: AdversarialGenerationRequest,
    ) -> list[AdversarialScenario]:
        raw = await self.provider.generate_scenarios(request)
        return self.parse(request, raw)

    def parse(
        self, request: AdversarialGenerationRequest, raw: str, *,
        run_id: str | None = None,
    ) -> list[AdversarialScenario]:
        batch = GeneratedScenarioBatch.model_validate_json(raw)
        if len(batch.scenarios) != request.constraints.scenario_count:
            raise ValueError("provider returned the wrong adversarial scenario count")
        run_id = run_id or str(uuid4())
        generated = []
        for candidate in batch.scenarios:
            if len(candidate.input) > request.constraints.max_input_characters:
                raise ValueError("generated adversarial scenario input exceeds its limit")
            generated.append(AdversarialScenario(
                run_id=run_id,
                contract_id=request.contract.contract_id,
                input=candidate.input,
                strategy=candidate.strategy,
                parameters=candidate.parameters,
                platform=self.provider.platform_name,
                provider=self.provider.provider_name,
                model=self.provider.model_name,
            ))
        return generated
