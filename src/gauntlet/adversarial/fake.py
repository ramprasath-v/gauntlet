"""Deterministic provider substitute for offline generator tests."""

from gauntlet.adversarial.models import (
    AdversarialGenerationRequest,
    GeneratedScenarioBatch,
)


class FakeAdversarialScenarioProvider:
    platform_name = "offline"
    provider_name = "deterministic_adversarial_fixture"
    model_name = "fixed-scenario-batch-v1"

    def __init__(self, batch: GeneratedScenarioBatch) -> None:
        self.batch = batch
        self.requests: list[AdversarialGenerationRequest] = []

    async def generate_scenarios(
        self, request: AdversarialGenerationRequest,
    ) -> str:
        self.requests.append(request)
        return self.batch.model_dump_json()
