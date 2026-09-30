"""Small strict models for model-proposed adversarial scenarios."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import Field, JsonValue, field_validator, model_validator

from gauntlet.contracts.models import SecurityContract, StrictModel


class GenerationConstraints(StrictModel):
    scenario_count: int = Field(ge=1, le=5)
    max_input_characters: int = Field(default=500, ge=20, le=2_000)


class AdversarialGenerationRequest(StrictModel):
    contract: SecurityContract
    seed_scenario: str = Field(min_length=1, max_length=2_000)
    capability_context: dict[str, JsonValue]
    constraints: GenerationConstraints


class GeneratedScenarioCandidate(StrictModel):
    """Untrusted provider content; it contains no verdict or provenance fields."""

    input: str = Field(min_length=1, max_length=2_000)
    strategy: str | None = Field(default=None, min_length=1, max_length=120)
    parameters: dict[str, JsonValue] = Field(default_factory=dict)


class GeneratedScenarioBatch(StrictModel):
    scenarios: list[GeneratedScenarioCandidate] = Field(min_length=1, max_length=5)

    @model_validator(mode="after")
    def unique_inputs(self) -> "GeneratedScenarioBatch":
        inputs = [scenario.input for scenario in self.scenarios]
        if len(inputs) != len(set(inputs)):
            raise ValueError("generated adversarial scenario inputs must be unique")
        return self


class AdversarialScenario(StrictModel):
    scenario_id: str = Field(default_factory=lambda: str(uuid4()))
    run_id: str
    contract_id: str = Field(min_length=1, max_length=128)
    input: str = Field(min_length=1, max_length=2_000)
    strategy: str | None = Field(default=None, min_length=1, max_length=120)
    parameters: dict[str, JsonValue] = Field(default_factory=dict)
    platform: str = Field(min_length=1, max_length=100)
    provider: str = Field(min_length=1, max_length=100)
    model: str = Field(min_length=1, max_length=200)
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("scenario_id", "run_id")
    @classmethod
    def valid_ids(cls, value: str) -> str:
        UUID(value)
        return value
