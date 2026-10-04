"""Small strict models for model-proposed adversarial scenarios."""

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import Field, JsonValue, field_validator, model_validator

from gauntlet.contracts.models import SecurityContract, StrictModel


class GenerationConstraints(StrictModel):
    scenario_count: int = Field(ge=1, le=5)
    max_input_characters: int = Field(default=500, ge=20, le=2_000)


class ScenarioParameterSpec(StrictModel):
    """Property-neutral declaration of one executable scenario parameter."""

    name: str = Field(min_length=1, max_length=100)
    json_type: Literal["string", "integer", "number", "boolean"]
    required: bool = True
    description: str = Field(min_length=1, max_length=500)
    enum: list[JsonValue] | None = Field(default=None, min_length=1, max_length=20)
    minimum: int | float | None = None


class ScenarioExecutionContract(StrictModel):
    """Canonical capability argument shape shared by generation and adapters."""

    capability: str = Field(min_length=1, max_length=128)
    parameters: list[ScenarioParameterSpec] = Field(min_length=1, max_length=20)
    allow_additional_parameters: bool = False

    @model_validator(mode="after")
    def unique_parameter_names(self) -> "ScenarioExecutionContract":
        names = [parameter.name for parameter in self.parameters]
        if len(names) != len(set(names)):
            raise ValueError("scenario execution parameter names must be unique")
        return self


class AdversarialGenerationRequest(StrictModel):
    contract: SecurityContract
    seed_scenario: str = Field(min_length=1, max_length=2_000)
    capability_context: dict[str, JsonValue]
    execution_contract: ScenarioExecutionContract
    constraints: GenerationConstraints


class GeneratedScenarioCandidate(StrictModel):
    """Untrusted provider content; it contains no verdict or provenance fields."""

    input: str = Field(min_length=1, max_length=2_000)
    strategy: str | None = Field(default=None, min_length=1, max_length=120)
    parameters: dict[str, JsonValue]


class GeneratedScenarioBatch(StrictModel):
    scenarios: list[GeneratedScenarioCandidate] = Field(min_length=1, max_length=5)

    @model_validator(mode="after")
    def unique_inputs(self) -> "GeneratedScenarioBatch":
        inputs = [scenario.input for scenario in self.scenarios]
        if len(inputs) != len(set(inputs)):
            raise ValueError("generated adversarial scenario inputs must be unique")
        return self


def generated_scenario_batch_schema(
    request: AdversarialGenerationRequest,
) -> dict[str, Any]:
    """Build strict provider output from the canonical execution contract."""
    schema = GeneratedScenarioBatch.model_json_schema()
    candidate = schema["$defs"]["GeneratedScenarioCandidate"]
    parameter_properties: dict[str, Any] = {}
    required: list[str] = []
    for parameter in request.execution_contract.parameters:
        field_schema: dict[str, Any] = {
            "type": parameter.json_type,
            "description": parameter.description,
        }
        if parameter.enum is not None:
            field_schema["enum"] = parameter.enum
        if parameter.minimum is not None:
            field_schema["minimum"] = parameter.minimum
        parameter_properties[parameter.name] = field_schema
        if parameter.required:
            required.append(parameter.name)
    parameters_schema: dict[str, Any] = {
        "type": "object",
        "properties": parameter_properties,
        "additionalProperties": request.execution_contract.allow_additional_parameters,
    }
    if required:
        parameters_schema["required"] = required
    candidate["properties"]["parameters"] = parameters_schema
    return schema


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
