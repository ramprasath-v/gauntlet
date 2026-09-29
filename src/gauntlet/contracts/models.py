"""Small serializable domain model for execution contracts and their results."""

from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NormalizedEventType(StrEnum):
    USER_INPUT = "USER_INPUT"
    DATA_READ = "DATA_READ"
    TOOL_AVAILABLE = "TOOL_AVAILABLE"
    TOOL_CALL = "TOOL_CALL"
    TOOL_RESULT = "TOOL_RESULT"
    APPROVAL = "APPROVAL"
    IDENTITY_CONTEXT = "IDENTITY_CONTEXT"
    AGENT_DELEGATION = "AGENT_DELEGATION"
    EXTERNAL_EFFECT = "EXTERNAL_EFFECT"
    MODEL_OUTPUT = "MODEL_OUTPUT"
    VERIFICATION_RESULT = "VERIFICATION_RESULT"


class TrustClassification(StrEnum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    UNKNOWN = "UNKNOWN"


class DataClassification(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SENSITIVE = "SENSITIVE"
    SECRET = "SECRET"
    UNKNOWN = "UNKNOWN"


class NormalizedExecutionEvent(StrictModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    event_type: NormalizedEventType
    sequence: int = Field(ge=0)
    timestamp: datetime | None = None
    agent: str | None = None
    principal: str | None = None
    tool_name: str | None = None
    arguments: dict[str, JsonValue] = Field(default_factory=dict)
    source: str | None = None
    trust_classification: TrustClassification = TrustClassification.UNKNOWN
    data_classification: DataClassification = DataClassification.UNKNOWN
    result: JsonValue | None = None
    effect: dict[str, JsonValue] = Field(default_factory=dict)
    input_event_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class NormalizedExecutionTrace(StrictModel):
    trace_id: str = Field(min_length=1)
    events: list[NormalizedExecutionEvent] = Field(min_length=1)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def ordered_unique_events(self) -> "NormalizedExecutionTrace":
        event_ids = [event.event_id for event in self.events]
        sequences = [event.sequence for event in self.events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("normalized trace event IDs must be unique")
        if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
            raise ValueError("normalized trace sequences must be strictly increasing")
        known_ids = set(event_ids)
        if any(parent not in known_ids for event in self.events for parent in event.input_event_ids):
            raise ValueError("normalized trace input links must reference trace events")
        return self


class EventCondition(StrictModel):
    """A declared event shape relevant to a property, not a general-purpose DSL."""

    event_type: NormalizedEventType
    field_equals: dict[str, JsonValue] = Field(default_factory=dict)


class SecurityContract(StrictModel):
    contract_id: str = Field(min_length=1, max_length=128)
    description: str = Field(min_length=1, max_length=1000)
    evaluator_id: str = Field(min_length=1, max_length=128)
    relevant_event_types: list[NormalizedEventType] = Field(min_length=1)
    relevant_conditions: list[EventCondition] = Field(default_factory=list)
    invariant: str = Field(min_length=1, max_length=1000)
    parameters: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def unique_relevant_event_types(self) -> "SecurityContract":
        if len(self.relevant_event_types) != len(set(self.relevant_event_types)):
            raise ValueError("relevant event types must be unique")
        return self


class ContractStatus(StrEnum):
    PASS = "PASS"
    VIOLATED = "VIOLATED"


class ViolationEvidence(StrictModel):
    evidence_id: str = Field(default_factory=lambda: str(uuid4()), min_length=1)
    summary: str = Field(min_length=1, max_length=2000)
    event_ids: list[str] = Field(min_length=1)
    violation_path: list[str] = Field(min_length=1)
    observations: dict[str, JsonValue] = Field(default_factory=dict)


class ContractEvaluation(StrictModel):
    contract_id: str
    trace_id: str
    status: ContractStatus
    evidence: list[ViolationEvidence] = Field(default_factory=list)

    @model_validator(mode="after")
    def evidence_matches_status(self) -> "ContractEvaluation":
        if self.status == ContractStatus.VIOLATED and not self.evidence:
            raise ValueError("violated evaluations require evidence")
        if self.status == ContractStatus.PASS and self.evidence:
            raise ValueError("passing evaluations cannot contain violation evidence")
        return self
