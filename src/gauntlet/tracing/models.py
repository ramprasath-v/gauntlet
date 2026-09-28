"""Serializable observable execution evidence; never hidden model reasoning."""
from enum import StrEnum
from typing import Literal
from uuid import uuid4
from pydantic import BaseModel, Field

class TrustLevel(StrEnum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"

class SourceKind(StrEnum):
    USER = "USER"
    TOOL = "TOOL"
    SYSTEM = "SYSTEM"
    MODEL = "MODEL"
    VERIFIER = "VERIFIER"

class SourceLocation(BaseModel):
    file: str
    symbol: str
    responsibility: str

class ContextFlow(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    sequence: int
    input_event_id: str
    from_component: str = "search_reviews"
    from_trust_level: TrustLevel = TrustLevel.UNTRUSTED
    to_component: str = "model_context"
    privileged_context: bool
    location: SourceLocation

class ExecutionEvent(BaseModel):
    kind: Literal["user_message", "tool_call", "tool_result", "context_flow", "model_response", "verdict"]
    data: dict[str, str]
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    sequence: int = 0
    source: SourceKind | None = None
    trust_level: TrustLevel | None = None
    input_event_id: str | None = None
    context_flow: ContextFlow | None = None

class FailureBoundary(BaseModel):
    boundary_id: str = Field(default_factory=lambda: str(uuid4()))
    from_component: str
    from_trust_level: TrustLevel
    to_component: str
    boundary_type: str = "tool_result → model_context"
    evidence_event_ids: list[str]
    description: str

class AttackTrace(BaseModel):
    attack_id: str
    events: list[ExecutionEvent]
    failure_boundary: FailureBoundary | None
    evidence: dict[str, str]
    verdict: str
    source_locations: list[SourceLocation]
