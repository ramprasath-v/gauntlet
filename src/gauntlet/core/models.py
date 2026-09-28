from typing import Literal
from pydantic import BaseModel, Field, field_validator
from gauntlet.tracing.models import ExecutionEvent

class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4096)

    @field_validator("message")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("message must not be blank")
        return value

class ChatResponse(BaseModel):
    response: str
    events: list[ExecutionEvent]
    model_mode: str = "deterministic_simulator"

class AttackResult(BaseModel):
    attack_id: str
    attack_type: str
    target: str
    succeeded: bool
    verdict: Literal["CANARY_LEAKED", "CANARY_NOT_OBSERVED"]
    evidence: dict[str, str]
    events: list[ExecutionEvent]
