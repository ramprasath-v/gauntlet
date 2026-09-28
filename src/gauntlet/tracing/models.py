"""Observed events only; M1 does not infer causality."""
from typing import Literal
from pydantic import BaseModel

class ExecutionEvent(BaseModel):
    kind: Literal["user_message", "tool_call", "tool_result", "model_response", "verdict"]
    data: dict[str, str]
