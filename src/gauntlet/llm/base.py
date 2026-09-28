from dataclasses import dataclass
from typing import Protocol

@dataclass(frozen=True)
class ModelContext:
    system: str
    user: str
    tool_content: str

class AgentModelClient(Protocol):
    async def generate(self, context: ModelContext) -> str: ...
