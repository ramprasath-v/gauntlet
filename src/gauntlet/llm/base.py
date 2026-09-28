from dataclasses import dataclass
from typing import Protocol

@dataclass(frozen=True)
class ModelContext:
    system: str
    user: str
    tool_content: str
    tool_content_is_untrusted: bool = False
    enforce_data_only_boundary: bool = False

class AgentModelClient(Protocol):
    async def generate(self, context: ModelContext) -> str: ...
