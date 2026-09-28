"""Future adapter boundary. No guessed URL, credentials, or API protocol."""
from gauntlet.core.config import NebiusConfig
from gauntlet.llm.base import ModelContext

class NebiusTokenFactoryClient:
    def __init__(self, config: NebiusConfig | None = None):
        self.config = config if config is not None else NebiusConfig.from_environment()

    async def generate(self, context: ModelContext) -> str:
        raise NotImplementedError("Live Nebius access is deferred; use FakeAgentModelClient for M1.")
