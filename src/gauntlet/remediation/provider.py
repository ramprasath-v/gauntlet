from typing import Protocol

from gauntlet.llm.nebius import (
    NEMOTRON_REASONING_DISABLED,
    NebiusTokenFactoryClient,
)
from gauntlet.remediation.models import RemediationRequest, RepairProposal
from gauntlet.remediation.prompt import build_messages


class RemediationProvider(Protocol):
    provider_name: str
    model_name: str

    async def generate(self, request: RemediationRequest) -> str: ...


class NebiusNemotronRemediationProvider:
    provider_name = "nebius_token_factory"
    max_output_tokens = 4_096

    def __init__(self, client: NebiusTokenFactoryClient):
        self.client = client
        self.model_name = client.config.model or ""

    async def generate(self, request: RemediationRequest) -> str:
        return await self.client.complete(
            build_messages(request),
            response_schema=RepairProposal.model_json_schema(),
            reasoning_directive=NEMOTRON_REASONING_DISABLED,
            max_tokens=self.max_output_tokens,
        )
