from typing import Protocol

from gauntlet.llm.nebius import (
    NEMOTRON_LIGHTNING_MODEL,
    NEMOTRON_REASONING_DISABLED,
    NEMOTRON_SUPER_MODEL,
    NebiusTokenFactoryClient,
)
from gauntlet.remediation.models import GeneratedRepair, RemediationRequest
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
        reasoning_options = {}
        if self.model_name == NEMOTRON_SUPER_MODEL:
            reasoning_options["reasoning_directive"] = NEMOTRON_REASONING_DISABLED
        elif self.model_name == NEMOTRON_LIGHTNING_MODEL:
            reasoning_options["chat_template_kwargs"] = {"enable_thinking": False}
        return await self.client.complete(
            build_messages(request),
            response_schema=GeneratedRepair.model_json_schema(),
            max_tokens=self.max_output_tokens,
            **reasoning_options,
        )
