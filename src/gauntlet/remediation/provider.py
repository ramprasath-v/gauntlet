from typing import Protocol

from gauntlet.llm.nebius import (
    NEMOTRON_LIGHTNING_MODEL,
    NEMOTRON_REASONING_DISABLED,
    NEMOTRON_SUPER_MODEL,
    NebiusTokenFactoryClient,
)
from gauntlet.remediation.models import GeneratedRepairCandidate, RemediationRequest
from gauntlet.remediation.prompt import build_messages, build_revision_messages
from gauntlet.remediation.retry_models import SafeProviderCompletion


class RemediationProvider(Protocol):
    provider_name: str
    model_name: str

    async def generate(self, request: RemediationRequest) -> str: ...


class RetryRemediationProvider(RemediationProvider, Protocol):
    async def generate_revision(
        self,
        request: RemediationRequest,
        *,
        previous_candidate: dict[str, str | None],
        failure_feedback: dict[str, object],
    ) -> str: ...

    def safe_completion_metadata(self) -> SafeProviderCompletion | None: ...


class NebiusNemotronRemediationProvider:
    provider_name = "nebius_token_factory"
    max_output_tokens = 4_096

    def __init__(self, client: NebiusTokenFactoryClient):
        self.client = client
        self.model_name = client.config.model or ""

    async def generate(self, request: RemediationRequest) -> str:
        return await self._complete(build_messages(request))

    async def generate_revision(
        self,
        request: RemediationRequest,
        *,
        previous_candidate: dict[str, str | None],
        failure_feedback: dict[str, object],
    ) -> str:
        return await self._complete(build_revision_messages(
            request,
            previous_candidate=previous_candidate,
            failure_feedback=failure_feedback,
        ))

    async def _complete(self, messages: list[dict[str, str]]) -> str:
        reasoning_options = {}
        if self.model_name == NEMOTRON_SUPER_MODEL:
            reasoning_options["reasoning_directive"] = NEMOTRON_REASONING_DISABLED
        elif self.model_name == NEMOTRON_LIGHTNING_MODEL:
            reasoning_options["chat_template_kwargs"] = {"enable_thinking": False}
        return await self.client.complete(
            messages,
            response_schema=GeneratedRepairCandidate.model_json_schema(),
            max_tokens=self.max_output_tokens,
            **reasoning_options,
        )

    def safe_completion_metadata(self) -> SafeProviderCompletion | None:
        metadata = self.client.last_response_metadata
        if metadata is None:
            return None
        return SafeProviderCompletion(
            http_status=metadata.http_status,
            response_id=metadata.response_id,
            returned_model=metadata.returned_model,
            finish_reason=metadata.finish_reason,
            content_type=metadata.content_type,
            content_length=metadata.content_length,
            prompt_tokens=metadata.prompt_tokens,
            completion_tokens=metadata.completion_tokens,
            total_tokens=metadata.total_tokens,
        )
