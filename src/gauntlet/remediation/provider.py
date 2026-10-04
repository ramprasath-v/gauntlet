from typing import Protocol

from gauntlet.llm.nebius import (
    NEMOTRON_LIGHTNING_MODEL,
    NEMOTRON_REASONING_DISABLED,
    NEMOTRON_SUPER_MODEL,
    QWEN_35_MODEL,
    NebiusTokenFactoryClient,
)
from gauntlet.remediation.models import (
    GeneratedEditCandidate, GeneratedMultiEditCandidate,
    GeneratedRepairCandidate, GeneratedTestCandidate,
    MultiTargetRemediationRequest, RemediationRequest,
)
from gauntlet.remediation.prompt import (
    build_edit_messages, build_edit_revision_messages,
    build_live_demo_messages, build_multi_target_edit_messages,
    build_test_messages, build_test_revision_messages,
)
from gauntlet.remediation.retry_models import SafeProviderCompletion


EDIT_SCHEMA_NAME = "edit_candidate"
TEST_SCHEMA_NAME = "test_candidate"
LIVE_DEMO_SCHEMA_NAME = "repair_candidate"
MULTI_EDIT_SCHEMA_NAME = "multi_edit_candidate"


class RemediationProvider(Protocol):
    provider_name: str
    model_name: str

    async def generate_edit(self, request: RemediationRequest) -> str: ...

    async def generate_test(
        self, request: RemediationRequest, *, derived_patch: str,
    ) -> str: ...


class RetryRemediationProvider(RemediationProvider, Protocol):
    async def generate_edit_revision(
        self,
        request: RemediationRequest,
        *,
        previous_edit: dict[str, object],
        failure_feedback: dict[str, object],
    ) -> str: ...

    async def generate_test_revision(
        self,
        request: RemediationRequest,
        *,
        derived_patch: str,
        previous_test: dict[str, object],
        failure_feedback: dict[str, object],
    ) -> str: ...

    def safe_completion_metadata(self) -> SafeProviderCompletion | None: ...


class NebiusNemotronRemediationProvider:
    provider_name = "nebius_token_factory"
    max_edit_tokens = 2_048
    max_test_tokens = 2_048
    max_live_demo_tokens = 2_048

    def __init__(self, client: NebiusTokenFactoryClient):
        self.client = client
        self.model_name = client.config.model or ""

    async def generate_edit(self, request: RemediationRequest) -> str:
        return await self._complete(
            build_edit_messages(request),
            response_schema=GeneratedEditCandidate.model_json_schema(),
            schema_name=EDIT_SCHEMA_NAME,
            max_tokens=self.max_edit_tokens,
        )

    async def generate_multi_edit(
        self, request: MultiTargetRemediationRequest,
    ) -> str:
        return await self._complete(
            build_multi_target_edit_messages(request),
            response_schema=GeneratedMultiEditCandidate.model_json_schema(),
            schema_name=MULTI_EDIT_SCHEMA_NAME,
            max_tokens=self.max_edit_tokens,
        )

    async def generate_test(
        self, request: RemediationRequest, *, derived_patch: str,
    ) -> str:
        return await self._complete(
            build_test_messages(request, derived_patch=derived_patch),
            response_schema=GeneratedTestCandidate.model_json_schema(),
            schema_name=TEST_SCHEMA_NAME,
            max_tokens=self.max_test_tokens,
        )

    async def generate_live_demo_candidate(
        self, request: RemediationRequest,
    ) -> str:
        """Generate one combined v3 candidate for the separately scoped M7.2 path."""
        return await self._complete(
            build_live_demo_messages(request),
            response_schema=GeneratedRepairCandidate.model_json_schema(),
            schema_name=LIVE_DEMO_SCHEMA_NAME,
            max_tokens=self.max_live_demo_tokens,
        )

    async def generate_edit_revision(
        self,
        request: RemediationRequest,
        *,
        previous_edit: dict[str, object],
        failure_feedback: dict[str, object],
    ) -> str:
        return await self._complete(
            build_edit_revision_messages(
                request,
                previous_edit=previous_edit,
                failure_feedback=failure_feedback,
            ),
            response_schema=GeneratedEditCandidate.model_json_schema(),
            schema_name=EDIT_SCHEMA_NAME,
            max_tokens=self.max_edit_tokens,
        )

    async def generate_test_revision(
        self,
        request: RemediationRequest,
        *,
        derived_patch: str,
        previous_test: dict[str, object],
        failure_feedback: dict[str, object],
    ) -> str:
        return await self._complete(
            build_test_revision_messages(
                request,
                derived_patch=derived_patch,
                previous_test=previous_test,
                failure_feedback=failure_feedback,
            ),
            response_schema=GeneratedTestCandidate.model_json_schema(),
            schema_name=TEST_SCHEMA_NAME,
            max_tokens=self.max_test_tokens,
        )

    async def _complete(
        self, messages: list[dict[str, str]], *,
        response_schema: dict, schema_name: str, max_tokens: int,
    ) -> str:
        reasoning_options = {}
        if self.model_name == NEMOTRON_SUPER_MODEL:
            reasoning_options["reasoning_directive"] = NEMOTRON_REASONING_DISABLED
        elif self.model_name in {NEMOTRON_LIGHTNING_MODEL, QWEN_35_MODEL}:
            reasoning_options["chat_template_kwargs"] = {"enable_thinking": False}
        return await self.client.complete(
            messages,
            response_schema=response_schema,
            schema_name=schema_name,
            max_tokens=max_tokens,
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
