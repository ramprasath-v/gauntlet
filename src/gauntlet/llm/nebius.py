"""Nebius Token Factory OpenAI-compatible transport."""
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
import json
import logging
import re
from typing import Any
from urllib.parse import urlsplit

import httpx

from gauntlet.core.config import NebiusConfig
from gauntlet.llm.base import ModelContext


ALLOWED_NEBIUS_HOSTS = {
    "api.tokenfactory.nebius.com",
    "api.tokenfactory.us-central1.nebius.com",
}
NEMOTRON_SUPER_MODEL = "nvidia/nemotron-3-super-120b-a12b"
NEMOTRON_SUPER_HOST = "api.tokenfactory.us-central1.nebius.com"
NEMOTRON_LIGHTNING_MODEL = "nvidia/Nemotron-3_5-Lightning"
QWEN_35_MODEL = "Qwen/Qwen3.5-397B-A17B"
REPAIR_SCHEMA_NAME = "repair_proposal"
NEMOTRON_REASONING_ENABLED = "/think"
NEMOTRON_REASONING_DISABLED = "/no_think"
NEMOTRON_REASONING_DIRECTIVES = frozenset({
    NEMOTRON_REASONING_ENABLED,
    NEMOTRON_REASONING_DISABLED,
})
MAX_ERROR_BODY_CHARS = 4_000
logger = logging.getLogger(__name__)


class NebiusAPIError(ValueError):
    """Sanitized provider error suitable for CLI and build-diary reporting."""

    def __init__(self, status_code: int, response_body: str):
        self.status_code = status_code
        self.response_body = response_body
        super().__init__(f"Nebius API returned HTTP {status_code}: {response_body}")


@dataclass(frozen=True)
class NebiusCompletionMetadata:
    http_status: int
    response_id: str | None
    object_type: str | None
    returned_model: str | None
    choice_count: int | None
    selected_choice_index: int | None
    finish_reason: str | None
    message_role: str | None
    message_field_types: dict[str, str]
    content_type: str
    content_length: int | None
    refusal_present: bool
    refusal_type: str | None
    reasoning_present: bool
    reasoning_type: str | None
    reasoning_content_present: bool
    reasoning_content_type: str | None
    tool_calls_present: bool
    tool_calls_count: int | None
    prompt_tokens: int | None
    completion_tokens: int | None
    total_tokens: int | None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class NebiusCompletionError(ValueError):
    def __init__(self, classification: str, metadata: NebiusCompletionMetadata):
        self.classification = classification
        self.metadata = metadata
        super().__init__(
            f"Nebius completion {classification}: "
            + json.dumps(metadata.as_dict(), sort_keys=True)
        )


def _redact_text(value: str, api_key: str) -> str:
    if api_key:
        value = value.replace(api_key, "[REDACTED]")
    value = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value)
    return value


def _safe_text(value: Any, api_key: str, limit: int = 200) -> str | None:
    if not isinstance(value, str):
        return None
    return _redact_text(value, api_key)[:limit]


def _value_type(value: Any) -> str:
    return "null" if value is None else type(value).__name__


def _completion_metadata(
    body: Any, status_code: int, api_key: str
) -> tuple[NebiusCompletionMetadata, Any, str | None]:
    root = body if isinstance(body, dict) else {}
    choices = root.get("choices")
    choice_count = len(choices) if isinstance(choices, list) else None
    choice = choices[0] if isinstance(choices, list) and choices else None
    choice_object = choice if isinstance(choice, dict) else {}
    message = choice_object.get("message")
    message_object = message if isinstance(message, dict) else {}
    content = message_object.get("content") if "content" in message_object else _MISSING
    refusal = message_object.get("refusal") if "refusal" in message_object else _MISSING
    reasoning = message_object.get("reasoning") if "reasoning" in message_object else _MISSING
    reasoning_content = (
        message_object.get("reasoning_content")
        if "reasoning_content" in message_object else _MISSING
    )
    tool_calls = message_object.get("tool_calls") if "tool_calls" in message_object else _MISSING
    usage = root.get("usage") if isinstance(root.get("usage"), dict) else {}
    metadata = NebiusCompletionMetadata(
        http_status=status_code,
        response_id=_safe_text(root.get("id"), api_key),
        object_type=_safe_text(root.get("object"), api_key),
        returned_model=_safe_text(root.get("model"), api_key),
        choice_count=choice_count,
        selected_choice_index=(choice_object.get("index")
                               if isinstance(choice_object.get("index"), int) else None),
        finish_reason=_safe_text(choice_object.get("finish_reason"), api_key, 80),
        message_role=_safe_text(message_object.get("role"), api_key, 80),
        message_field_types={
            _safe_text(key, api_key, 80) or "[REDACTED]": _value_type(value)
            for key, value in message_object.items()
        },
        content_type="missing" if content is _MISSING else _value_type(content),
        content_length=len(content) if isinstance(content, str) else None,
        refusal_present=refusal is not _MISSING,
        refusal_type=None if refusal is _MISSING else _value_type(refusal),
        reasoning_present=reasoning is not _MISSING,
        reasoning_type=None if reasoning is _MISSING else _value_type(reasoning),
        reasoning_content_present=reasoning_content is not _MISSING,
        reasoning_content_type=(None if reasoning_content is _MISSING
                                else _value_type(reasoning_content)),
        tool_calls_present=tool_calls is not _MISSING,
        tool_calls_count=len(tool_calls) if isinstance(tool_calls, list) else None,
        prompt_tokens=usage.get("prompt_tokens") if isinstance(usage.get("prompt_tokens"), int) else None,
        completion_tokens=(usage.get("completion_tokens")
                           if isinstance(usage.get("completion_tokens"), int) else None),
        total_tokens=usage.get("total_tokens") if isinstance(usage.get("total_tokens"), int) else None,
    )
    return metadata, content, _classify_empty_content(body, choices, choice, message, content,
                                                       refusal, reasoning, reasoning_content,
                                                       tool_calls, metadata.finish_reason)


_MISSING = object()


def _has_value(value: Any) -> bool:
    return value is not _MISSING and value is not None and value != "" and value != []


def _classify_empty_content(
    body: Any, choices: Any, choice: Any, message: Any, content: Any,
    refusal: Any, reasoning: Any, reasoning_content: Any, tool_calls: Any,
    finish_reason: str | None,
) -> str | None:
    if not isinstance(body, dict):
        return "NON_OBJECT_RESPONSE"
    if "choices" not in body:
        return "MISSING_CHOICES"
    if not isinstance(choices, list):
        return "NON_LIST_CHOICES"
    if not choices:
        return "EMPTY_CHOICES"
    if not isinstance(choice, dict):
        return "NON_OBJECT_CHOICE"
    if "message" not in choice:
        return "MISSING_MESSAGE"
    if not isinstance(message, dict):
        return "NON_OBJECT_MESSAGE"
    if isinstance(content, str) and content.strip():
        return None
    if _has_value(refusal):
        return "REFUSAL_PRESENT"
    if finish_reason in {"length", "max_tokens"}:
        return "LENGTH_TERMINATED_WITHOUT_CONTENT"
    if _has_value(reasoning) or _has_value(reasoning_content):
        return "REASONING_WITHOUT_CONTENT"
    if _has_value(tool_calls):
        return "TOOL_CALLS_WITHOUT_CONTENT"
    if content is _MISSING:
        return "CONTENT_MISSING"
    if content is None:
        return "CONTENT_NULL"
    if not isinstance(content, str):
        return "CONTENT_NON_STRING"
    if content == "":
        return "CONTENT_EMPTY"
    if not content.strip():
        return "CONTENT_WHITESPACE"
    return "UNKNOWN_EMPTY_CONTENT"


def _sanitize_error_body(response: httpx.Response, api_key: str) -> str:
    raw = response.text
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        sanitized = _redact_text(raw, api_key)
    else:
        def redact(value: Any) -> Any:
            if isinstance(value, dict):
                return {
                    key: ("[REDACTED]" if key.lower().replace("-", "_") in {
                        "api_key", "authorization", "access_token", "token", "secret",
                        "password", "client_secret", "private_key",
                    } else redact(item))
                    for key, item in value.items()
                }
            if isinstance(value, list):
                return [redact(item) for item in value]
            if isinstance(value, str):
                return _redact_text(value, api_key)
            return value
        sanitized = json.dumps(redact(parsed), ensure_ascii=False, sort_keys=True)
    if len(sanitized) > MAX_ERROR_BODY_CHARS:
        return sanitized[:MAX_ERROR_BODY_CHARS] + "…[truncated]"
    return sanitized or "<empty response body>"


def _with_nemotron_reasoning_directive(
    messages: Sequence[Mapping[str, str]], directive: str,
) -> list[dict[str, str]]:
    if directive not in NEMOTRON_REASONING_DIRECTIVES:
        raise ValueError(
            "Nemotron reasoning directive must be /think or /no_think"
        )
    serialized = [dict(message) for message in messages]
    if serialized and serialized[0].get("role") == "system":
        serialized[0]["content"] = directive + "\n" + serialized[0]["content"]
    else:
        serialized.insert(0, {"role": "system", "content": directive})
    return serialized


class NebiusTokenFactoryClient:
    def __init__(
        self, config: NebiusConfig | None = None, *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout_seconds: float = 60.0,
    ):
        self.config = (config or NebiusConfig.from_environment()).require_complete()
        parsed = urlsplit(self.config.base_url or "")
        if (parsed.scheme != "https" or parsed.hostname not in ALLOWED_NEBIUS_HOSTS
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path.rstrip("/") != "/v1"):
            raise ValueError("NEBIUS_BASE_URL must be an approved HTTPS Token Factory origin/path")
        if self.config.model == NEMOTRON_SUPER_MODEL and parsed.hostname != NEMOTRON_SUPER_HOST:
            raise ValueError(
                "Nemotron-3-Super requires the documented us-central1 Token Factory endpoint"
            )
        self._transport = transport
        self._timeout_seconds = timeout_seconds
        self.last_response_metadata: NebiusCompletionMetadata | None = None

    async def complete(
        self, messages: Sequence[Mapping[str, str]], *,
        response_schema: dict[str, Any] | None = None,
        schema_name: str | None = None,
        reasoning_directive: str | None = None,
        chat_template_kwargs: Mapping[str, bool] | None = None,
        max_tokens: int | None = None,
    ) -> str:
        serialized_messages = [dict(message) for message in messages]
        if reasoning_directive is not None:
            if self.config.model != NEMOTRON_SUPER_MODEL:
                raise ValueError(
                    "Nemotron reasoning directives require the Nemotron-3-Super model"
                )
            serialized_messages = _with_nemotron_reasoning_directive(
                serialized_messages, reasoning_directive
            )
        serialized_chat_template_kwargs = (
            dict(chat_template_kwargs) if chat_template_kwargs is not None else None
        )
        if serialized_chat_template_kwargs is not None:
            if self.config.model != NEMOTRON_LIGHTNING_MODEL:
                raise ValueError(
                    "chat_template_kwargs reasoning control requires Nemotron-3.5-Lightning"
                )
            if serialized_chat_template_kwargs != {"enable_thinking": False}:
                raise ValueError(
                    "Nemotron-3.5-Lightning requires enable_thinking=false for remediation"
                )
        if max_tokens is not None and (
            isinstance(max_tokens, bool) or not isinstance(max_tokens, int)
            or max_tokens <= 0
        ):
            raise ValueError("max_tokens must be a positive integer")
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": serialized_messages,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if serialized_chat_template_kwargs is not None:
            payload["chat_template_kwargs"] = serialized_chat_template_kwargs
        if response_schema is not None:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": schema_name or REPAIR_SCHEMA_NAME,
                    "schema": response_schema,
                },
            }
        async with httpx.AsyncClient(
            base_url=(self.config.base_url or "").rstrip("/") + "/",
            headers={"Authorization": f"Bearer {self.config.api_key}"},
            timeout=self._timeout_seconds, follow_redirects=False,
            trust_env=False, transport=self._transport,
        ) as client:
            response = await client.post("chat/completions", json=payload)
        if response.is_error:
            raise NebiusAPIError(
                response.status_code,
                _sanitize_error_body(response, self.config.api_key or ""),
            )
        body = response.json()
        metadata, content, classification = _completion_metadata(
            body, response.status_code, self.config.api_key or ""
        )
        self.last_response_metadata = metadata
        logger.warning(
            "Nebius completion metadata: %s",
            json.dumps(metadata.as_dict(), sort_keys=True),
        )
        if classification is not None:
            raise NebiusCompletionError(classification, metadata)
        return content

    async def generate(self, context: ModelContext) -> str:
        return await self.complete([
            {"role": "system", "content": context.system},
            {"role": "user", "content": context.user + "\n\n" + context.tool_content},
        ])
