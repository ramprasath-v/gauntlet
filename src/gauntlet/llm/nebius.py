"""Nebius Token Factory OpenAI-compatible transport."""
from collections.abc import Mapping, Sequence
import json
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
REPAIR_SCHEMA_NAME = "repair_proposal"
MAX_ERROR_BODY_CHARS = 4_000


class NebiusAPIError(ValueError):
    """Sanitized provider error suitable for CLI and build-diary reporting."""

    def __init__(self, status_code: int, response_body: str):
        self.status_code = status_code
        self.response_body = response_body
        super().__init__(f"Nebius API returned HTTP {status_code}: {response_body}")


def _redact_text(value: str, api_key: str) -> str:
    if api_key:
        value = value.replace(api_key, "[REDACTED]")
    value = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value)
    return value


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

    async def complete(
        self, messages: Sequence[Mapping[str, str]], *,
        response_schema: dict[str, Any] | None = None,
    ) -> str:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": list(messages),
        }
        if response_schema is not None:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": REPAIR_SCHEMA_NAME,
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
        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError("Nebius response did not contain chat-completion content") from exc
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Nebius response content was empty or non-text")
        return content

    async def generate(self, context: ModelContext) -> str:
        return await self.complete([
            {"role": "system", "content": context.system},
            {"role": "user", "content": context.user + "\n\n" + context.tool_content},
        ])
