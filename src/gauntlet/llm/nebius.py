"""Nebius Token Factory OpenAI-compatible transport."""
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

import httpx

from gauntlet.core.config import NebiusConfig
from gauntlet.llm.base import ModelContext


ALLOWED_NEBIUS_HOSTS = {
    "api.tokenfactory.nebius.com",
    "api.tokenfactory.us-central1.nebius.com",
}


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
        self._transport = transport
        self._timeout_seconds = timeout_seconds

    async def complete(
        self, messages: Sequence[Mapping[str, str]], *,
        response_schema: dict[str, Any] | None = None,
    ) -> str:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": list(messages),
            "temperature": 0,
        }
        if response_schema is not None:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": response_schema,
            }
        async with httpx.AsyncClient(
            base_url=(self.config.base_url or "").rstrip("/") + "/",
            headers={"Authorization": f"Bearer {self.config.api_key}"},
            timeout=self._timeout_seconds, follow_redirects=False,
            trust_env=False, transport=self._transport,
        ) as client:
            response = await client.post("chat/completions", json=payload)
            response.raise_for_status()
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
