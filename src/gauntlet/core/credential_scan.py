"""Structure-aware credential checks for persisted evidence."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Literal


CredentialIssue = Literal["configured_credential", "credential_marker"]

_SENSITIVE_KEY = re.compile(
    r"^(?:api[_-]?key|access[_-]?token|authorization|password|secret|token)$",
    re.IGNORECASE,
)
_BEARER = re.compile(
    r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{8,})"
)
_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|authorization|password|secret|token)"
    r"\s*[:=]\s*['\"]?([^\s'\",;\]}]+)"
)
_KNOWN_PREFIX = re.compile(
    r"(?i)^(?:sk-|nvapi-|gh[opsu]_|xox[baprs]-|AIza|eyJ)"
)
_SAFE_PLACEHOLDER = re.compile(
    r"(?i)^(?:none|null|missing|unset|redacted|\[redacted\]|<redacted>)$"
)


def credential_issue(
    value: Any, *, configured_credentials: tuple[str, ...] = (),
) -> CredentialIssue | None:
    """Return a safe classification without returning credential material."""
    credentials = tuple(item for item in configured_credentials if item)

    def visit(item: Any, *, sensitive_value: bool = False) -> CredentialIssue | None:
        if isinstance(item, str):
            if any(secret in item for secret in credentials):
                return "configured_credential"
            if _BEARER.search(item):
                return "credential_marker"
            if sensitive_value and _credential_like(item):
                return "credential_marker"
            for match in _ASSIGNMENT.finditer(item):
                if _credential_like(match.group(1)):
                    return "credential_marker"
            return None
        if isinstance(item, Mapping):
            for key, child in item.items():
                if any(secret in str(key) for secret in credentials):
                    return "configured_credential"
                issue = visit(
                    child,
                    sensitive_value=_SENSITIVE_KEY.fullmatch(str(key)) is not None,
                )
                if issue:
                    return issue
            return None
        if isinstance(item, Sequence) and not isinstance(
            item, (bytes, bytearray)
        ):
            for child in item:
                issue = visit(child)
                if issue:
                    return issue
        return None

    return visit(value)


def _credential_like(value: str) -> bool:
    candidate = value.strip().strip("'\"")
    if not candidate or _SAFE_PLACEHOLDER.fullmatch(candidate):
        return False
    if _BEARER.search(candidate) or _KNOWN_PREFIX.search(candidate):
        return True
    if len(candidate) < 12 or any(character.isspace() for character in candidate):
        return False
    has_alpha = any(character.isalpha() for character in candidate)
    has_digit = any(character.isdigit() for character in candidate)
    punctuation = sum(not character.isalnum() for character in candidate)
    return has_alpha and (has_digit or punctuation >= 2)
