"""Decode provider JSON into untrusted repair candidates without repairing it."""
import json
import re

from pydantic import BaseModel, ValidationError

from gauntlet.remediation.models import (
    GeneratedEditCandidate, GeneratedMultiEditCandidate,
    GeneratedRepairCandidate, GeneratedTestCandidate,
)


DIAGNOSTIC_RADIUS = 48


class GeneratedCandidateJSONError(ValueError):
    def __init__(
        self, *, kind: str, content_length: int, line: int, column: int,
        code_point: str, diagnostic_window: str,
    ):
        self.kind = kind
        self.content_length = content_length
        self.line = line
        self.column = column
        self.code_point = code_point
        self.diagnostic_window = diagnostic_window
        super().__init__(
            f"Provider output is not valid {kind} JSON "
            f"(length={content_length}, line={line}, column={column}, "
            f"code_point={code_point}, window={diagnostic_window})"
        )


class GeneratedRepairCandidateJSONError(GeneratedCandidateJSONError):
    def __init__(
        self, *, content_length: int, line: int, column: int,
        code_point: str, diagnostic_window: str,
    ):
        super().__init__(
            kind="GeneratedRepairCandidate",
            content_length=content_length, line=line, column=column,
            code_point=code_point, diagnostic_window=diagnostic_window,
        )


class GeneratedEditCandidateJSONError(GeneratedCandidateJSONError):
    def __init__(
        self, *, content_length: int, line: int, column: int,
        code_point: str, diagnostic_window: str,
    ):
        super().__init__(
            kind="GeneratedEditCandidate",
            content_length=content_length, line=line, column=column,
            code_point=code_point, diagnostic_window=diagnostic_window,
        )


class GeneratedMultiEditCandidateJSONError(GeneratedCandidateJSONError):
    def __init__(
        self, *, content_length: int, line: int, column: int,
        code_point: str, diagnostic_window: str,
    ):
        super().__init__(
            kind="GeneratedMultiEditCandidate",
            content_length=content_length, line=line, column=column,
            code_point=code_point, diagnostic_window=diagnostic_window,
        )


class GeneratedTestCandidateJSONError(GeneratedCandidateJSONError):
    def __init__(
        self, *, content_length: int, line: int, column: int,
        code_point: str, diagnostic_window: str,
    ):
        super().__init__(
            kind="GeneratedTestCandidate",
            content_length=content_length, line=line, column=column,
            code_point=code_point, diagnostic_window=diagnostic_window,
        )


def _redact_diagnostic(value: str) -> str:
    value = re.sub(
        r'(?i)("(?:api[_-]?key|authorization|access[_-]?token|password|secret)"\s*:\s*")[^"]*',
        r'\1[REDACTED]', value,
    )
    return re.sub(
        r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value
    )


def _json_failure(
    error_class: type[GeneratedCandidateJSONError],
    raw: str, error: json.JSONDecodeError,
) -> GeneratedCandidateJSONError:
    start = max(0, error.pos - DIAGNOSTIC_RADIUS)
    end = min(len(raw), error.pos + DIAGNOSTIC_RADIUS + 1)
    window = _redact_diagnostic(raw[start:end])
    escaped_window = json.dumps(window, ensure_ascii=True)
    code_point = f"U+{ord(raw[error.pos]):04X}" if error.pos < len(raw) else "EOF"
    return error_class(
        content_length=len(raw), line=error.lineno, column=error.colno,
        code_point=code_point, diagnostic_window=escaped_window,
    )


def _parse(
    model: type[BaseModel],
    error_class: type[GeneratedCandidateJSONError],
    raw: str,
) -> BaseModel:
    """Parse without repairing malformed provider output."""
    try:
        return model.model_validate_json(raw)
    except ValidationError as validation_error:
        try:
            json.loads(raw)
        except json.JSONDecodeError as json_error:
            raise _json_failure(error_class, raw, json_error) from validation_error
        raise


def parse_generated_repair_candidate(raw: str) -> GeneratedRepairCandidate:
    return _parse(
        GeneratedRepairCandidate, GeneratedRepairCandidateJSONError, raw,
    )  # type: ignore[return-value]


def parse_generated_edit_candidate(raw: str) -> GeneratedEditCandidate:
    return _parse(
        GeneratedEditCandidate, GeneratedEditCandidateJSONError, raw,
    )  # type: ignore[return-value]


def parse_generated_multi_edit_candidate(raw: str) -> GeneratedMultiEditCandidate:
    return _parse(
        GeneratedMultiEditCandidate, GeneratedMultiEditCandidateJSONError, raw,
    )  # type: ignore[return-value]


def parse_generated_test_candidate(raw: str) -> GeneratedTestCandidate:
    return _parse(
        GeneratedTestCandidate, GeneratedTestCandidateJSONError, raw,
    )  # type: ignore[return-value]
