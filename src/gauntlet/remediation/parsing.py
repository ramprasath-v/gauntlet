"""Strict RepairProposal parsing with bounded, escaped failure diagnostics."""
import json
import re

from pydantic import ValidationError

from gauntlet.remediation.models import RepairProposal


DIAGNOSTIC_RADIUS = 48


class RepairProposalJSONError(ValueError):
    def __init__(
        self, *, content_length: int, line: int, column: int,
        code_point: str, diagnostic_window: str,
    ):
        self.content_length = content_length
        self.line = line
        self.column = column
        self.code_point = code_point
        self.diagnostic_window = diagnostic_window
        super().__init__(
            "Provider output is not valid RepairProposal JSON "
            f"(length={content_length}, line={line}, column={column}, "
            f"code_point={code_point}, window={diagnostic_window})"
        )


def _redact_diagnostic(value: str) -> str:
    value = re.sub(
        r'(?i)("(?:api[_-]?key|authorization|access[_-]?token|password|secret)"\s*:\s*")[^"]*',
        r'\1[REDACTED]', value,
    )
    return re.sub(
        r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value
    )


def _json_failure(raw: str, error: json.JSONDecodeError) -> RepairProposalJSONError:
    start = max(0, error.pos - DIAGNOSTIC_RADIUS)
    end = min(len(raw), error.pos + DIAGNOSTIC_RADIUS + 1)
    window = _redact_diagnostic(raw[start:end])
    escaped_window = json.dumps(window, ensure_ascii=True)
    code_point = f"U+{ord(raw[error.pos]):04X}" if error.pos < len(raw) else "EOF"
    return RepairProposalJSONError(
        content_length=len(raw), line=error.lineno, column=error.colno,
        code_point=code_point, diagnostic_window=escaped_window,
    )


def parse_repair_proposal(raw: str) -> RepairProposal:
    """Parse without repairing malformed provider output."""
    try:
        return RepairProposal.model_validate_json(raw)
    except ValidationError as validation_error:
        try:
            json.loads(raw)
        except json.JSONDecodeError as json_error:
            raise _json_failure(raw, json_error) from validation_error
        raise
