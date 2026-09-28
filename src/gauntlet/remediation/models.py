import ast
import json
import re
from hashlib import sha256
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


REGRESSION_DIAGNOSTIC_RADIUS = 48


class RegressionTestSyntaxError(ValueError):
    """Syntax failure metadata without exposing complete generated source."""

    def __init__(self, source: str, error: SyntaxError):
        self.syntax_message = error.msg
        self.line = error.lineno
        self.offset = error.offset
        self.source_length = len(source)
        position = _syntax_error_position(source, error)
        start = max(0, position - REGRESSION_DIAGNOSTIC_RADIUS)
        end = min(len(source), position + REGRESSION_DIAGNOSTIC_RADIUS + 1)
        window = _redact_generated_source(source[start:end])
        self.diagnostic_window = json.dumps(window, ensure_ascii=True)
        super().__init__(
            "regression_test must be valid Python source "
            f"(message={json.dumps(error.msg)}, line={error.lineno}, "
            f"offset={error.offset}, source_length={len(source)}, "
            f"window={self.diagnostic_window})"
        )


def _syntax_error_position(source: str, error: SyntaxError) -> int:
    line = max(error.lineno or 1, 1)
    offset = max(error.offset or 1, 1)
    lines = source.splitlines(keepends=True)
    prefix_length = sum(len(value) for value in lines[:line - 1])
    return min(len(source), prefix_length + offset - 1)


def _redact_generated_source(value: str) -> str:
    value = re.sub(
        r"(?i)((?:api[_-]?key|authorization|access[_-]?token|password|secret)"
        r"\s*=\s*['\"])[^'\"]*",
        r"\1[REDACTED]", value,
    )
    return re.sub(
        r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value
    )


class SourceContext(StrictModel):
    repository_relative_path: str
    target_symbol: str
    source_text: str = Field(min_length=1, max_length=12_000)
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    trace_id: str
    boundary_id: str
    evidence_ids: list[str] = Field(min_length=1)

    @classmethod
    def hash_text(cls, text: str) -> str:
        return sha256(text.encode()).hexdigest()


class RepairContext(StrictModel):
    trace_id: str
    boundary_id: str
    evidence_ids: list[str] = Field(min_length=1)
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    target_path: str
    target_symbol: str
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    failure_type: str = Field(min_length=1)


class GeneratedRepair(StrictModel):
    rationale: str = Field(min_length=1)
    patch: str = Field(min_length=1)
    regression_test: str = Field(min_length=1)
    optional_policy_artifact: str | None = None

    @field_validator("regression_test")
    @classmethod
    def executable_test_source(cls, value: str) -> str:
        try:
            tree = ast.parse(value)
        except SyntaxError as exc:
            raise RegressionTestSyntaxError(value, exc) from exc
        tests = [node for node in tree.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and node.name.startswith("test_")]
        if not tests or not any(isinstance(node, ast.Assert)
                                for test in tests for node in ast.walk(test)):
            raise ValueError("regression_test must contain a test function with an assertion")
        return value

    @model_validator(mode="after")
    def structurally_valid_single_target_patch(self) -> "GeneratedRepair":
        headers = [line for line in self.patch.splitlines()
                   if line.startswith("--- ") or line.startswith("+++ ")]
        if (len(headers) != 2 or not headers[0].startswith("--- a/")
                or not headers[1].startswith("+++ b/")
                or headers[0][6:] != headers[1][6:] or "@@" not in self.patch):
            raise ValueError("patch must be a structurally valid single-target unified diff")
        return self


class RepairProposal(GeneratedRepair):
    repair_id: str
    trace_id: str
    boundary_id: str
    evidence_ids: list[str] = Field(min_length=1)
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    target_path: str
    target_symbol: str
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    failure_type: str = Field(min_length=1)

    @field_validator("repair_id")
    @classmethod
    def valid_repair_id(cls, value: str) -> str:
        UUID(value)
        return value

    @model_validator(mode="after")
    def authorized_single_target_patch(self) -> "RepairProposal":
        expected_old = f"--- a/{self.target_path}"
        expected_new = f"+++ b/{self.target_path}"
        headers = [line for line in self.patch.splitlines()
                   if line.startswith("--- ") or line.startswith("+++ ")]
        if headers != [expected_old, expected_new]:
            raise ValueError("patch must be a single-target unified diff for target_path")
        return self


class RemediationRequest(StrictModel):
    source_context: SourceContext
    repair_context: RepairContext
    evidence_summary: dict[str, Any]
