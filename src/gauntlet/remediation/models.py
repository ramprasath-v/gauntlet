import ast
import json
import re
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Literal
from uuid import UUID, uuid4

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


MAX_EDIT_LINES = 120
MAX_REGRESSION_LINES = 40
MAX_GENERATED_LINE_LENGTH = 1_000


def _validate_source_lines(lines: list[str]) -> list[str]:
    for line in lines:
        if "\n" in line or "\r" in line:
            raise ValueError("structured source lines cannot contain LF or CR characters")
        if len(line) > MAX_GENERATED_LINE_LENGTH:
            raise ValueError("structured source line exceeds the length limit")
    return lines


class StructuredSourceEdit(StrictModel):
    """One model-owned contiguous edit within the authorized source symbol."""

    target_path: str = Field(min_length=1, max_length=500)
    target_symbol: str = Field(min_length=1, max_length=500)
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    start_line: int = Field(ge=1, le=100_000)
    delete_line_count: int = Field(ge=0, le=MAX_EDIT_LINES)
    replacement_lines: list[str] = Field(max_length=MAX_EDIT_LINES)

    @field_validator("replacement_lines")
    @classmethod
    def valid_lines(cls, value: list[str]) -> list[str]:
        return _validate_source_lines(value)

    @model_validator(mode="after")
    def coherent_range(self) -> "StructuredSourceEdit":
        if self.delete_line_count == 0 and not self.replacement_lines:
            raise ValueError("structured source edit must insert, replace, or delete")
        return self


class StructuredRegressionTest(StrictModel):
    """Exact model-owned Python lines; Gauntlet only joins them with LF."""

    lines: list[str] = Field(min_length=1, max_length=MAX_REGRESSION_LINES)

    @field_validator("lines")
    @classmethod
    def valid_lines(cls, value: list[str]) -> list[str]:
        return _validate_source_lines(value)


class GeneratedRepairCandidate(StrictModel):
    """Decoded provider content; no patch or Python semantics are implied."""

    rationale: str = Field(max_length=8_000)
    source_edit: StructuredSourceEdit
    regression_test: StructuredRegressionTest
    optional_policy_artifact: str | None = Field(default=None, max_length=16_000)


class GeneratedEditCandidate(StrictModel):
    """Decoded provider content for the source-edit call.

    Emitted by the first of the two remediation calls so the model produces
    only the rationale and the bounded structured source edit. No patch or
    Python semantics are implied until deterministic validation.
    """

    rationale: str = Field(max_length=8_000)
    source_edit: StructuredSourceEdit
    optional_policy_artifact: str | None = Field(default=None, max_length=16_000)


class GeneratedMultiEditCandidate(StrictModel):
    """One bounded edit per explicitly authorized source boundary."""

    rationale: str = Field(max_length=8_000)
    source_edits: list[StructuredSourceEdit] = Field(min_length=1, max_length=2)
    optional_policy_artifact: str | None = Field(default=None, max_length=16_000)

    @model_validator(mode="after")
    def unique_authorized_boundaries(self) -> "GeneratedMultiEditCandidate":
        targets = [
            (edit.target_path, edit.target_symbol) for edit in self.source_edits
        ]
        if len(targets) != len(set(targets)):
            raise ValueError("multi-target candidate has duplicate source boundaries")
        return self


class GeneratedTestCandidate(StrictModel):
    """Decoded provider content for the regression-test call.

    Emitted by the second of the two remediation calls, after the source edit
    has validated, so the model produces only the regression test lines.
    """

    regression_test: StructuredRegressionTest


def combine_repair_candidate(
    edit: GeneratedEditCandidate, test: GeneratedTestCandidate,
) -> GeneratedRepairCandidate:
    """Assemble the combined repair candidate from the two call outputs."""
    return GeneratedRepairCandidate(
        rationale=edit.rationale,
        source_edit=edit.source_edit,
        regression_test=test.regression_test,
        optional_policy_artifact=edit.optional_policy_artifact,
    )


FailureStage = Literal[
    "candidate_validation",
    "source_identity",
    "regression_syntax",
    "regression_structure",
    "patch_format",
    "patch_authorization",
    "patch_apply",
    "compile",
    "regression_execution",
    "security_test",
    "utility_test",
    "existing_suite",
]


class RepairFailure(StrictModel):
    failure_id: str = Field(default_factory=lambda: str(uuid4()))
    repair_id: str | None = None
    candidate_id: str = Field(default_factory=lambda: str(uuid4()))
    candidate_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_field_digests: dict[str, str]
    candidate_field_lengths: dict[str, int]
    trace_id: str
    boundary_id: str
    evidence_ids: list[str] = Field(min_length=1)
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    target_path: str
    target_symbol: str
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    failure_type: str = Field(min_length=1)
    failure_stage: FailureStage
    failure_code: str = Field(min_length=1, max_length=80)
    message: str = Field(min_length=1, max_length=500)
    diagnostics: dict[str, str | int | bool | None]
    attempt: int = Field(ge=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("failure_id", "candidate_id", "repair_id")
    @classmethod
    def valid_failure_uuid(cls, value: str | None) -> str | None:
        if value is None:
            return value
        UUID(value)
        return value


class RepairProposal(StrictModel):
    rationale: str = Field(min_length=1)
    patch: str = Field(min_length=1)
    regression_test: str = Field(min_length=1)
    optional_policy_artifact: str | None = None
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

    @field_validator("rationale")
    @classmethod
    def non_empty_rationale(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("rationale must be non-empty")
        return value

    @field_validator("optional_policy_artifact")
    @classmethod
    def non_empty_policy_when_present(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("optional_policy_artifact must be non-empty when present")
        return value

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
        changed_lines = [line for line in self.patch.splitlines()
                         if line.startswith(("+", "-"))
                         and not line.startswith(("+++ ", "--- "))]
        if headers != [expected_old, expected_new] or not any(
            line.startswith("@@") for line in self.patch.splitlines()
        ) or any("Kestrel-7749" in line for line in changed_lines):
            raise ValueError("patch must be a single-target unified diff for target_path")
        return self


class RemediationRequest(StrictModel):
    source_context: SourceContext
    repair_context: RepairContext
    evidence_summary: dict[str, Any]


class MultiTargetRemediationRequest(StrictModel):
    """Provider input containing only an explicit bounded source allowlist."""

    source_contexts: list[SourceContext] = Field(min_length=2, max_length=2)
    repair_contexts: list[RepairContext] = Field(min_length=2, max_length=2)
    evidence_summary: dict[str, Any]

    @model_validator(mode="after")
    def contexts_match(self) -> "MultiTargetRemediationRequest":
        source_targets = [
            (item.repository_relative_path, item.target_symbol, item.source_hash)
            for item in self.source_contexts
        ]
        repair_targets = [
            (item.target_path, item.target_symbol, item.source_hash)
            for item in self.repair_contexts
        ]
        if len(set(source_targets)) != len(source_targets):
            raise ValueError("authorized source contexts must be unique")
        if source_targets != repair_targets:
            raise ValueError("multi-target source and repair contexts differ")
        return self
