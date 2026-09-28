import ast
from hashlib import sha256
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


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


class RepairProposal(StrictModel):
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
    rationale: str = Field(min_length=1)
    patch: str = Field(min_length=1)
    regression_test: str = Field(min_length=1)
    optional_policy_artifact: str | None = None

    @field_validator("repair_id")
    @classmethod
    def valid_repair_id(cls, value: str) -> str:
        UUID(value)
        return value

    @field_validator("regression_test")
    @classmethod
    def executable_test_source(cls, value: str) -> str:
        try:
            tree = ast.parse(value)
        except SyntaxError as exc:
            raise ValueError("regression_test must be valid Python source") from exc
        tests = [node for node in tree.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and node.name.startswith("test_")]
        if not tests or not any(isinstance(node, ast.Assert)
                                for test in tests for node in ast.walk(test)):
            raise ValueError("regression_test must contain a test function with an assertion")
        return value

    @model_validator(mode="after")
    def machine_applicable_single_target_patch(self) -> "RepairProposal":
        expected_old = f"--- a/{self.target_path}"
        expected_new = f"+++ b/{self.target_path}"
        headers = [line for line in self.patch.splitlines()
                   if line.startswith("--- ") or line.startswith("+++ ")]
        if headers != [expected_old, expected_new] or "@@" not in self.patch:
            raise ValueError("patch must be a single-target unified diff for target_path")
        return self


class RemediationRequest(StrictModel):
    source_context: SourceContext
    failure_type: str
    provider: str
    model: str
    evidence_summary: dict[str, Any]
