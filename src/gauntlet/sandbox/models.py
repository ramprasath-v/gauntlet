from datetime import datetime, timezone
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel


class CommandCategory(StrEnum):
    BUILD = "BUILD"
    TEST = "TEST"
    PATCH_APPLY = "PATCH_APPLY"
    GENERATED_REGRESSION = "GENERATED_REGRESSION"
    SECURITY = "SECURITY"
    UTILITY = "UTILITY"
    EXISTING_SUITE = "EXISTING_SUITE"


class FailureCategory(StrEnum):
    PATCH_APPLY_FAILED = "PATCH_APPLY_FAILED"
    BUILD_FAILED = "BUILD_FAILED"
    TEST_FAILED = "TEST_FAILED"
    UTILITY_REGRESSION = "UTILITY_REGRESSION"


class PatchApplicationResult(BaseModel):
    patch_id: str
    workspace_id: str
    target_file: str
    target_symbol: str
    applied: bool
    files_changed: list[str]
    error: str | None = None
    timestamp: datetime


class CommandResult(BaseModel):
    category: CommandCategory
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    workspace_id: str
    working_directory: str
    timed_out: bool = False

    @property
    def passed(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class RepairFailure(BaseModel):
    category: FailureCategory
    attempt: int
    workspace_id: str
    summary: str
    patch_result: PatchApplicationResult | None = None
    command_result: CommandResult | None = None


class SourceContext(BaseModel):
    file: str
    symbol: str
    content: str


class RepairProposal(BaseModel):
    patch_id: str
    target_file: str
    target_symbol: str
    control: str
    source_failure_category: FailureCategory


class SandboxRepairResult(BaseModel):
    succeeded: bool
    attempts: int
    max_attempts: int
    workspace_id: str
    workspace_path: str
    source_revision: str | None
    workspace_cleaned: bool
    original_workspace_unchanged: bool
    outside_writes: Literal["NONE", "DETECTED"]
    patch_result: PatchApplicationResult | None
    build_result: CommandResult | None
    test_result: CommandResult | None
    failures: list[RepairFailure]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
