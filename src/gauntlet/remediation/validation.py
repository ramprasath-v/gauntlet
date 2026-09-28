"""Deterministic boundary from untrusted repair candidate to trusted result."""
import ast
import json
from hashlib import sha256
from uuid import uuid4

from gauntlet.remediation.models import (
    FailureStage,
    GeneratedRepairCandidate,
    RegressionTestSyntaxError,
    RepairContext,
    RepairFailure,
    RepairProposal,
)


def _digest(value: str | None) -> str:
    serialized = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    return sha256(serialized.encode()).hexdigest()


def _failure(
    candidate: GeneratedRepairCandidate,
    context: RepairContext,
    candidate_id: str,
    *,
    stage: FailureStage,
    code: str,
    message: str,
    diagnostics: dict[str, str | int | bool | None],
    attempt: int,
) -> RepairFailure:
    fields = candidate.model_dump(mode="json")
    return RepairFailure(
        candidate_id=candidate_id,
        candidate_digest=sha256(candidate.model_dump_json().encode()).hexdigest(),
        candidate_field_digests={name: _digest(value) for name, value in fields.items()},
        candidate_field_lengths={
            name: len(value) if isinstance(value, str) else 0
            for name, value in fields.items()
        },
        trace_id=context.trace_id,
        boundary_id=context.boundary_id,
        evidence_ids=context.evidence_ids,
        provider=context.provider,
        model=context.model,
        target_path=context.target_path,
        target_symbol=context.target_symbol,
        source_hash=context.source_hash,
        failure_type=context.failure_type,
        failure_stage=stage,
        failure_code=code,
        message=message,
        diagnostics=diagnostics,
        attempt=attempt,
    )


def validate_candidate(
    candidate: GeneratedRepairCandidate,
    repair_context: RepairContext,
    *,
    attempt: int = 1,
) -> RepairProposal | RepairFailure:
    """Validate in fixed order and never repair model-generated artifacts."""
    candidate_id = str(uuid4())

    if not candidate.rationale.strip():
        return _failure(
            candidate, repair_context, candidate_id,
            stage="candidate_validation", code="empty_rationale",
            message="Candidate rationale must be non-empty.",
            diagnostics={"field": "rationale"}, attempt=attempt,
        )

    lines = candidate.patch.splitlines()
    headers = [line for line in lines
               if line.startswith("--- ") or line.startswith("+++ ")]
    structurally_valid = (
        len(headers) == 2
        and headers[0].startswith("--- a/")
        and headers[1].startswith("+++ b/")
        and headers[0][6:] == headers[1][6:]
        and any(line.startswith("@@") for line in lines)
    )
    if not structurally_valid:
        return _failure(
            candidate, repair_context, candidate_id,
            stage="patch_format", code="invalid_unified_diff",
            message="Candidate patch is not a single-target unified diff.",
            diagnostics={"header_count": len(headers), "has_hunk": any(
                line.startswith("@@") for line in lines
            )}, attempt=attempt,
        )

    expected_headers = [
        f"--- a/{repair_context.target_path}",
        f"+++ b/{repair_context.target_path}",
    ]
    changed_lines = [line for line in lines
                     if line.startswith(("+", "-"))
                     and not line.startswith(("+++ ", "--- "))]
    if headers != expected_headers or any(
        "Kestrel-7749" in line for line in changed_lines
    ):
        return _failure(
            candidate, repair_context, candidate_id,
            stage="patch_authorization", code="unauthorized_patch_target",
            message="Candidate patch exceeds the authorized source target.",
            diagnostics={
                "expected_target": repair_context.target_path,
                "header_match": headers == expected_headers,
                "canary_literal_changed": any(
                    "Kestrel-7749" in line for line in changed_lines
                ),
            }, attempt=attempt,
        )

    try:
        tree = ast.parse(candidate.regression_test)
    except SyntaxError as exc:
        diagnostic = RegressionTestSyntaxError(candidate.regression_test, exc)
        return _failure(
            candidate, repair_context, candidate_id,
            stage="regression_syntax", code="invalid_python",
            message="Candidate regression test is not valid Python source.",
            diagnostics={
                "syntax_message": diagnostic.syntax_message,
                "line": diagnostic.line,
                "offset": diagnostic.offset,
                "source_length": diagnostic.source_length,
                "window": diagnostic.diagnostic_window,
            }, attempt=attempt,
        )

    tests = [node for node in tree.body
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
             and node.name.startswith("test_")]
    if not tests:
        return _failure(
            candidate, repair_context, candidate_id,
            stage="regression_structure", code="missing_test_function",
            message="Candidate regression test has no test_* function.",
            diagnostics={"top_level_test_count": 0}, attempt=attempt,
        )
    assertion_count = sum(
        isinstance(node, ast.Assert) for test in tests for node in ast.walk(test)
    )
    if assertion_count == 0:
        return _failure(
            candidate, repair_context, candidate_id,
            stage="regression_structure", code="missing_assertion",
            message="Candidate regression test has no assertion in a test function.",
            diagnostics={"top_level_test_count": len(tests), "assertion_count": 0},
            attempt=attempt,
        )

    if (candidate.optional_policy_artifact is not None
            and not candidate.optional_policy_artifact.strip()):
        return _failure(
            candidate, repair_context, candidate_id,
            stage="candidate_validation", code="empty_policy_artifact",
            message="Optional policy artifact must be non-empty when present.",
            diagnostics={"field": "optional_policy_artifact"}, attempt=attempt,
        )

    return RepairProposal(
        repair_id=str(uuid4()),
        **repair_context.model_dump(),
        **candidate.model_dump(),
    )
