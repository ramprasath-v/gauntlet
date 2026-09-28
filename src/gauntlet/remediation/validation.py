"""Deterministic boundary from untrusted repair candidate to trusted result."""
import ast
import difflib
import json
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from gauntlet.remediation.models import (
    FailureStage,
    GeneratedEditCandidate,
    GeneratedRepairCandidate,
    GeneratedTestCandidate,
    RegressionTestSyntaxError,
    RepairContext,
    RepairFailure,
    RepairProposal,
    StrictModel,
)


def _digest(value: str | None) -> str:
    serialized = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    return sha256(serialized.encode()).hexdigest()


def combined_candidate_identity(
    candidate: GeneratedRepairCandidate,
) -> tuple[str, dict[str, str], dict[str, int]]:
    fields = candidate.model_dump(mode="json")
    return (
        sha256(candidate.model_dump_json().encode()).hexdigest(),
        {name: _digest(value) for name, value in fields.items()},
        {
            name: len(value) if isinstance(value, str) else len(
                json.dumps(value, ensure_ascii=True, separators=(",", ":"))
            )
            for name, value in fields.items()
        },
    )


def restamp_failure_identity(
    failure: RepairFailure, candidate: GeneratedRepairCandidate,
) -> RepairFailure:
    """Normalize a part-level failure to the combined candidate identity."""
    digest, field_digests, field_lengths = combined_candidate_identity(candidate)
    return failure.model_copy(update={
        "candidate_digest": digest,
        "candidate_field_digests": field_digests,
        "candidate_field_lengths": field_lengths,
    })


def _failure(
    part: StrictModel,
    context: RepairContext,
    candidate_id: str,
    *,
    stage: FailureStage,
    code: str,
    message: str,
    diagnostics: dict[str, str | int | bool | None],
    attempt: int,
) -> RepairFailure:
    fields = part.model_dump(mode="json")
    return RepairFailure(
        candidate_id=candidate_id,
        candidate_digest=sha256(part.model_dump_json().encode()).hexdigest(),
        candidate_field_digests={name: _digest(value) for name, value in fields.items()},
        candidate_field_lengths={
            name: len(value) if isinstance(value, str) else len(
                json.dumps(value, ensure_ascii=True, separators=(",", ":"))
            )
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


def _resolve_symbol_source(
    edit: GeneratedEditCandidate,
    repair_context: RepairContext,
    repository_root: Path,
    candidate_id: str,
    *,
    attempt: int,
) -> tuple[str, list[str], list[str], int, int] | RepairFailure:
    """Resolve the authorized symbol.

    Returns (original_text, full_lines, symbol_lines, symbol_start, symbol_end).
    """
    root = repository_root.resolve(strict=True)
    relative = Path(repair_context.target_path)
    target = None
    if not relative.is_absolute() and ".." not in relative.parts:
        try:
            target = (root / relative).resolve(strict=True)
        except OSError:
            target = None
    if (target is None or not target.is_relative_to(root) or not target.is_file()):
        return _failure(
            edit, repair_context, candidate_id,
            stage="patch_authorization", code="authorized_target_unreadable",
            message="Trusted repair target could not be resolved safely.",
            diagnostics={"target_path": repair_context.target_path}, attempt=attempt,
        )

    try:
        source = target.read_bytes().decode("utf-8")
    except UnicodeDecodeError as exc:
        return _failure(
            edit, repair_context, candidate_id,
            stage="source_identity", code="authorized_source_not_utf8",
            message="Trusted authorized source is not valid UTF-8.",
            diagnostics={"error_type": type(exc).__name__}, attempt=attempt,
        )
    if "\r" in source:
        return _failure(
            edit, repair_context, candidate_id,
            stage="source_identity", code="unsupported_source_line_endings",
            message="Structured edits require LF source without normalization.",
            diagnostics={"contains_carriage_return": True}, attempt=attempt,
        )
    try:
        tree = ast.parse(source)
        class_name, method_name = repair_context.target_symbol.split(".")
        class_node = next(
            (node for node in tree.body
             if isinstance(node, ast.ClassDef) and node.name == class_name), None,
        )
        method = next(
            (node for node in class_node.body
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
             and node.name == method_name), None,
        ) if class_node else None
        if method is None or method.end_lineno is None:
            raise ValueError("authorized symbol is missing")
    except (SyntaxError, ValueError) as exc:
        return _failure(
            edit, repair_context, candidate_id,
            stage="source_identity", code="authorized_symbol_unreadable",
            message="Trusted authorized symbol could not be identified.",
            diagnostics={"error_type": type(exc).__name__}, attempt=attempt,
        )

    source_lines_with_endings = source.splitlines(keepends=True)
    full_lines = source.splitlines()
    symbol_start = method.lineno - 1
    symbol_end = method.end_lineno
    symbol_lines = full_lines[symbol_start:symbol_end]
    bounded_source = "".join(source_lines_with_endings[symbol_start:symbol_end])
    observed_hash = sha256(bounded_source.encode()).hexdigest()
    if observed_hash != repair_context.source_hash:
        return _failure(
            edit, repair_context, candidate_id,
            stage="source_identity", code="current_source_hash_mismatch",
            message="Current authorized source differs from trusted RepairContext.",
            diagnostics={
                "expected_source_hash": repair_context.source_hash,
                "observed_source_hash": observed_hash,
            }, attempt=attempt,
        )
    return source, full_lines, symbol_lines, symbol_start, symbol_end


def validate_source_edit(
    edit: GeneratedEditCandidate,
    repair_context: RepairContext,
    repository_root: Path,
    *,
    attempt: int = 1,
    materialized_output: dict[str, str] | None = None,
) -> str | RepairFailure:
    """Validate the source-edit call output; return the derived patch or failure."""
    candidate_id = str(uuid4())

    if not edit.rationale.strip():
        return _failure(
            edit, repair_context, candidate_id,
            stage="candidate_validation", code="empty_rationale",
            message="Candidate rationale must be non-empty.",
            diagnostics={"field": "rationale"}, attempt=attempt,
        )

    source_edit = edit.source_edit
    if (source_edit.target_path != repair_context.target_path
            or source_edit.target_symbol != repair_context.target_symbol):
        return _failure(
            edit, repair_context, candidate_id,
            stage="patch_authorization", code="unauthorized_edit_target",
            message="Structured edit does not match the authorized target.",
            diagnostics={
                "path_match": source_edit.target_path == repair_context.target_path,
                "symbol_match": source_edit.target_symbol == repair_context.target_symbol,
            }, attempt=attempt,
        )

    if source_edit.source_hash != repair_context.source_hash:
        return _failure(
            edit, repair_context, candidate_id,
            stage="source_identity", code="candidate_source_hash_mismatch",
            message="Structured edit does not reference the trusted source revision.",
            diagnostics={
                "expected_source_hash": repair_context.source_hash,
                "candidate_source_hash": source_edit.source_hash,
            }, attempt=attempt,
        )

    resolved = _resolve_symbol_source(
        edit, repair_context, repository_root, candidate_id, attempt=attempt,
    )
    if isinstance(resolved, RepairFailure):
        return resolved
    original_text, full_lines, symbol_lines, symbol_start, symbol_end = resolved

    start = source_edit.start_line - 1
    end = start + source_edit.delete_line_count
    valid_range = (
        0 <= start <= len(symbol_lines)
        and end <= len(symbol_lines)
        and (source_edit.delete_line_count == 0 or start < len(symbol_lines))
    )
    if not valid_range:
        return _failure(
            edit, repair_context, candidate_id,
            stage="patch_authorization", code="edit_range_outside_symbol",
            message="Structured edit range is outside the authorized symbol.",
            diagnostics={
                "start_line": source_edit.start_line,
                "delete_line_count": source_edit.delete_line_count,
                "symbol_line_count": len(symbol_lines),
            }, attempt=attempt,
        )

    observed_original = symbol_lines[start:end]
    if observed_original != source_edit.expected_original_lines:
        return _failure(
            edit, repair_context, candidate_id,
            stage="source_identity", code="expected_original_lines_mismatch",
            message="Structured edit does not match the selected source slice.",
            diagnostics={
                "start_line": source_edit.start_line,
                "expected_line_count": len(source_edit.expected_original_lines),
                "observed_line_count": len(observed_original),
            }, attempt=attempt,
        )

    patched_symbol_lines = (
        symbol_lines[:start] + source_edit.replacement_lines + symbol_lines[end:]
    )
    patched_lines = (
        full_lines[:symbol_start] + patched_symbol_lines + full_lines[symbol_end:]
    )
    patched_source = "\n".join(patched_lines) + ("\n" if original_text.endswith("\n") else "")
    if patched_source == original_text:
        return _failure(
            edit, repair_context, candidate_id,
            stage="candidate_validation", code="source_edit_noop",
            message="Structured edit does not change the authorized source.",
            diagnostics={"start_line": source_edit.start_line}, attempt=attempt,
        )

    patch = "".join(difflib.unified_diff(
        original_text.splitlines(keepends=True),
        patched_source.splitlines(keepends=True),
        fromfile=f"a/{repair_context.target_path}",
        tofile=f"b/{repair_context.target_path}",
    ))
    changed_lines = [
        line for line in patch.splitlines()
        if line.startswith(("+", "-"))
        and not line.startswith(("+++ ", "--- "))
    ]
    if any("Kestrel-7749" in line for line in changed_lines):
        return _failure(
            edit, repair_context, candidate_id,
            stage="patch_authorization", code="canary_literal_changed",
            message="Structured edit attempts to change the verifier canary literal.",
            diagnostics={"canary_literal_changed": True}, attempt=attempt,
        )

    if (edit.optional_policy_artifact is not None
            and not edit.optional_policy_artifact.strip()):
        return _failure(
            edit, repair_context, candidate_id,
            stage="candidate_validation", code="empty_policy_artifact",
            message="Optional policy artifact must be non-empty when present.",
            diagnostics={"field": "optional_policy_artifact"}, attempt=attempt,
        )

    if materialized_output is not None:
        materialized_output["patch"] = patch
    return patch


def validate_regression_test(
    test: GeneratedTestCandidate,
    repair_context: RepairContext,
    *,
    attempt: int = 1,
    materialized_output: dict[str, str] | None = None,
) -> str | RepairFailure:
    """Validate the regression-test call output; return test source or failure."""
    candidate_id = str(uuid4())

    regression_test = "\n".join(test.regression_test.lines) + "\n"
    if materialized_output is not None:
        materialized_output["regression_test"] = regression_test

    try:
        tree = ast.parse(regression_test)
    except SyntaxError as exc:
        diagnostic = RegressionTestSyntaxError(regression_test, exc)
        return _failure(
            test, repair_context, candidate_id,
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
            test, repair_context, candidate_id,
            stage="regression_structure", code="missing_test_function",
            message="Candidate regression test has no test_* function.",
            diagnostics={"top_level_test_count": 0}, attempt=attempt,
        )
    assertion_count = sum(
        isinstance(node, ast.Assert) for test in tests for node in ast.walk(test)
    )
    if assertion_count == 0:
        return _failure(
            test, repair_context, candidate_id,
            stage="regression_structure", code="missing_assertion",
            message="Candidate regression test has no assertion in a test function.",
            diagnostics={"top_level_test_count": len(tests), "assertion_count": 0},
            attempt=attempt,
        )
    return regression_test


def validate_candidate(
    candidate: GeneratedRepairCandidate,
    repair_context: RepairContext,
    repository_root: Path,
    *,
    attempt: int = 1,
    materialized_output: dict[str, str] | None = None,
) -> RepairProposal | RepairFailure:
    """Validate in fixed order and never repair model-generated artifacts."""
    materialized: dict[str, str] = {}
    edit = GeneratedEditCandidate(
        rationale=candidate.rationale,
        source_edit=candidate.source_edit,
        optional_policy_artifact=candidate.optional_policy_artifact,
    )
    patch_or_failure = validate_source_edit(
        edit, repair_context, repository_root,
        attempt=attempt, materialized_output=materialized,
    )
    if isinstance(patch_or_failure, RepairFailure):
        return restamp_failure_identity(patch_or_failure, candidate)
    test = GeneratedTestCandidate(regression_test=candidate.regression_test)
    test_or_failure = validate_regression_test(
        test, repair_context, attempt=attempt, materialized_output=materialized,
    )
    if isinstance(test_or_failure, RepairFailure):
        return restamp_failure_identity(test_or_failure, candidate)

    if materialized_output is not None:
        materialized_output.update(materialized)
    return RepairProposal(
        repair_id=str(uuid4()),
        **repair_context.model_dump(),
        rationale=candidate.rationale,
        patch=materialized["patch"],
        regression_test=materialized["regression_test"],
        optional_policy_artifact=candidate.optional_policy_artifact,
    )
