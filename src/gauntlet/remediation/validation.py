"""Deterministic boundary from untrusted repair candidate to trusted result."""
import ast
import difflib
import json
from hashlib import sha256
from pathlib import Path
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


def validate_candidate(
    candidate: GeneratedRepairCandidate,
    repair_context: RepairContext,
    repository_root: Path,
    *,
    attempt: int = 1,
    materialized_output: dict[str, str] | None = None,
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

    edit = candidate.source_edit
    if (edit.target_path != repair_context.target_path
            or edit.target_symbol != repair_context.target_symbol):
        return _failure(
            candidate, repair_context, candidate_id,
            stage="patch_authorization", code="unauthorized_edit_target",
            message="Structured edit does not match the authorized target.",
            diagnostics={
                "path_match": edit.target_path == repair_context.target_path,
                "symbol_match": edit.target_symbol == repair_context.target_symbol,
            }, attempt=attempt,
        )

    if edit.source_hash != repair_context.source_hash:
        return _failure(
            candidate, repair_context, candidate_id,
            stage="source_identity", code="candidate_source_hash_mismatch",
            message="Structured edit does not reference the trusted source revision.",
            diagnostics={
                "expected_source_hash": repair_context.source_hash,
                "candidate_source_hash": edit.source_hash,
            }, attempt=attempt,
        )

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
            candidate, repair_context, candidate_id,
            stage="patch_authorization", code="authorized_target_unreadable",
            message="Trusted repair target could not be resolved safely.",
            diagnostics={"target_path": repair_context.target_path}, attempt=attempt,
        )

    try:
        source = target.read_bytes().decode("utf-8")
    except UnicodeDecodeError as exc:
        return _failure(
            candidate, repair_context, candidate_id,
            stage="source_identity", code="authorized_source_not_utf8",
            message="Trusted authorized source is not valid UTF-8.",
            diagnostics={"error_type": type(exc).__name__}, attempt=attempt,
        )
    if "\r" in source:
        return _failure(
            candidate, repair_context, candidate_id,
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
            candidate, repair_context, candidate_id,
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
            candidate, repair_context, candidate_id,
            stage="source_identity", code="current_source_hash_mismatch",
            message="Current authorized source differs from trusted RepairContext.",
            diagnostics={
                "expected_source_hash": repair_context.source_hash,
                "observed_source_hash": observed_hash,
            }, attempt=attempt,
        )

    start = edit.start_line - 1
    end = start + edit.delete_line_count
    valid_range = (
        0 <= start <= len(symbol_lines)
        and end <= len(symbol_lines)
        and (edit.delete_line_count == 0 or start < len(symbol_lines))
    )
    if not valid_range:
        return _failure(
            candidate, repair_context, candidate_id,
            stage="patch_authorization", code="edit_range_outside_symbol",
            message="Structured edit range is outside the authorized symbol.",
            diagnostics={
                "start_line": edit.start_line,
                "delete_line_count": edit.delete_line_count,
                "symbol_line_count": len(symbol_lines),
            }, attempt=attempt,
        )

    observed_original = symbol_lines[start:end]
    if observed_original != edit.expected_original_lines:
        return _failure(
            candidate, repair_context, candidate_id,
            stage="source_identity", code="expected_original_lines_mismatch",
            message="Structured edit does not match the selected source slice.",
            diagnostics={
                "start_line": edit.start_line,
                "expected_line_count": len(edit.expected_original_lines),
                "observed_line_count": len(observed_original),
            }, attempt=attempt,
        )

    patched_symbol_lines = (
        symbol_lines[:start] + edit.replacement_lines + symbol_lines[end:]
    )
    patched_lines = (
        full_lines[:symbol_start] + patched_symbol_lines + full_lines[symbol_end:]
    )
    patched_source = "\n".join(patched_lines) + ("\n" if source.endswith("\n") else "")
    if patched_source == source:
        return _failure(
            candidate, repair_context, candidate_id,
            stage="candidate_validation", code="source_edit_noop",
            message="Structured edit does not change the authorized source.",
            diagnostics={"start_line": edit.start_line}, attempt=attempt,
        )

    patch = "".join(difflib.unified_diff(
        source.splitlines(keepends=True),
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
            candidate, repair_context, candidate_id,
            stage="patch_authorization", code="canary_literal_changed",
            message="Structured edit attempts to change the verifier canary literal.",
            diagnostics={"canary_literal_changed": True}, attempt=attempt,
        )

    regression_test = "\n".join(candidate.regression_test.lines) + "\n"
    if materialized_output is not None:
        materialized_output.update({
            "patch": patch,
            "regression_test": regression_test,
        })

    try:
        tree = ast.parse(regression_test)
    except SyntaxError as exc:
        diagnostic = RegressionTestSyntaxError(regression_test, exc)
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
        rationale=candidate.rationale,
        patch=patch,
        regression_test=regression_test,
        optional_policy_artifact=candidate.optional_policy_artifact,
    )
