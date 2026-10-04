"""Bounded validation and mechanical materialization for multi-target repairs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from gauntlet.remediation.models import (
    GeneratedEditCandidate,
    GeneratedMultiEditCandidate,
    RepairContext,
    RepairFailure,
)
from gauntlet.remediation.validation import validate_source_edit


@dataclass(frozen=True)
class MaterializedSourceEdit:
    candidate: GeneratedEditCandidate
    context: RepairContext
    trusted_original_lines: tuple[str, ...]
    derived_patch: str
    patch_digest: str


@dataclass(frozen=True)
class MaterializedMultiEdit:
    candidate: GeneratedMultiEditCandidate
    edits: tuple[MaterializedSourceEdit, ...]
    combined_patch: str
    combined_patch_digest: str
    candidate_digest: str


def validate_multi_target_edit(
    candidate: GeneratedMultiEditCandidate,
    repair_contexts: list[RepairContext],
    repository_root: Path,
) -> MaterializedMultiEdit | RepairFailure:
    """Validate every edit before returning one mechanically combined patch."""
    contexts = {
        (context.target_path, context.target_symbol): context
        for context in repair_contexts
    }
    if len(contexts) != len(repair_contexts):
        raise ValueError("authorized repair boundaries must be unique")

    requested = {
        (edit.target_path, edit.target_symbol): edit
        for edit in candidate.source_edits
    }
    unknown = sorted(set(requested) - set(contexts))
    if unknown:
        first = requested[unknown[0]]
        context = repair_contexts[0]
        wrapped = GeneratedEditCandidate(
            rationale=candidate.rationale,
            source_edit=first,
            optional_policy_artifact=candidate.optional_policy_artifact,
        )
        # Reuse the trusted validator's stable authorization failure shape.
        failure = validate_source_edit(wrapped, context, repository_root)
        assert isinstance(failure, RepairFailure)
        return failure

    materialized: list[MaterializedSourceEdit] = []
    # Authorization order, rather than provider order, makes combined bytes stable.
    for context in repair_contexts:
        source_edit = requested.get((context.target_path, context.target_symbol))
        if source_edit is None:
            continue
        wrapped = GeneratedEditCandidate(
            rationale=candidate.rationale,
            source_edit=source_edit,
            optional_policy_artifact=candidate.optional_policy_artifact,
        )
        output: dict[str, object] = {}
        result = validate_source_edit(
            wrapped, context, repository_root, materialized_output=output,
        )
        if isinstance(result, RepairFailure):
            return result
        materialized.append(MaterializedSourceEdit(
            candidate=wrapped,
            context=context,
            trusted_original_lines=tuple(
                str(line) for line in output["trusted_original_lines"]
            ),
            derived_patch=result,
            patch_digest=hashlib.sha256(result.encode()).hexdigest(),
        ))

    if not materialized:
        raise ValueError("multi-target candidate contains no authorized edits")
    combined = "".join(edit.derived_patch for edit in materialized)
    canonical_candidate = json.dumps(
        candidate.model_dump(mode="json"),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return MaterializedMultiEdit(
        candidate=candidate,
        edits=tuple(materialized),
        combined_patch=combined,
        combined_patch_digest=hashlib.sha256(combined.encode()).hexdigest(),
        candidate_digest=hashlib.sha256(canonical_candidate.encode()).hexdigest(),
    )
