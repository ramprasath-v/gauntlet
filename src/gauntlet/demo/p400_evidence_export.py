"""Read-only, integrity-checked export of completed P400 live evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import quote

from gauntlet.contracts.p400_live import P400LiveEvidence
from gauntlet.contracts.p400_live_repair import P400LiveRepairEvidence
from gauntlet.contracts.p400_true_live import (
    P400LiveProofEvidence,
    repair_is_eligible_for_live_proof,
)
from gauntlet.remediation.candidate_artifact import (
    ValidatedEditArtifact,
    load_validated_edit_artifact,
)


_SECRET_KEY = re.compile(
    r"^(?:api[_-]?key|authorization|password|secret|access[_-]?token)$",
    re.IGNORECASE,
)
_SECRET_ENV_NAME = re.compile(
    r"(?:api[_-]?key|authorization|password|secret|access[_-]?token)",
    re.IGNORECASE,
)
_BEARER_VALUE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)


class InvalidEvidencePath(ValueError):
    """The requested name is outside the intentionally exportable surface."""


class UnsafeEvidence(PermissionError):
    """An otherwise addressable artifact is unsafe to export."""


def resolve_p400_json(evidence_root: Path, relative_path: str) -> Path:
    """Resolve one regular JSON file without permitting an escape from root."""
    if not relative_path or "\x00" in relative_path:
        raise InvalidEvidencePath("A relative P400 evidence path is required")
    requested = Path(relative_path)
    if requested.is_absolute() or ".." in requested.parts:
        raise InvalidEvidencePath("P400 evidence path must remain relative")
    if requested.suffix.lower() != ".json":
        raise InvalidEvidencePath("Only P400 JSON evidence can be exported")

    try:
        root = evidence_root.resolve(strict=True)
    except FileNotFoundError as exc:
        raise FileNotFoundError("P400 evidence root does not exist") from exc

    cursor = root
    for part in requested.parts:
        cursor /= part
        if cursor.is_symlink():
            raise UnsafeEvidence("Symlinked P400 evidence is not exportable")

    try:
        resolved = (root / requested).resolve(strict=True)
    except FileNotFoundError as exc:
        raise FileNotFoundError("P400 evidence file was not found") from exc
    if not resolved.is_relative_to(root):
        raise UnsafeEvidence("P400 evidence path escapes the allowed root")
    if not resolved.is_file():
        raise FileNotFoundError("P400 evidence path is not a regular file")
    return resolved


def read_safe_json(
    path: Path, credential_values: tuple[str, ...] = (),
) -> bytes:
    """Read valid JSON only after applying conservative credential checks."""
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
        document = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UnsafeEvidence("Evidence is not valid UTF-8 JSON") from exc

    def contains_secret_field(value: object) -> bool:
        if isinstance(value, dict):
            if any(_SECRET_KEY.fullmatch(str(key)) for key in value):
                return True
            return any(contains_secret_field(item) for item in value.values())
        if isinstance(value, list):
            return any(contains_secret_field(item) for item in value)
        return False

    if contains_secret_field(document) or _BEARER_VALUE.search(text):
        raise UnsafeEvidence("Evidence contains credential-shaped material")
    for name, value in os.environ.items():
        if (
            value
            and len(value) >= 8
            and _SECRET_ENV_NAME.search(name)
            and value in text
        ):
            raise UnsafeEvidence("Evidence contains a configured credential")
    if any(value and value in text for value in credential_values):
        raise UnsafeEvidence("Evidence contains a configured credential")
    return raw


def latest_success_manifest(
    evidence_root: Path, credential_values: tuple[str, ...] = (),
) -> dict[str, object]:
    """Return the newest complete, integrity-valid VERIFIED P400 evidence chain."""
    root = evidence_root.resolve(strict=True)
    proofs: list[tuple[P400LiveProofEvidence, Path]] = []
    for candidate in (root / "proof").glob("*.json"):
        try:
            path = resolve_p400_json(root, candidate.relative_to(root).as_posix())
            proof = P400LiveProofEvidence.model_validate_json(
                read_safe_json(path, credential_values)
            )
        except (OSError, ValueError):
            continue
        if proof.final_status == "VERIFIED":
            proofs.append((proof, path))
    proofs.sort(key=lambda item: item[0].created_at, reverse=True)

    for proof, proof_path in proofs:
        repair_pair = _find_by_run_id(
            root, "repair", proof.source_live_repair_run_id,
            P400LiveRepairEvidence, credential_values,
        )
        if repair_pair is None:
            continue
        repair, repair_path = repair_pair
        if (
            not repair_is_eligible_for_live_proof(repair)
            or repair.derived_patch_digest != proof.source_patch_digest
            or repair.edit_artifact is None
        ):
            continue

        attack_pair = _find_by_run_id(
            root, "attack", repair.source_live_attack_run_id, P400LiveEvidence,
            credential_values,
        )
        if attack_pair is None:
            continue
        attack, attack_path = attack_pair
        attack_bytes = read_safe_json(attack_path, credential_values)
        if (
            attack.final_status != "DETECTED"
            or hashlib.sha256(attack_bytes).hexdigest()
            != repair.source_live_attack_digest
        ):
            continue

        try:
            edit_relative = (
                repair_path.parent.relative_to(root) / repair.edit_artifact
            ).as_posix()
            edit_path = resolve_p400_json(root, edit_relative)
            read_safe_json(edit_path, credential_values)
            edit = load_validated_edit_artifact(edit_path)
        except (OSError, ValueError):
            continue
        if not _edit_matches_repair(edit, repair):
            continue

        return {
            "attack": _download_entry(root, attack_path, "run_id", attack.run_id),
            "repair": _download_entry(root, repair_path, "run_id", repair.run_id),
            "validated_edit": _download_entry(
                root, edit_path, "candidate_id", edit.edit_id,
            ),
            "proof": _download_entry(root, proof_path, "run_id", proof.run_id),
            "patch_digest": proof.source_patch_digest,
            "verified": True,
        }
    raise FileNotFoundError("No complete VERIFIED P400 live evidence is available")


def _find_by_run_id(
    root: Path,
    directory: str,
    run_id: str,
    model: type[P400LiveEvidence] | type[P400LiveRepairEvidence],
    credential_values: tuple[str, ...],
) -> tuple[P400LiveEvidence | P400LiveRepairEvidence, Path] | None:
    for candidate in (root / directory).glob("*.json"):
        try:
            path = resolve_p400_json(root, candidate.relative_to(root).as_posix())
            evidence = model.model_validate_json(
                read_safe_json(path, credential_values)
            )
        except (OSError, ValueError):
            continue
        if evidence.run_id == run_id:
            return evidence, path
    return None


def _edit_matches_repair(
    edit: ValidatedEditArtifact, repair: P400LiveRepairEvidence,
) -> bool:
    return bool(
        repair.edit_candidate is not None
        and repair.derived_patch is not None
        and repair.derived_patch_digest is not None
        and edit.run_id == repair.run_id
        and edit.edit_candidate() == repair.edit_candidate
        and edit.derived_patch == repair.derived_patch
        and edit.derived_patch_digest == repair.derived_patch_digest
        and edit.source_hash == repair.contract_request.source_context.source_hash
        and edit.target_symbol
        == repair.contract_request.source_context.target_symbol
    )


def _download_entry(
    root: Path, path: Path, identity_name: str, identity: str,
) -> dict[str, str]:
    relative = path.relative_to(root).as_posix()
    return {
        identity_name: identity,
        "path": relative,
        "download_url": (
            "/api/p400/evidence/export?path=" + quote(relative, safe="")
        ),
    }
