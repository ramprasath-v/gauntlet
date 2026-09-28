from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from gauntlet.remediation.candidate_artifact import (
    CANDIDATE_ARTIFACT_SCHEMA_VERSION, candidate_identity,
    load_candidate_artifact, persist_candidate_artifact,
)
from gauntlet.remediation.models import GeneratedRepairCandidate
from gauntlet.sandbox.workspace import repository_digest


ROOT = Path(__file__).parents[1]
TARGET = "victims/customer_support/agent.py"


def candidate(kind: str) -> GeneratedRepairCandidate:
    patch = (
        f"--- a/{TARGET}\n+++ b/{TARGET}\n"
        "@@ -1 +1 @@\n-old\n+new\n"
    )
    regression = "def test_boundary():\n    assert True\n"
    if kind == "malformed_diff":
        patch = f"--- a/{TARGET}\n+replacement without hunk\n"
    if kind == "malformed_python":
        regression = "def test_boundary(:\n    assert True\n"
    return GeneratedRepairCandidate(
        rationale="Exact rationale.\nSecond line remains exact.",
        patch=patch,
        regression_test=regression,
        optional_policy_artifact="Exact policy artifact.",
    )


def persist(value: GeneratedRepairCandidate, path: Path):
    return persist_candidate_artifact(
        value,
        path=path,
        candidate_id=str(uuid4()),
        run_id=str(uuid4()),
        attempt_number=1,
        provider="offline_scripted_provider",
        model="nvidia/Nemotron-3_5-Lightning",
        trace_id="trace-id",
        boundary_id="boundary-id",
        evidence_ids=["evidence-id"],
        target_path=TARGET,
        target_symbol="CustomerSupportAgent.chat",
        source_hash="0" * 64,
    )


@pytest.mark.parametrize("kind", [
    "malformed_diff", "malformed_python", "valid",
])
def test_candidate_artifact_preserves_decoded_fields_exactly(kind, tmp_path):
    original = candidate(kind)
    path = tmp_path / f"{kind}.json"
    artifact = persist(original, path)
    loaded = load_candidate_artifact(path)

    assert loaded.schema_version == CANDIDATE_ARTIFACT_SCHEMA_VERSION
    assert loaded.candidate() == original
    assert loaded.rationale == original.rationale
    assert loaded.patch == original.patch
    assert loaded.regression_test == original.regression_test
    assert loaded.optional_policy_artifact == original.optional_policy_artifact
    expected_digest, expected_fields = candidate_identity(original)
    assert loaded.candidate_digest == expected_digest
    assert loaded.candidate_field_digests == expected_fields
    assert loaded.integrity_digest == artifact.integrity_digest

    if kind == "malformed_diff":
        path.write_text(path.read_text().replace("replacement", "tampered", 1))
        with pytest.raises(ValidationError, match="integrity failed"):
            load_candidate_artifact(path)


def test_candidate_artifact_excludes_external_secrets_and_preserves_repository(
    tmp_path, monkeypatch
):
    external_secret = "synthetic-external-key-not-for-artifacts"
    monkeypatch.setenv("NEBIUS_API_KEY", external_secret)
    before = repository_digest(ROOT)
    path = tmp_path / "candidate.json"
    persist(candidate("valid"), path)
    serialized = path.read_text()

    assert external_secret not in serialized
    assert "authorization" not in serialized.lower()
    assert "request_headers" not in serialized.lower()
    assert "reasoning_content" not in serialized.lower()
    assert '"reasoning"' not in serialized.lower()
    assert repository_digest(ROOT) == before
