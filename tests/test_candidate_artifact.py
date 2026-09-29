from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from gauntlet.remediation.candidate_artifact import (
    CANDIDATE_ARTIFACT_SCHEMA_VERSION,
    LEGACY_CANDIDATE_ARTIFACT_SCHEMA_VERSION,
    STRUCTURED_V2_CANDIDATE_ARTIFACT_SCHEMA_VERSION,
    LegacyGeneratedRepairCandidateV2,
    LegacyGeneratedRepairCandidate,
    LegacyStructuredSourceEditV2,
    LegacyRepairCandidateArtifact,
    RepairCandidateArtifactV2,
    _artifact_digest,
    edit_candidate_identity,
    _legacy_candidate_identity,
    candidate_identity,
    load_candidate_artifact,
    load_validated_edit_artifact,
    persist_candidate_artifact,
    persist_validated_edit_artifact,
)
from gauntlet.remediation.models import (
    GeneratedEditCandidate, GeneratedRepairCandidate, StructuredRegressionTest,
    StructuredSourceEdit,
)
from gauntlet.sandbox.workspace import repository_digest


ROOT = Path(__file__).parents[1]
TARGET = "victims/customer_support/agent.py"


def candidate() -> GeneratedRepairCandidate:
    return GeneratedRepairCandidate(
        rationale="Exact rationale.",
        source_edit=StructuredSourceEdit(
            target_path=TARGET,
            target_symbol="CustomerSupportAgent.chat",
            source_hash="0" * 64,
            start_line=2,
            delete_line_count=1,
            replacement_lines=["        new_value = True"],
        ),
        regression_test=StructuredRegressionTest(lines=[
            "def test_boundary():", "    assert True",
        ]),
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
        derived_patch=(
            f"--- a/{TARGET}\n+++ b/{TARGET}\n"
            "@@ -1 +1 @@\n-old_value = True\n+new_value = True\n"
        ),
        derived_regression_test="def test_boundary():\n    assert True\n",
    )


def test_candidate_artifact_preserves_structured_and_derived_content_exactly(tmp_path):
    original = candidate()
    path = tmp_path / "candidate.json"
    artifact = persist(original, path)
    loaded = load_candidate_artifact(path)

    assert loaded.schema_version == CANDIDATE_ARTIFACT_SCHEMA_VERSION
    assert loaded.candidate() == original
    assert loaded.source_edit == original.source_edit
    assert loaded.regression_test == original.regression_test
    assert loaded.derived_patch == artifact.derived_patch
    assert loaded.derived_regression_test == artifact.derived_regression_test
    expected_digest, expected_fields = candidate_identity(original)
    assert loaded.candidate_digest == expected_digest
    assert loaded.candidate_field_digests == expected_fields
    assert loaded.integrity_digest == artifact.integrity_digest


def test_validated_edit_artifact_is_incomplete_integrity_bound_evidence(tmp_path):
    complete = candidate()
    edit = GeneratedEditCandidate(
        rationale=complete.rationale,
        source_edit=complete.source_edit,
        optional_policy_artifact=complete.optional_policy_artifact,
    )
    path = tmp_path / "validated-edit.json"
    artifact = persist_validated_edit_artifact(
        edit,
        path=path,
        edit_id=str(uuid4()),
        run_id=str(uuid4()),
        originating_attempt=1,
        provider="offline_scripted_provider",
        model="Qwen/Qwen3.5-397B-A17B",
        trace_id="trace-id",
        boundary_id="boundary-id",
        evidence_ids=["evidence-id"],
        target_path=TARGET,
        target_symbol="CustomerSupportAgent.chat",
        source_hash="0" * 64,
        trusted_original_lines=["        old_value = True"],
        derived_patch="--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n",
    )

    loaded = load_validated_edit_artifact(path)
    digest, fields = edit_candidate_identity(edit)
    assert loaded.validation_result == "PASS"
    assert loaded.edit_candidate() == edit
    assert loaded.edit_candidate_digest == digest
    assert loaded.edit_field_digests == fields
    assert loaded.trusted_original_lines == ["        old_value = True"]
    assert loaded.derived_patch == artifact.derived_patch
    assert not hasattr(loaded, "regression_test")

    path.write_text(path.read_text().replace("+new", "+tampered", 1))
    with pytest.raises(ValidationError, match="integrity failed"):
        load_validated_edit_artifact(path)


@pytest.mark.parametrize("field", [
    "new_value = True", "def test_boundary():", "Exact rationale.",
])
def test_candidate_artifact_tampering_is_rejected(field, tmp_path):
    path = tmp_path / "candidate.json"
    persist(candidate(), path)
    path.write_text(path.read_text().replace(field, field + " # tampered", 1))
    with pytest.raises(ValidationError, match="integrity failed"):
        load_candidate_artifact(path)


def test_version_one_candidate_artifact_still_loads(tmp_path):
    legacy = LegacyGeneratedRepairCandidate(
        rationale="Legacy rationale.",
        patch=f"--- a/{TARGET}\n+++ b/{TARGET}\n@@ -1 +1 @@\n-old\n+new\n",
        regression_test="def test_legacy():\n    assert True\n",
        optional_policy_artifact=None,
    )
    candidate_digest, field_digests = _legacy_candidate_identity(legacy)
    values = dict(
        schema_version=LEGACY_CANDIDATE_ARTIFACT_SCHEMA_VERSION,
        candidate_id=str(uuid4()), run_id=str(uuid4()), attempt_number=1,
        provider="legacy", model="legacy", created_at=datetime.now(timezone.utc),
        trace_id="trace", boundary_id="boundary", evidence_ids=["evidence"],
        target_path=TARGET, target_symbol="CustomerSupportAgent.chat",
        source_hash="0" * 64, **legacy.model_dump(),
        candidate_digest=candidate_digest, candidate_field_digests=field_digests,
    )
    provisional = LegacyRepairCandidateArtifact.model_construct(
        **values, integrity_digest="0" * 64
    )
    artifact = LegacyRepairCandidateArtifact(
        **values, integrity_digest=_artifact_digest(provisional)
    )
    path = tmp_path / "legacy.json"
    path.write_text(artifact.model_dump_json(indent=2) + "\n")

    loaded = load_candidate_artifact(path)

    assert loaded.schema_version == LEGACY_CANDIDATE_ARTIFACT_SCHEMA_VERSION
    assert loaded.legacy_candidate() == legacy


def test_version_two_candidate_artifact_still_loads_with_original_meaning(tmp_path):
    legacy = LegacyGeneratedRepairCandidateV2(
        rationale="Historical two-call structured rationale.",
        source_edit=LegacyStructuredSourceEditV2(
            target_path=TARGET,
            target_symbol="CustomerSupportAgent.chat",
            source_hash="0" * 64,
            start_line=2,
            delete_line_count=1,
            expected_original_lines=["        old_value = True"],
            replacement_lines=["        new_value = True"],
        ),
        regression_test=StructuredRegressionTest(
            lines=["def test_v2():", "    assert True"]
        ),
    )
    candidate_digest, field_digests = _legacy_candidate_identity(legacy)
    values = dict(
        schema_version=STRUCTURED_V2_CANDIDATE_ARTIFACT_SCHEMA_VERSION,
        candidate_id=str(uuid4()), run_id=str(uuid4()), attempt_number=1,
        provider="legacy-v2", model="legacy-v2",
        created_at=datetime.now(timezone.utc), trace_id="trace",
        boundary_id="boundary", evidence_ids=["evidence"], target_path=TARGET,
        target_symbol="CustomerSupportAgent.chat", source_hash="0" * 64,
        rationale=legacy.rationale, source_edit=legacy.source_edit,
        regression_test=legacy.regression_test, optional_policy_artifact=None,
        derived_patch=None, derived_regression_test=None,
        derived_patch_digest=None, derived_regression_test_digest=None,
        candidate_digest=candidate_digest, candidate_field_digests=field_digests,
    )
    provisional = RepairCandidateArtifactV2.model_construct(
        **values, integrity_digest="0" * 64
    )
    artifact = RepairCandidateArtifactV2(
        **values, integrity_digest=_artifact_digest(provisional)
    )
    path = tmp_path / "structured-v2.json"
    path.write_text(artifact.model_dump_json(indent=2) + "\n")

    loaded = load_candidate_artifact(path)

    assert loaded.schema_version == STRUCTURED_V2_CANDIDATE_ARTIFACT_SCHEMA_VERSION
    assert loaded.candidate_v2() == legacy
    assert loaded.source_edit.expected_original_lines == ["        old_value = True"]


def test_candidate_artifact_excludes_external_secrets_and_preserves_repository(
    tmp_path, monkeypatch
):
    external_secret = "synthetic-external-key-not-for-artifacts"
    monkeypatch.setenv("NEBIUS_API_KEY", external_secret)
    before = repository_digest(ROOT)
    path = tmp_path / "candidate.json"
    persist(candidate(), path)
    serialized = path.read_text()

    assert external_secret not in serialized
    assert "authorization" not in serialized.lower()
    assert "request_headers" not in serialized.lower()
    assert "reasoning_content" not in serialized.lower()
    assert '"reasoning"' not in serialized.lower()
    assert repository_digest(ROOT) == before
