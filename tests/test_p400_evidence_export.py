from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from gauntlet.contracts.p400_live import P400LiveEvidence
from gauntlet.contracts.p400_live_repair import P400LiveRepairEvidence
from gauntlet.contracts.p400_true_live import P400LiveProofEvidence
from gauntlet.demo import p400_evidence_export as evidence_export
from gauntlet.demo.m8_web import create_m8_demo_app


ROOT = Path(__file__).parents[1]


def _forbidden_provider():
    raise AssertionError("evidence export must not construct a provider")


def _app(evidence_root: Path):
    return create_m8_demo_app(
        ROOT,
        live_provider_factory=_forbidden_provider,
        p100_live_provider_factory=_forbidden_provider,
        p400_attack_provider_factory=_forbidden_provider,
        p400_patch_provider_factory=_forbidden_provider,
        p400_proof_provider_factory=_forbidden_provider,
        p400_live_evidence_directory=evidence_root,
    )


async def _get(app, url: str):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.get(url)


@pytest.mark.asyncio
async def test_export_serves_only_safe_json_without_provider_calls(tmp_path: Path):
    root = tmp_path / "p400"
    path = root / "attack" / "live-safe.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"schema_version":"test","safe":true}\n')

    response = await _get(
        _app(root), "/api/p400/evidence/export?path=attack%2Flive-safe.json"
    )

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {"schema_version": "test", "safe": True}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("requested", "status"),
    [
        ("/etc/passwd.json", 400),
        ("../outside.json", 400),
        ("%2e%2e%2Foutside.json", 400),
        ("attack/live.txt", 400),
        (".env", 400),
        ("src/gauntlet/demo/m8_web.py", 400),
        ("attack/missing.json", 404),
    ],
)
async def test_export_rejects_unsafe_or_missing_paths(
    tmp_path: Path, requested: str, status: int,
):
    root = tmp_path / "p400"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"outside":true}\n')

    response = await _get(
        _app(root), f"/api/p400/evidence/export?path={requested}"
    )

    assert response.status_code == status
    assert "outside" not in response.text


@pytest.mark.asyncio
async def test_export_rejects_symlink_escape(tmp_path: Path):
    root = tmp_path / "p400"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text('{"outside":true}\n')
    (root / "escape.json").symlink_to(outside)

    response = await _get(
        _app(root), "/api/p400/evidence/export?path=escape.json"
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_export_rejects_secret_shaped_json(tmp_path: Path, monkeypatch):
    root = tmp_path / "p400"
    root.mkdir()
    monkeypatch.setenv("NEBIUS_API_KEY", "synthetic-secret-value")
    (root / "key.json").write_text(json.dumps({
        "api_key": "synthetic-secret-value",
    }))
    (root / "embedded.json").write_text(json.dumps({
        "message": "synthetic-secret-value",
    }))

    direct = await _get(_app(root), "/api/p400/evidence/export?path=key.json")
    embedded = await _get(
        _app(root), "/api/p400/evidence/export?path=embedded.json"
    )

    assert direct.status_code == 403
    assert embedded.status_code == 403
    assert "synthetic-secret-value" not in direct.text + embedded.text


def _manifest_fixture(tmp_path: Path, monkeypatch, *, digest_match: bool = True):
    root = tmp_path / "p400"
    paths = {
        name: root / name / f"live-{name}.json"
        for name in ("attack", "repair", "proof")
    }
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}")
    edit_path = root / "repair" / "live-repair.edits" / "edit.json"
    edit_path.parent.mkdir()
    edit_path.write_text("{}")

    patch_digest = "a" * 64
    candidate = object()
    source = SimpleNamespace(source_hash="b" * 64, target_symbol="Agent.respond")
    attack = SimpleNamespace(run_id="attack", final_status="DETECTED")
    repair = SimpleNamespace(
        run_id="repair",
        source_live_attack_run_id="attack",
        source_live_attack_digest=hashlib.sha256(b"{}").hexdigest(),
        derived_patch_digest=patch_digest,
        derived_patch="diff",
        edit_artifact="live-repair.edits/edit.json",
        edit_candidate=candidate,
        contract_request=SimpleNamespace(source_context=source),
    )
    proof = SimpleNamespace(
        run_id="proof",
        created_at=datetime.now(timezone.utc),
        source_live_repair_run_id="repair",
        source_patch_digest=patch_digest if digest_match else "c" * 64,
        final_status="VERIFIED",
    )
    edit = SimpleNamespace(
        edit_id="edit",
        run_id="repair",
        derived_patch="diff",
        derived_patch_digest=patch_digest,
        source_hash=source.source_hash,
        target_symbol=source.target_symbol,
        edit_candidate=lambda: candidate,
    )
    monkeypatch.setattr(
        P400LiveProofEvidence, "model_validate_json",
        classmethod(lambda cls, raw: proof),
    )
    monkeypatch.setattr(
        P400LiveRepairEvidence, "model_validate_json",
        classmethod(lambda cls, raw: repair),
    )
    monkeypatch.setattr(
        P400LiveEvidence, "model_validate_json",
        classmethod(lambda cls, raw: attack),
    )
    monkeypatch.setattr(
        evidence_export, "load_validated_edit_artifact", lambda path: edit,
    )
    monkeypatch.setattr(
        evidence_export, "repair_is_eligible_for_live_proof", lambda item: True,
    )
    return root


def test_latest_success_requires_complete_verified_digest_bound_chain(
    tmp_path: Path, monkeypatch,
):
    root = _manifest_fixture(tmp_path, monkeypatch)

    manifest = evidence_export.latest_success_manifest(root)

    assert manifest["verified"] is True
    assert manifest["patch_digest"] == "a" * 64
    assert manifest["attack"]["run_id"] == "attack"
    assert manifest["repair"]["run_id"] == "repair"
    assert manifest["validated_edit"]["candidate_id"] == "edit"
    assert manifest["proof"]["run_id"] == "proof"
    for name in ("attack", "repair", "validated_edit", "proof"):
        assert manifest[name]["download_url"].startswith(
            "/api/p400/evidence/export?path="
        )


def test_latest_success_rejects_patch_digest_mismatch(tmp_path: Path, monkeypatch):
    root = _manifest_fixture(tmp_path, monkeypatch, digest_match=False)

    with pytest.raises(FileNotFoundError, match="No complete VERIFIED"):
        evidence_export.latest_success_manifest(root)


def test_latest_success_rejects_incomplete_or_rejected_runs(
    tmp_path: Path, monkeypatch,
):
    root = tmp_path / "p400"
    (root / "proof").mkdir(parents=True)
    (root / "proof" / "live-proof.json").write_text("{}")
    rejected = SimpleNamespace(
        run_id="proof",
        created_at=datetime.now(timezone.utc),
        final_status="NOT_VERIFIED",
    )
    monkeypatch.setattr(
        P400LiveProofEvidence, "model_validate_json",
        classmethod(lambda cls, raw: rejected),
    )

    with pytest.raises(FileNotFoundError, match="No complete VERIFIED"):
        evidence_export.latest_success_manifest(root)


@pytest.mark.asyncio
async def test_latest_success_endpoint_is_read_only_and_ui_button_is_verified_only(
    tmp_path: Path, monkeypatch,
):
    root = tmp_path / "p400"
    root.mkdir()
    expected = {"verified": True, "patch_digest": "a" * 64}
    monkeypatch.setattr(
        "gauntlet.demo.m8_web.latest_success_manifest",
        lambda path, credentials: expected,
    )
    app = _app(root)

    manifest = await _get(app, "/api/p400/evidence/latest-success")
    page = await _get(app, "/")

    assert manifest.status_code == 200
    assert manifest.json() == expected
    assert 'class="secondary hidden" id="download-p400-evidence"' in page.text
    assert "classList.toggle('hidden',!verified)" in page.text
    assert "classList.add('hidden')" in page.text
