import html
import json
from pathlib import Path
import re
import shutil

import pytest

from gauntlet.demo.m7 import (
    CANDIDATE_PATH, EXPECTED_CANDIDATE_ID, EXPECTED_PATCH_DIGEST,
    EXPECTED_MUTATIONS, DemoEvidenceError, generate_demo, load_demo_evidence,
)


ROOT = Path(__file__).parents[1]


def test_frozen_kimi_evidence_is_validated_and_complete():
    evidence = load_demo_evidence(ROOT)

    assert evidence.candidate_id == EXPECTED_CANDIDATE_ID
    assert evidence.candidate_schema == "gauntlet.repair-candidate.v3"
    assert evidence.patch_digest == EXPECTED_PATCH_DIGEST
    assert evidence.model == "Kimi K2.7 Code"
    assert evidence.attempt == 3
    assert evidence.p100_status == "PASS"
    assert evidence.p200_status == "PASS"
    assert evidence.compatibility_count == 21
    assert evidence.generated_regression_status == "FAIL"
    assert evidence.security_repair_verified
    assert not evidence.full_candidate_verified
    assert set(evidence.mutation_ids) == EXPECTED_MUTATIONS
    assert (evidence.qualified_count, evidence.blocked_count) == (4, 4)
    assert evidence.provider_requests == 0


def test_generator_fails_loudly_when_candidate_evidence_is_tampered(tmp_path):
    for relative in (
        CANDIDATE_PATH,
        Path("evidence/live-m42-repair-run.json"),
        Path("evidence/deterministic-reevaluations/kimi-k2.7-code-attempt-03.patch-assessment.json"),
        Path("evidence/deterministic-reevaluations/kimi-k2.7-code-attempt-03.reevaluation.json"),
        Path("evidence/deterministic-reevaluations/kimi-k2.7-code-attempt-03.m5-attack-mutation-assessment.json"),
    ):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    candidate_path = tmp_path / CANDIDATE_PATH
    payload = json.loads(candidate_path.read_text())
    payload["derived_patch"] += "\n# tampered\n"
    candidate_path.write_text(json.dumps(payload))

    with pytest.raises(DemoEvidenceError, match="candidate integrity failed"):
        load_demo_evidence(tmp_path)


def test_generated_page_has_three_column_control_room_and_only_allowed_attacks(tmp_path):
    output = generate_demo(ROOT, tmp_path / "gauntlet.html")
    page = output.read_text()

    assert "ATTACKS" in page.upper()
    assert "ATTACK TRACE" in page.upper() or 'aria-label="Attack trace"' in page
    assert 'aria-label="Evidence"' in page
    assert "P100 — Prompt Injection" in page
    assert "Personalization" in page and "Coming next" in page
    assert "+ New Attack" not in page
    assert "Human-written fix" not in page


def test_replay_and_proof_receipt_contain_all_evidence_backed_results(tmp_path):
    page = generate_demo(ROOT, tmp_path / "gauntlet.html").read_text()

    for stage in ("ATTACK", "DIAGNOSE", "PATCH", "RE-ATTACK", "MUTATE", "PROVE"):
        assert stage in page
    assert "RUN GAUNTLET" in page
    assert "SECURITY REPAIR VERIFIED / PROTECTED" in page
    assert "Vulnerability reproduced" in page
    assert "Original attack blocked" in page
    assert "Mutation attacks" in page and "4/4" in page
    assert "Legitimate utility preserved" in page
    assert "21/21" in page
    assert "Repository unchanged" in page


def test_exact_patch_and_visible_regression_caveat_are_preserved(tmp_path):
    evidence = load_demo_evidence(ROOT)
    page = generate_demo(ROOT, tmp_path / "gauntlet.html").read_text()

    assert EXPECTED_PATCH_DIGEST in page
    assert "Known-good fix supplied</span><b>NO" in page
    assert "Model-generated regression test failed" in page
    assert "independent Gauntlet gates verified the repair" in page
    receipt = page[page.index('<section class="receipt"'):page.index('</section>', page.index('<section class="receipt"'))]
    assert "FULL_CANDIDATE_VERIFIED" not in receipt
    assert "FULL_CANDIDATE_VERIFIED = NO" in page
    assert "Full candidate verified</span><b class=\"warn-text\">NO" in page
    assert html.escape(evidence.patch) in page


def test_page_is_single_file_offline_responsive_and_omits_unsupported_suite_claim(tmp_path):
    page = generate_demo(ROOT, tmp_path / "gauntlet.html").read_text()

    assert "<style>" in page and "<script>" in page
    assert "@media(max-width:820px)" in page
    assert not re.search(r'''(?:src|href)=["']https?://''', page)
    assert "<link " not in page
    assert "fetch(" not in page
    assert "XMLHttpRequest" not in page
    assert "194/194" not in page
    assert "not embedded in the frozen integrity-bound assessments" in page
