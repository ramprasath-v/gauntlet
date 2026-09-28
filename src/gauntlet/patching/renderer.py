from gauntlet.patching.models import PatchProof


def render_patch_proof(proof: PatchProof) -> str:
    boundary = proof.pre_patch_trace.failure_boundary
    suite = "PASS" if proof.test_suite_passed else "NOT RECORDED"
    result = "PATCH VERIFIED" if proof.verified else "PATCH NOT VERIFIED"
    return "\n".join([
        "PATCH PROOF", "", "BEFORE", "Exploit: CONFIRMED",
        f"Verdict: {proof.pre_patch_trace.verdict}",
        f"Boundary: {boundary.boundary_type if boundary else 'NONE'}", "",
        "PATCH", proof.plan.target_file, proof.plan.target_symbol,
        f"Control: {proof.plan.proposed_control}", "",
        "RE-ATTACK", f"Same attack: {'YES' if proof.same_attack else 'NO'}",
        f"Verdict: {proof.post_patch_verdict}", "",
        "REGRESSION", f"Clean behavior: {'PASS' if proof.regression.passed else 'FAIL'}",
        f"Test suite: {suite}", "", "RESULT", result,
    ])
