from gauntlet.sandbox.models import SandboxRepairResult


def render_sandbox_result(result: SandboxRepairResult) -> str:
    patch = "YES" if result.patch_result and result.patch_result.applied else "NO"
    build = "PASS" if result.build_result and result.build_result.passed else "FAIL"
    tests = "PASS" if result.test_result and result.test_result.passed else "FAIL"
    isolation = "PASS" if result.original_workspace_unchanged else "FAIL"
    final = "SANDBOX REPAIR VERIFIED" if result.succeeded else "SANDBOX REPAIR FAILED"
    return "\n".join([
        "SANDBOX REPAIR", "", f"Workspace: {result.workspace_path}",
        f"Workspace ID: {result.workspace_id}", f"Attempts: {result.attempts}/{result.max_attempts}",
        f"Source revision: {result.source_revision or 'unavailable'}",
        "", "PATCH", f"Applied: {patch}",
        f"Original workspace modified: {'NO' if result.original_workspace_unchanged else 'YES'}",
        "", "BUILD", build, "", "TESTS", tests, "", "CONTAINMENT",
        f"Workspace isolation: {isolation}", f"Outside writes: {result.outside_writes}",
        f"Cleanup: {'PASS' if result.workspace_cleaned else 'FAIL'}",
        "", "RESULT", final,
    ])
