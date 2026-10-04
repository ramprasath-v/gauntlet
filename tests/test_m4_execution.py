import difflib
import hashlib
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from gauntlet.attacks.indirect_prompt_injection import IndirectPromptInjectionAttack
from gauntlet.remediation.fake import FakeRemediationProvider
from gauntlet.remediation.handoff import (
    load_repair_proposal, persist_repair_proposal,
)
from gauntlet.remediation.models import RepairFailure, RepairProposal
from gauntlet.remediation.workflow import generate_repair_proposal
from gauntlet.sandbox.m4_executor import M41RepairExecutor
from gauntlet.sandbox.m4_models import PatchAssessment
from gauntlet.sandbox.m4_runner import M41CommandRunner
from gauntlet.sandbox.models import CommandCategory
from gauntlet.sandbox.workspace import repository_digest
from victims.customer_support.app import create_app


ROOT = Path(__file__).parents[1]
TARGET = "victims/customer_support/agent.py"


@pytest.fixture
async def proposal() -> RepairProposal:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://before"
    ) as client:
        trace = (await IndirectPromptInjectionAttack(client).run()).trace
    result = await generate_repair_proposal(
        trace.model_dump_json(), ROOT, FakeRemediationProvider()
    )
    assert isinstance(result, RepairProposal)
    return result


def patch_for(source: str, changed: str) -> str:
    return "".join(difflib.unified_diff(
        source.splitlines(keepends=True), changed.splitlines(keepends=True),
        fromfile=f"a/{TARGET}", tofile=f"b/{TARGET}",
    ))


def with_artifacts(
    proposal: RepairProposal, *, patch: str | None = None,
    regression_test: str | None = None,
) -> RepairProposal:
    values = proposal.model_dump()
    if patch is not None:
        values["patch"] = patch
    if regression_test is not None:
        values["regression_test"] = regression_test
    return RepairProposal.model_validate(values)


async def test_valid_persisted_proposal_produces_command_derived_patch_proof(
    proposal, tmp_path
):
    before = repository_digest(ROOT)
    handoff = tmp_path / "repair-proposal.json"
    envelope = persist_repair_proposal(proposal, handoff)
    loaded = load_repair_proposal(handoff)

    assert loaded == proposal
    assert envelope.patch_digest == hashlib.sha256(proposal.patch.encode()).hexdigest()
    assert envelope.regression_test_digest == hashlib.sha256(
        proposal.regression_test.encode()
    ).hexdigest()

    proof = await M41RepairExecutor(ROOT).run_persisted(handoff)

    assert isinstance(proof, PatchAssessment)
    assert proof.full_candidate_verified
    assert proof.repair_id == proposal.repair_id
    assert proof.trace_id == proposal.trace_id
    assert proof.boundary_id == proposal.boundary_id
    assert proof.evidence_ids == proposal.evidence_ids
    assert proof.original_source_hash == proposal.source_hash
    assert proof.files_changed == [proposal.target_path]
    assert proof.patch_digest == envelope.patch_digest
    assert proof.regression_test_digest == envelope.regression_test_digest
    assert all(gate.status == "PASS" for gate in (
        proof.build_integrity, proof.generated_regression, proof.p100_security,
        proof.p200_utility, proof.compatibility,
    ))
    assert proof.trusted_workspace_id != proof.generated_test_workspace_id
    assert proof.cleanup == "PASS"
    assert proof.original_repository_unchanged
    assert repository_digest(ROOT) == before


async def test_handoff_tamper_is_rejected(proposal, tmp_path):
    path = tmp_path / "repair.json"
    persist_repair_proposal(proposal, path)
    serialized = path.read_text().replace(
        "Enforce the recorded", "Alter the recorded", 1
    )
    path.write_text(serialized)
    with pytest.raises(ValueError, match="integrity failed"):
        load_repair_proposal(path)


async def test_source_identity_mismatch_stops_before_patch(proposal):
    mismatched = proposal.model_copy(update={"source_hash": "0" * 64})
    result = await M41RepairExecutor(ROOT).run(mismatched)
    assert isinstance(result, RepairFailure)
    assert (result.failure_stage, result.failure_code) == (
        "source_identity", "source_hash_mismatch",
    )
    assert result.repair_id == proposal.repair_id


async def test_exact_patch_apply_failure_is_structured(proposal):
    bad = with_artifacts(
        proposal,
        patch=(
            f"--- a/{TARGET}\n+++ b/{TARGET}\n"
            "@@ -1 +1 @@\n-this line is absent\n+replacement\n"
        ),
    )
    result = await M41RepairExecutor(ROOT).run(bad)
    assert isinstance(result, RepairFailure)
    assert (result.failure_stage, result.failure_code) == (
        "patch_apply", "git_apply_failed",
    )
    assert result.diagnostics["command"].startswith("git apply --verbose")


async def test_compile_failure_is_command_derived(proposal):
    source = (ROOT / TARGET).read_text()
    changed = source.replace(
        "class CustomerSupportAgent:", "class CustomerSupportAgent("
    )
    result = await M41RepairExecutor(ROOT).run(
        with_artifacts(proposal, patch=patch_for(source, changed))
    )
    assert isinstance(result, PatchAssessment)
    assert result.build_integrity.status == "FAIL"
    assert result.build_integrity.evidence.exit_code != 0
    assert result.p100_security.status == "NOT_RUN"
    assert result.p200_utility.status == "NOT_RUN"
    assert result.compatibility.status == "NOT_RUN"


async def test_generated_regression_failure_does_not_block_trusted_gates(proposal):
    result = await M41RepairExecutor(ROOT).run(with_artifacts(
        proposal, regression_test="def test_generated_repair():\n    assert False\n"
    ))
    assert isinstance(result, PatchAssessment)
    assert result.generated_regression.status == "FAIL"
    assert result.p100_security.status == "PASS"
    assert result.p200_utility.status == "PASS"
    assert result.compatibility.status == "PASS"
    assert result.security_repair_verified
    assert not result.generated_regression_valid
    assert not result.full_candidate_verified


class MutatingGeneratedTestRunner(M41CommandRunner):
    async def generated_regression(self, workspace, test_path):
        workspace.resolve_relative(TARGET).write_text("model test mutated its sandbox\n")
        return await super().generated_regression(workspace, test_path)


async def test_generated_test_mutation_is_isolated_from_trusted_gates(proposal):
    before = repository_digest(ROOT)
    result = await M41RepairExecutor(
        ROOT, runner=MutatingGeneratedTestRunner()
    ).run(proposal)

    assert isinstance(result, PatchAssessment)
    assert result.trusted_workspace_id != result.generated_test_workspace_id
    assert result.p100_security.status == "PASS"
    assert result.p200_utility.status == "PASS"
    assert result.compatibility.status == "PASS"
    assert result.same_patch_integrity == "PASS"
    assert result.generated_workspace_integrity == "FAIL"
    assert result.security_repair_verified
    assert not result.full_candidate_verified
    assert result.cleanup == "PASS"
    assert result.repository_immutability == "PASS"
    assert repository_digest(ROOT) == before


class P100FailureRunner(M41CommandRunner):
    async def p100_security(self, workspace, target_path=None):
        test = workspace.resolve_relative(".gauntlet/test_forced_p100_failure.py")
        test.parent.mkdir(parents=True, exist_ok=True)
        test.write_text("def test_forced_p100_failure():\n    assert False\n")
        return await self._run(
            workspace, CommandCategory.SECURITY,
            [__import__("sys").executable, "-m", "pytest", "-q",
             ".gauntlet/test_forced_p100_failure.py"],
        )


async def test_p100_failure_does_not_block_utility_or_compatibility(proposal):
    result = await M41RepairExecutor(ROOT, runner=P100FailureRunner()).run(proposal)
    assert isinstance(result, PatchAssessment)
    assert result.p100_security.status == "FAIL"
    assert result.p200_utility.status == "PASS"
    assert result.compatibility.status == "PASS"
    assert not result.security_repair_verified
    assert result.utility_preserved
    assert result.compatibility_preserved
    assert not result.full_candidate_verified


async def test_candidate_patch_digest_mismatch_is_rejected(proposal):
    result = await M41RepairExecutor(ROOT).run(
        proposal, expected_patch_digest="0" * 64
    )
    assert isinstance(result, RepairFailure)
    assert (result.failure_stage, result.failure_code) == (
        "candidate_validation", "patch_digest_mismatch",
    )


async def test_assessment_cleanup_claim_cannot_contradict_observation(proposal):
    result = await M41RepairExecutor(ROOT).run(proposal)
    assert isinstance(result, PatchAssessment)
    payload = result.model_dump(mode="json")
    payload["trusted_workspace_cleaned"] = False
    with pytest.raises(ValidationError, match="Cleanup PASS"):
        PatchAssessment.model_validate(payload)


class CapturingRunner(M41CommandRunner):
    applied_target: str | None = None

    async def apply_patch(self, workspace, patch_path):
        result = await super().apply_patch(workspace, patch_path)
        if result.passed:
            self.applied_target = workspace.resolve_relative(TARGET).read_text()
        return result


async def test_changing_proposal_patch_changes_workspace_and_cannot_use_fake_switch(
    proposal,
):
    source = (ROOT / TARGET).read_text()
    marker = "        # exact-proposal-patch-marker\n"
    changed = source.replace(
        "    async def chat(self, message: str) -> ChatResponse:\n",
        "    async def chat(self, message: str) -> ChatResponse:\n" + marker,
    )
    runner = CapturingRunner()
    result = await M41RepairExecutor(ROOT, runner=runner).run(with_artifacts(
        proposal,
        patch=patch_for(source, changed),
        regression_test="def test_exact_patch_materialized():\n    assert True\n",
    ))
    assert isinstance(result, PatchAssessment)
    assert result.p100_security.status == "FAIL"
    assert marker.strip() in runner.applied_target
    assert "enforce_tool_data_boundary=True" not in runner.applied_target


async def test_p200_utility_regression_is_rejected(proposal):
    source = (ROOT / TARGET).read_text()
    changed = source.replace(
        "privileged_context=not self.enforce_tool_data_boundary,",
        "privileged_context=False,",
    ).replace(
        "enforce_data_only_boundary=self.enforce_tool_data_boundary))",
        "enforce_data_only_boundary=True))",
    ).replace(
        "review = search_reviews(product_id)",
        "review = None if product_id == \"P200\" else search_reviews(product_id)",
    )
    result = await M41RepairExecutor(ROOT).run(with_artifacts(
        proposal,
        patch=patch_for(source, changed),
        regression_test="def test_candidate_shape():\n    assert True\n",
    ))
    assert isinstance(result, PatchAssessment)
    assert result.p200_utility.status == "FAIL"
    assert result.compatibility.status != "NOT_RUN"


class UnauthorizedWriteRunner(M41CommandRunner):
    async def apply_patch(self, workspace, patch_path):
        result = await super().apply_patch(workspace, patch_path)
        workspace.resolve_relative("src/gauntlet/unauthorized.py").write_text("x = 1\n")
        return result


async def test_unauthorized_post_patch_source_change_is_rejected(proposal):
    result = await M41RepairExecutor(
        ROOT, runner=UnauthorizedWriteRunner()
    ).run(proposal)
    assert isinstance(result, RepairFailure)
    assert (result.failure_stage, result.failure_code) == (
        "patch_authorization", "unauthorized_post_patch_change",
    )
    assert "src/gauntlet/unauthorized.py" in result.diagnostics["changed_files"]


class BroaderFailureRunner(M41CommandRunner):
    async def broader_suite(self, workspace):
        test = workspace.resolve_relative(".gauntlet/test_broader_failure.py")
        test.write_text("def test_broader_failure():\n    assert False\n")
        return await self._run(
            workspace, CommandCategory.EXISTING_SUITE,
            [__import__("sys").executable, "-m", "pytest", "-q",
             ".gauntlet/test_broader_failure.py"],
        )


async def test_broader_existing_suite_failure_prevents_verified(proposal):
    result = await M41RepairExecutor(
        ROOT, runner=BroaderFailureRunner()
    ).run(proposal)
    assert isinstance(result, PatchAssessment)
    assert result.compatibility.status == "FAIL"
    assert result.p100_security.status == "PASS"
    assert result.p200_utility.status == "PASS"
