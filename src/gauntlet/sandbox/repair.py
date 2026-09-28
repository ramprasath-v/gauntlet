"""Bounded repair-proposal boundary; live provider behavior is not assumed."""
from typing import Protocol

from gauntlet.patching.models import PatchPlan
from gauntlet.sandbox.models import RepairFailure, RepairProposal, SourceContext


class RepairProposalClient(Protocol):
    async def propose(
        self, plan: PatchPlan, source: SourceContext, failure: RepairFailure
    ) -> RepairProposal: ...


class DeterministicRepairProposalClient:
    """Test/demo implementation that keeps the constrained M3 control."""
    async def propose(
        self, plan: PatchPlan, source: SourceContext, failure: RepairFailure
    ) -> RepairProposal:
        return RepairProposal(
            patch_id=plan.patch_id,
            target_file=plan.target_file,
            target_symbol=plan.target_symbol,
            control=plan.proposed_control,
            source_failure_category=failure.category,
        )
