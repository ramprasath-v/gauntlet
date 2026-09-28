"""One deterministic patch applicator constrained by the existing M3 plan."""
import ast

from gauntlet.patching.models import PatchPlan
from gauntlet.patching.planner import EXPECTED_FILE, EXPECTED_SYMBOL
from gauntlet.sandbox.models import PatchApplicationResult, utc_now
from gauntlet.sandbox.workspace import SandboxWorkspace


OLD_FLOW = "privileged_context=not self.enforce_tool_data_boundary,"
NEW_FLOW = "privileged_context=False,"
OLD_CONTROL = "enforce_data_only_boundary=self.enforce_tool_data_boundary))"
NEW_CONTROL = "enforce_data_only_boundary=True))"


def apply_patch(workspace: SandboxWorkspace, plan: PatchPlan) -> PatchApplicationResult:
    base = dict(
        patch_id=plan.patch_id, workspace_id=workspace.workspace_id,
        target_file=plan.target_file, target_symbol=plan.target_symbol,
        timestamp=utc_now(),
    )
    try:
        if plan.target_file != EXPECTED_FILE or plan.target_symbol != EXPECTED_SYMBOL:
            raise ValueError("PatchPlan is outside the supported M4 file/symbol scope")
        target = workspace.resolve_relative(plan.target_file)
        if not target.is_file():
            raise ValueError("Patch target is not a sandbox file")
        source = target.read_text()
        tree = ast.parse(source)
        agent = next(
            (node for node in tree.body
             if isinstance(node, ast.ClassDef) and node.name == "CustomerSupportAgent"), None
        )
        method = next(
            (node for node in agent.body
             if isinstance(node, ast.AsyncFunctionDef) and node.name == "chat"), None
        ) if agent else None
        if method is None:
            raise ValueError("Expected target symbol was not found")
        if source.count(OLD_FLOW) != 1 or source.count(OLD_CONTROL) != 1:
            raise ValueError("Expected integration seam does not match the constrained patch")
        patched = source.replace(OLD_FLOW, NEW_FLOW).replace(OLD_CONTROL, NEW_CONTROL)
        target.write_text(patched)
        return PatchApplicationResult(
            **base, applied=True, files_changed=[plan.target_file]
        )
    except (OSError, SyntaxError, ValueError) as exc:
        return PatchApplicationResult(
            **base, applied=False, files_changed=[], error=str(exc)
        )
