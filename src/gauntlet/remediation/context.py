"""Construct bounded source context from the exact M2 boundary location."""
import ast
from pathlib import Path

from gauntlet.remediation.models import SourceContext
from gauntlet.tracing.models import AttackTrace


AUTHORIZED_TARGETS = {
    "victims/customer_support/agent.py": "CustomerSupportAgent.chat",
    "victims/clean_customer_support/agent.py": "CleanCustomerSupportAgent.chat",
}


def build_source_context(serialized_trace: str, repository_root: Path) -> SourceContext:
    trace = AttackTrace.model_validate_json(serialized_trace)
    boundary = trace.failure_boundary
    if boundary is None:
        raise ValueError("Source context requires an M2 FailureBoundary")
    locations = [
        item for item in trace.source_locations
        if AUTHORIZED_TARGETS.get(item.file) == item.symbol
    ]
    if len(locations) != 1:
        raise ValueError("Trace does not identify the authorized source location")
    known_ids = {event.event_id for event in trace.events}
    if not boundary.evidence_event_ids or not set(boundary.evidence_event_ids) <= known_ids:
        raise ValueError("FailureBoundary references missing evidence")
    boundary_locations = [
        event.context_flow.location
        for event in trace.events
        if event.event_id in boundary.evidence_event_ids and event.context_flow is not None
    ]
    if len(boundary_locations) != 1 or boundary_locations[0] != locations[0]:
        raise ValueError("Authorized source location does not match the M2 boundary evidence")
    return build_authorized_source_context(
        repository_root,
        target_path=locations[0].file,
        target_symbol=locations[0].symbol,
        trace_id=trace.attack_id,
        boundary_id=boundary.boundary_id,
        evidence_ids=boundary.evidence_event_ids,
    )


def build_authorized_source_context(
    repository_root: Path,
    *,
    target_path: str,
    target_symbol: str,
    trace_id: str,
    boundary_id: str,
    evidence_ids: list[str],
) -> SourceContext:
    """Read one explicitly authorized class method without inferring a target."""
    relative, bounded = read_authorized_source_text(
        repository_root, target_path=target_path, target_symbol=target_symbol
    )
    if not evidence_ids:
        raise ValueError("Authorized source context requires evidence IDs")
    return SourceContext(
        repository_relative_path=relative.as_posix(),
        target_symbol=target_symbol, source_text=bounded,
        source_hash=SourceContext.hash_text(bounded),
        trace_id=trace_id, boundary_id=boundary_id,
        evidence_ids=evidence_ids,
    )


def read_authorized_source_text(
    repository_root: Path, *, target_path: str, target_symbol: str,
) -> tuple[Path, str]:
    """Return an exact bounded class-method span after path and AST checks."""
    relative = Path(target_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Source location must be repository-relative without traversal")
    root = repository_root.resolve(strict=True)
    target = (root / relative).resolve(strict=True)
    if not target.is_relative_to(root) or not target.is_file():
        raise ValueError("Source location resolves outside the authorized repository")
    source = target.read_text()
    tree = ast.parse(source)
    symbol_parts = target_symbol.split(".")
    if len(symbol_parts) != 2:
        raise ValueError("Authorized target must be a Class.method symbol")
    class_name, method_name = symbol_parts
    class_node = next((node for node in tree.body
                       if isinstance(node, ast.ClassDef)
                       and node.name == class_name), None)
    method = next((node for node in class_node.body
                   if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                   and node.name == method_name), None) if class_node else None
    if method is None or method.end_lineno is None:
        raise ValueError("Authorized target symbol is missing")
    lines = source.splitlines(keepends=True)
    bounded = "".join(lines[method.lineno - 1:method.end_lineno])
    if len(bounded) > 12_000:
        raise ValueError("Authorized source symbol exceeds the M3.1 context limit")
    return relative, bounded
