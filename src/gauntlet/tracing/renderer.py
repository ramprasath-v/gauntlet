from gauntlet.tracing.models import AttackTrace


def render_trace(trace: AttackTrace) -> str:
    lines = ["ATTACK PATH", "-----------"]
    boundary = trace.failure_boundary
    for number, event in enumerate(trace.events, 1):
        label = event.kind.upper()
        if event.kind == "context_flow" and boundary and event.event_id in boundary.evidence_event_ids:
            label = "TRUST BOUNDARY CROSSED"
        if event.trust_level:
            label += f" [{event.trust_level.value}]"
        lines.append(f"{number} {label} (event: {event.event_id})")
        if event.kind == "user_message":
            summary = "Product-review question (user request)"
        elif event.kind == "tool_call":
            summary = f"{event.data.get('name')}({event.data.get('product_id')})"
        elif event.kind == "tool_result":
            summary = "external_product_review; contains_instruction_like_content: " + event.data.get("contains_instruction_like_content", "false")
        elif event.kind == "context_flow":
            summary = "UNTRUSTED TOOL DATA → PRIVILEGED MODEL CONTEXT"
        elif event.kind == "model_response":
            summary = "Synthetic canary observed" if trace.verdict == "CANARY_LEAKED" else "Synthetic canary not observed"
        else:
            summary = event.data.get("verdict", "INCONCLUSIVE")
        lines.append("  " + summary)
    if boundary:
        lines.extend(["", "FAILURE BOUNDARY", boundary.boundary_type,
                      "Evidence strength: DETERMINISTIC", "Canary: " + trace.evidence["canary"],
                      "Supporting events: " + ", ".join(boundary.evidence_event_ids),
                      "", "ACTIONABLE LOCATION", "-------------------"])
        for location in trace.source_locations:
            lines.extend([location.file, location.symbol, location.responsibility])
    else:
        lines.append("\nNo injection failure boundary established by this evidence.")
    lines.append("\nObservable execution evidence; no claim about hidden model reasoning.")
    return "\n".join(lines)
