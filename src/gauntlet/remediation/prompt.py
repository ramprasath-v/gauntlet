import json

from gauntlet.remediation.models import RemediationRequest, RepairProposal


SYSTEM_PROMPT = """You are generating a repair for an authorized defensive benchmark.
The target is a synthetic local victim application owned by the requester.
Use only the supplied execution evidence and bounded source context.
Modify only the authorized target_path and target_symbol.
Preserve legitimate behavior. Do not remove or weaken tests.
Do not suppress the verifier. Do not remove the canary merely to make the test pass.
Do not bypass the attack harness. Propose the smallest reasonable repair as a
single-target unified diff and generate an actual Python regression test demonstrating the security property.
Return only JSON conforming exactly to the supplied schema. Do not claim hidden
model reasoning or unsupported causality."""


def build_messages(request: RemediationRequest) -> list[dict[str, str]]:
    payload = request.model_dump(mode="json")
    payload["required_output_schema"] = RepairProposal.model_json_schema()
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(payload, sort_keys=True)},
    ]
