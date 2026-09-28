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
The regression_test value must contain complete, executable, pytest-compatible
Python 3 source. Every import must be a syntactically valid Python statement.
Preserve all required newlines and indentation, JSON-escape source newlines as
`\\n` inside the JSON string, and do not compress multiple Python statements
onto one line unless that line is valid Python. The generated regression_test
must parse successfully with Python `ast.parse()`. Put no Markdown fences or
prose inside regression_test. Formatting example only:
{"regression_test":"import asyncio\\nfrom package import thing\\n\\ndef test_example():\\n    assert True\\n"}
Return only standards-compliant JSON conforming exactly to the supplied schema,
with no Markdown fences. Inside JSON string values, encode every newline, tab,
carriage return, and other control character using JSON escapes (`\\n`, `\\t`,
`\\r`, or `\\u00XX`); never place a literal control character inside a JSON
string. Do not claim hidden model reasoning or unsupported causality."""


def build_messages(request: RemediationRequest) -> list[dict[str, str]]:
    payload = request.model_dump(mode="json")
    payload["required_output_schema"] = RepairProposal.model_json_schema()
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(payload, sort_keys=True)},
    ]
