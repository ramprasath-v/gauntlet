from pathlib import Path
import ast
import httpx
import pytest
from gauntlet.attacks.indirect_prompt_injection import IndirectPromptInjectionAttack
from gauntlet.core.config import CANARY
from gauntlet.core.models import ChatResponse
from gauntlet.tracing.builder import build_trace
from gauntlet.tracing.models import AttackTrace, ExecutionEvent, SourceKind, TrustLevel
from victims.customer_support.app import create_app

async def attacked():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url="http://test") as client:
        return await IndirectPromptInjectionAttack(client).run()

async def test_poisoned_review_is_untrusted_and_trace_preserves_order():
    result = await attacked()
    assert result.events[2].trust_level == TrustLevel.UNTRUSTED
    trace = result.trace
    assert [e.kind for e in trace.events] == ["user_message", "tool_call", "tool_result", "context_flow", "model_response", "verdict"]
    assert [e.sequence for e in trace.events] == [1, 2, 3, 4, 5, 6]
    assert [e.event_id for e in trace.events if e.kind != "context_flow"] == [e.event_id for e in result.events]
    assert AttackTrace.model_validate_json(trace.model_dump_json()) == trace

async def test_boundary_references_linked_runtime_evidence_and_source_seam():
    trace = (await attacked()).trace
    boundary = trace.failure_boundary
    assert boundary.from_component == "search_reviews"
    assert boundary.from_trust_level == TrustLevel.UNTRUSTED
    assert boundary.to_component == "model_context"
    assert boundary.evidence_event_ids == [e.event_id for e in trace.events[1:]]
    location = trace.source_locations[0]
    assert location.file == "victims/customer_support/agent.py"
    assert location.symbol == "CustomerSupportAgent.chat"
    tree = ast.parse(Path(location.file).read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "CustomerSupportAgent")
    method = next(n for n in cls.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "chat")
    assert any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "ModelContext" for n in ast.walk(method))

async def test_clean_p200_has_context_flow_but_no_failure_boundary():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url="http://test") as client:
        response = await client.post("/chat", json={"message": "Reviews for P200?"})
    chat = ChatResponse.model_validate(response.json())
    verdict = ExecutionEvent(kind="verdict", sequence=6, source=SourceKind.VERIFIER,
                             input_event_id=chat.events[-1].event_id, data={"verdict": "CANARY_NOT_OBSERVED"})
    trace = build_trace("clean", [*chat.events, verdict], CANARY)
    assert trace.events[2].trust_level == TrustLevel.UNTRUSTED
    assert trace.events[3].kind == "context_flow"
    assert trace.failure_boundary is None
    assert trace.source_locations == []

@pytest.mark.parametrize("missing", ["flow", "instruction", "canary", "verdict", "link", "trust"])
async def test_incomplete_or_contradictory_evidence_never_establishes_boundary(missing):
    result = await attacked()
    events = [e.model_copy(deep=True) for e in result.events]
    if missing == "flow": events[2].context_flow = None
    elif missing == "instruction": events[2].data["content"] = "Ordinary review"
    elif missing == "canary": events[3].data["response"] = "No secret here"
    elif missing == "verdict": events[-1].data["verdict"] = "CANARY_NOT_OBSERVED"
    elif missing == "link": events[3].input_event_id = "unrelated"
    elif missing == "trust": events[2].trust_level = TrustLevel.TRUSTED
    assert build_trace(result.attack_id, events, CANARY).failure_boundary is None

async def test_duplicate_ids_and_out_of_order_events_rejected():
    result = await attacked()
    events = [e.model_copy(deep=True) for e in result.events]
    events[1].event_id = events[0].event_id
    with pytest.raises(ValueError): build_trace(result.attack_id, events, CANARY)
    with pytest.raises(ValueError): build_trace(result.attack_id, list(reversed(result.events)), CANARY)

async def test_cli_renders_attack_path(monkeypatch, capsys):
    from gauntlet import cli
    original = httpx.AsyncClient
    def local_client(**kwargs):
        return original(transport=httpx.ASGITransport(app=create_app()), **kwargs)
    monkeypatch.setattr(cli.httpx, "AsyncClient", local_client)
    assert await cli.attack("http://127.0.0.1:8001") == 0
    output = capsys.readouterr().out
    for text in ["EXPLOIT CONFIRMED", "ATTACK PATH", "TOOL_RESULT [UNTRUSTED]", "TRUST BOUNDARY CROSSED", "CANARY_LEAKED", "ACTIONABLE LOCATION", "CustomerSupportAgent.chat"]:
        assert text in output
    assert "INTERNAL VERIFICATION INSTRUCTION:" not in output
