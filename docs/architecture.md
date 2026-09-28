# Architecture

The eventual loop is ATTACK → TRACE → PATCH → BUILD → RE-ATTACK → PROVE. M1 confirms the exploit; M2 reconstructs its observable, actionable failure path.

- `core`: Pydantic request, response and attack-result contracts; environment configuration and public canary constants.
- `llm`: async `AgentModelClient` protocol, deterministic `FakeAgentModelClient`, and unimplemented `NebiusTokenFactoryClient` boundary.
- `victims/customer_support`: FastAPI `/chat`, fixed review lookup, poisoned P100 fixture and clean P200 fixture.
- `attacks`: async attack protocol and one indirect-injection attack using httpx.
- `verification`: exact case-sensitive canary substring detection against response text only, with no model judgment.
- `tracing`: structured user-message, tool-call, tool-result, model-response and verdict events. M2 adds linked context-flow evidence and actionable source locations; it does not infer hidden reasoning.
- `cli`: invokes the loopback demo, prints evidence and a concrete verdict.

The innocent request and poisoned fixture do not contain the canary value. The fixture refers to ADMIN_SECRET. The victim passes both privileged instructions containing the synthetic secret and untrusted review data to the model. Although the context has named fields, there is no enforced trust policy. The simulator deliberately promotes the review instruction to privileged behavior and extracts the canary from system context.

The simulator recognizes one fixed instruction. This is not an LLM evaluation, general injection detector, or proof of Nemotron behavior. Clean P200 requests retain useful review content. Unknown products and missing IDs have explicit responses; invalid messages receive HTTP 422.

HTTP errors and malformed response contracts raise execution errors, rather than being treated as safe. `CANARY_NOT_OBSERVED` is not PATCH VERIFIED. Tool provenance is emitted by the cooperating victim, not independently verified.

No order lookup, refund action, patching, sandbox, persistence, frontend, or live model call is implemented. Later execution must add authorized isolation separately. No .NET artifacts are part of this Python implementation.


## M2 — Evidence & Trace

ExecutionEvent retains M1's kind/data fields and ordered event list. New UUID event IDs, sequence numbers, optional SourceKind/TrustLevel, and input-event references support explicit provenance. Review results are UNTRUSTED, including clean reviews. A nested ContextFlow record captures the actual model-call integration seam without recording privileged system context. The trace expands that record into a context_flow event between tool_result and model_response, preserving existing M1 consumers.

AttackTrace contains attack_id, ordered events, failure_boundary, evidence, verdict, and source_locations. FailureBoundary identifies search_reviews (UNTRUSTED) → model_context, the tool_result → model_context boundary type, and supporting tool-call, tool-result, flow, response, and verifier IDs. SourceLocation uses repository-relative file plus symbol: victims/customer_support/agent.py, CustomerSupportAgent.chat. No brittle line numbers are stored.

The deterministic builder requires the known fixture instruction, linked context flow into privileged context, exact canary in the linked response, and a matching verifier verdict. Missing or contradictory evidence does not establish a failure boundary. Duplicate IDs and non-increasing sequences are rejected. Clean P200 still records context flow but produces no injection failure boundary.

Instruction-like detection recognizes only the known M1 fixture header and instruction. It is not a general prompt-injection classifier. The renderer summarizes tool content and user requests instead of dumping raw prompts. Raw event data remains available for this synthetic demo; this is not a general secret-redaction pipeline.

Evidence strength DETERMINISTIC describes reproducible checks over the local instrumented runtime. Victim-provided provenance is not independently authenticated. The recorded source symbol identifies the inspected local integration seam, not an attestation of arbitrary remote code. Gauntlet observes and experiments on behavior; it has no access to model chain-of-thought and makes no claim of internal causal proof. No security behavior, patching, or live model integration changed in M2.
