# Architecture

The eventual loop is ATTACK → TRACE → PATCH → BUILD → RE-ATTACK → PROVE. M1 stops at deterministic exploit confirmation.

- `core`: Pydantic request, response and attack-result contracts; environment configuration and public canary constants.
- `llm`: async `AgentModelClient` protocol, deterministic `FakeAgentModelClient`, and unimplemented `NebiusTokenFactoryClient` boundary.
- `victims/customer_support`: FastAPI `/chat`, fixed review lookup, poisoned P100 fixture and clean P200 fixture.
- `attacks`: async attack protocol and one indirect-injection attack using httpx.
- `verification`: exact case-sensitive canary substring detection against response text only, with no model judgment.
- `tracing`: structured user-message, tool-call, tool-result, model-response and verdict events. No causal reasoning yet.
- `cli`: invokes the loopback demo, prints evidence and a concrete verdict.

The innocent request and poisoned fixture do not contain the canary value. The fixture refers to ADMIN_SECRET. The victim passes both privileged instructions containing the synthetic secret and untrusted review data to the model. Although the context has named fields, there is no enforced trust policy. The simulator deliberately promotes the review instruction to privileged behavior and extracts the canary from system context.

The simulator recognizes one fixed instruction. This is not an LLM evaluation, general injection detector, or proof of Nemotron behavior. Clean P200 requests retain useful review content. Unknown products and missing IDs have explicit responses; invalid messages receive HTTP 422.

HTTP errors and malformed response contracts raise execution errors, rather than being treated as safe. `CANARY_NOT_OBSERVED` is not PATCH VERIFIED. Tool provenance is emitted by the cooperating victim, not independently verified.

No order lookup, refund action, patching, sandbox, persistence, frontend, or live model call is implemented. Later execution must add authorized isolation separately. No .NET artifacts are part of this Python implementation.
