# Architecture

The eventual loop is ATTACK → TRACE → PATCH → BUILD → RE-ATTACK → PROVE. M1 confirms the exploit; M2 reconstructs its observable, actionable failure path; M3 consumes that artifact for one constrained repair and before/after proof.

- `core`: Pydantic request, response and attack-result contracts; environment configuration and public canary constants.
- `llm`: async `AgentModelClient` protocol, deterministic `FakeAgentModelClient`, and unimplemented `NebiusTokenFactoryClient` boundary.
- `victims/customer_support`: FastAPI `/chat`, fixed review lookup, poisoned P100 fixture and clean P200 fixture.
- `attacks`: async attack protocol and one indirect-injection attack using httpx.
- `verification`: exact case-sensitive canary substring detection against response text only, with no model judgment.
- `tracing`: structured user-message, tool-call, tool-result, model-response and verdict events. M2 adds linked context-flow evidence and actionable source locations; it does not infer hidden reasoning.
- `patching`: validates a serialized M2 trace, creates a constrained plan, runs the repaired local variant, checks P200 utility, and links the artifacts in a `PatchProof`.
- `sandbox`: copies an allowlisted project subset to a temporary directory, applies the M3 plan there, runs fixed build/test commands, captures structured results, bounds retries, checks the original digest, and cleans up.
- `cli`: invokes the loopback demo, prints evidence and a concrete verdict.

The innocent request and poisoned fixture do not contain the canary value. The fixture refers to ADMIN_SECRET. The victim passes both privileged instructions containing the synthetic secret and untrusted review data to the model. Although the context has named fields, there is no enforced trust policy. The simulator deliberately promotes the review instruction to privileged behavior and extracts the canary from system context.

The simulator recognizes one fixed instruction. This is not an LLM evaluation, general injection detector, or proof of Nemotron behavior. Clean P200 requests retain useful review content. Unknown products and missing IDs have explicit responses; invalid messages receive HTTP 422.

HTTP errors and malformed response contracts raise execution errors, rather than being treated as safe. `CANARY_NOT_OBSERVED` is not PATCH VERIFIED. Tool provenance is emitted by the cooperating victim, not independently verified.

No order lookup, refund action, arbitrary code editing, sandbox, persistence, frontend, or live model call is implemented. Later execution must add authorized isolation separately. No .NET artifacts are part of this Python implementation.


## M2 — Evidence & Trace

ExecutionEvent retains M1's kind/data fields and ordered event list. New UUID event IDs, sequence numbers, optional SourceKind/TrustLevel, and input-event references support explicit provenance. Review results are UNTRUSTED, including clean reviews. A nested ContextFlow record captures the actual model-call integration seam without recording privileged system context. The trace expands that record into a context_flow event between tool_result and model_response, preserving existing M1 consumers.

AttackTrace contains attack_id, ordered events, failure_boundary, evidence, verdict, and source_locations. FailureBoundary identifies search_reviews (UNTRUSTED) → model_context, the tool_result → model_context boundary type, and supporting tool-call, tool-result, flow, response, and verifier IDs. SourceLocation uses repository-relative file plus symbol: victims/customer_support/agent.py, CustomerSupportAgent.chat. No brittle line numbers are stored.

The deterministic builder requires the known fixture instruction, linked context flow into privileged context, exact canary in the linked response, and a matching verifier verdict. Missing or contradictory evidence does not establish a failure boundary. Duplicate IDs and non-increasing sequences are rejected. Clean P200 still records context flow but produces no injection failure boundary.

Instruction-like detection recognizes only the known M1 fixture header and instruction. It is not a general prompt-injection classifier. The renderer summarizes tool content and user requests instead of dumping raw prompts. Raw event data remains available for this synthetic demo; this is not a general secret-redaction pipeline.

Evidence strength DETERMINISTIC describes reproducible checks over the local instrumented runtime. Victim-provided provenance is not independently authenticated. The recorded source symbol identifies the inspected local integration seam, not an attestation of arbitrary remote code. Gauntlet observes and experiments on behavior; it has no access to model chain-of-thought and makes no claim of internal causal proof. No security behavior, patching, or live model integration changed in M2.

## M3 — Evidence-Guided Patch + Re-Attack

`plan_patch` accepts serialized `AttackTrace` JSON. It rejects traces without a
`FailureBoundary`, boundaries with missing evidence IDs, and locations other
than `victims/customer_support/agent.py` / `CustomerSupportAgent.chat`.
`PatchPlan` carries the source trace ID, stable boundary ID, supporting event
IDs, target location, failure type, control, evidence-backed rationale, and
security invariant.

The repair adds a data-only boundary flag to the model context at the identified
seam. Tool text stays available as review data, but the deterministic patched
simulator summarizes its review-prose channel without interpreting any tool
text as instructions. The control does not match P100 or the poison sentence;
it applies to all untrusted review content. The default app remains vulnerable
to preserve the frozen M1/M2 baseline. The M3 workflow explicitly creates the
patched variant.

`PatchProof` links the pre-patch trace, plan, applied-control record, post-patch
trace, same-attack comparison, verifier result, P200 regression result, and
full-suite result. Same attack means the innocent user message and
`search_reviews(P100)` call are identical before and after. `PATCH VERIFIED`
requires a confirmed pre-patch leak, matching re-attack, no post-patch canary,
clean P200 behavior, and a passing complete suite.

This is a deterministic repair of one synthetic local victim, not a general
prompt-injection defense. Exploit non-reproduction is evidence about this test,
not universal security. The proof uses observable events and source inspection;
it does not expose or infer hidden model reasoning.

## M4 — Isolated Sandbox Repair Loop

`SandboxWorkspace` accepts the repository-local source root and copies only
four required inputs: `pyproject.toml`, `src`, `victims`, and
`sandbox_checks`. It records the Git revision when available, allocates a
unique temporary directory, rejects absolute and traversal paths, and removes
the directory unless retention was explicitly requested for debugging.

The applicator consumes the existing M3 `PatchPlan`. It accepts only
`victims/customer_support/agent.py` and `CustomerSupportAgent.chat`, parses the
symbol, verifies the exact integration seam, and writes only the resolved file
inside the sandbox. `PatchApplicationResult` records its patch/workspace IDs,
changed files, timestamp, and error.

`SandboxCommandRunner` exposes only BUILD and TEST enum categories. BUILD runs
Python compilation for `src` and `victims`; TEST runs the two explicit sandbox
repair checks. It never accepts shell strings. Both commands use the sandbox
as their working directory, put the sandbox's source first on `PYTHONPATH`,
have a timeout, and capture argv, exit code, stdout, stderr, duration, working
directory, and workspace ID.

`SandboxRepairOrchestrator` allows at most three attempts. Patch, build, and
test failures become `RepairFailure` values with observable command evidence.
A `RepairProposalClient` receives the existing plan, relevant source, and the
failure; the deterministic offline implementation returns a scope-preserving
proposal. Any proposal that changes the authorized patch/file/symbol is
rejected. No Nebius behavior is assumed.

Success requires patch application, build and sandbox regression success,
unchanged original repository digest, and cleanup. The sandbox regression
repeats P100 against the patched default and checks useful P200 content. This
is process-level disposable-copy isolation, not an OS container or network
sandbox. The fixed commands need no network and cannot select external targets,
but M4 does not implement syscall-level network denial. It remains specific to
this synthetic Python repository and does not execute arbitrary repositories.
