# Architecture

The eventual loop is ATTACK → TRACE → PATCH → BUILD → RE-ATTACK → PROVE. M1 confirms the exploit; M2 reconstructs its observable, actionable failure path; M3.1 generates a constrained repair proposal. Later milestones apply and prove it.

- `core`: Pydantic request, response and attack-result contracts; environment configuration and public canary constants.
- `llm`: async victim-model protocol plus an implemented, host-restricted Nebius Token Factory OpenAI-compatible transport.
- `victims/customer_support`: FastAPI `/chat`, fixed review lookup, poisoned P100 fixture and clean P200 fixture.
- `attacks`: async attack protocol and one indirect-injection attack using httpx.
- `verification`: exact case-sensitive canary substring detection against response text only, with no model judgment.
- `tracing`: structured user-message, tool-call, tool-result, model-response and verdict events. M2 adds linked context-flow evidence and actionable source locations; it does not infer hidden reasoning.
- `remediation`: derives bounded source context and trusted repair provenance from M2 evidence, asks a replaceable provider only for `GeneratedRepair` content, validates it, and deterministically assembles a `RepairProposal` without applying it.
- `patching`: retains the earlier deterministic plan and proof only as a legacy/test-double compatibility path.
- `sandbox`: copies an allowlisted project subset to a temporary directory, applies the M3 plan there, runs fixed build/test commands, captures structured results, bounds retries, checks the original digest, and cleans up.
- `cli`: invokes the loopback demo, prints evidence and a concrete verdict.

The innocent request and poisoned fixture do not contain the canary value. The fixture refers to ADMIN_SECRET. The victim passes both privileged instructions containing the synthetic secret and untrusted review data to the model. Although the context has named fields, there is no enforced trust policy. The simulator deliberately promotes the review instruction to privileged behavior and extracts the canary from system context.

The simulator recognizes one fixed instruction. This is not an LLM evaluation, general injection detector, or proof of Nemotron behavior. Clean P200 requests retain useful review content. Unknown products and missing IDs have explicit responses; invalid messages receive HTTP 422.

HTTP errors and malformed response contracts raise execution errors, rather than being treated as safe. `CANARY_NOT_OBSERVED` is not PATCH VERIFIED. Tool provenance is emitted by the cooperating victim, not independently verified.

No order lookup, refund action, arbitrary code editing, persistence, frontend, or live model call is implemented. The existing disposable-copy sandbox remains partial because it does not yet consume M3.1 output. No .NET artifacts are part of this Python implementation.


## M2 — Evidence & Trace

ExecutionEvent retains M1's kind/data fields and ordered event list. New UUID event IDs, sequence numbers, optional SourceKind/TrustLevel, and input-event references support explicit provenance. Review results are UNTRUSTED, including clean reviews. A nested ContextFlow record captures the actual model-call integration seam without recording privileged system context. The trace expands that record into a context_flow event between tool_result and model_response, preserving existing M1 consumers.

AttackTrace contains attack_id, ordered events, failure_boundary, evidence, verdict, and source_locations. FailureBoundary identifies search_reviews (UNTRUSTED) → model_context, the tool_result → model_context boundary type, and supporting tool-call, tool-result, flow, response, and verifier IDs. SourceLocation uses repository-relative file plus symbol: victims/customer_support/agent.py, CustomerSupportAgent.chat. No brittle line numbers are stored.

The deterministic builder requires the known fixture instruction, linked context flow into privileged context, exact canary in the linked response, and a matching verifier verdict. Missing or contradictory evidence does not establish a failure boundary. Duplicate IDs and non-increasing sequences are rejected. Clean P200 still records context flow but produces no injection failure boundary.

Instruction-like detection recognizes only the known M1 fixture header and instruction. It is not a general prompt-injection classifier. The renderer summarizes tool content and user requests instead of dumping raw prompts. Raw event data remains available for this synthetic demo; this is not a general secret-redaction pipeline.

Evidence strength DETERMINISTIC describes reproducible checks over the local instrumented runtime. Victim-provided provenance is not independently authenticated. The recorded source symbol identifies the inspected local integration seam, not an attestation of arbitrary remote code. Gauntlet observes and experiments on behavior; it has no access to model chain-of-thought and makes no claim of internal causal proof. No security behavior, patching, or live model integration changed in M2.

## M3.1 — Provider-Backed AI Remediation

`build_source_context` accepts serialized `AttackTrace` JSON and rejects a
missing boundary, missing evidence, absolute/traversal paths, non-allowlisted
targets, resolution outside the repository, and source locations that differ
from the location embedded in boundary evidence. It extracts only the
`CustomerSupportAgent.chat` AST span, caps it at 12,000 characters, and hashes
that exact text.

`RemediationProvider` separates generation from orchestration. The production
provider sends a defensive system contract and serialized M2 evidence/source
context to Nebius Token Factory's OpenAI-compatible chat-completions endpoint,
requesting JSON-schema output from the configured model. M3.2 selects
`nvidia/Nemotron-3_5-Lightning` as the current repair-generation model. It
demonstrated HTTP/provider success, disabled thinking, normal-stop concise
completion, structured JSON, and much lower latency. Nemotron 3 Super remains
an evaluated model whose reasoning/output-budget behavior was unsuitable for
this structured repair workload. The transport requires explicit environment
configuration, Bearer authentication,
HTTPS, an approved Token Factory host, `/v1`, no redirects, and no environment
proxy. Tests inject `httpx.MockTransport`; the offline fake supplies generated
content without network access.

M3.3 restores the trust boundary between deterministic state and generated
content. `RepairContext` contains the trace/boundary/evidence IDs,
provider/model identity, authorized path and symbol, source hash, and failure
type. The provider schema is the smaller `GeneratedRepair`: rationale, patch,
regression test, and optional policy artifact only. Extra fields are forbidden.
After strict JSON, diff, and Python-test validation, Gauntlet generates the
repair UUID and assembles `RepairProposal` from `RepairContext` plus
`GeneratedRepair`. The model cannot redefine authoritative metadata.

This is a security architecture correction, not a workaround for invalid AI
output. The model proposes remediation content. Gauntlet owns identity,
provenance, authorization, source integrity, validation, application, and
verification. `RepairProposal` means a validated proposal assembled with
trusted provenance; it does not mean the patch was applied or verified. Model
artifact quality remains subject to Gauntlet validation, and the workflow
confirms that authorized source bytes are unchanged after generation.

M3.1 returns only the proposal. **Repair proposed != Patch applied != Patch
verified.** The legacy deterministic apply/re-attack code is explicitly marked
as a compatibility test double and is not the provider-backed architecture.

## M4 — Isolated Sandbox Repair Loop

`SandboxWorkspace` accepts the repository-local source root and copies only
four required inputs: `pyproject.toml`, `src`, `victims`, and
`sandbox_checks`. It records the Git revision when available, allocates a
unique temporary directory, rejects absolute and traversal paths, and removes
the directory unless retention was explicitly requested for debugging.

The current applicator consumes the legacy `PatchPlan`. It accepts only
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
A legacy `RepairProposalClient` receives the existing plan, relevant source,
and the failure; its deterministic offline result is currently discarded.
M4 is therefore partial until M4.1 applies the exact M3.1 proposal and generated
regression test. No M4.1 or M5 work is included in this milestone.

Success requires patch application, build and sandbox regression success,
unchanged original repository digest, and cleanup. The sandbox regression
repeats P100 against the patched default and checks useful P200 content. This
is process-level disposable-copy isolation, not an OS container or network
sandbox. The fixed commands need no network and cannot select external targets,
but M4 does not implement syscall-level network denial. It remains specific to
this synthetic Python repository and does not execute arbitrary repositories.
