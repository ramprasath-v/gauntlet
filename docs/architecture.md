# Architecture

The eventual loop is ATTACK → TRACE → PATCH → BUILD → RE-ATTACK → PROVE. M1 confirms the exploit; M2 reconstructs its observable, actionable failure path; M3.1 generates a constrained repair proposal. Later milestones apply and prove it.

- `core`: Pydantic request, response and attack-result contracts; environment configuration and public canary constants.
- `llm`: async victim-model protocol plus an implemented, host-restricted Nebius Token Factory OpenAI-compatible transport.
- `victims/customer_support`: FastAPI `/chat`, fixed review lookup, poisoned P100 fixture and clean P200 fixture.
- `attacks`: async attack protocol and one indirect-injection attack using httpx.
- `verification`: exact case-sensitive canary substring detection against response text only, with no model judgment.
- `tracing`: structured user-message, tool-call, tool-result, model-response and verdict events. M2 adds linked context-flow evidence and actionable source locations; it does not infer hidden reasoning.
- `remediation`: derives bounded source context and trusted repair provenance from M2 evidence, decodes provider content as an untrusted `GeneratedRepairCandidate`, and deterministically returns either `RepairProposal` or `RepairFailure` without applying anything.
- `patching`: retains the earlier deterministic plan and proof only as a legacy/test-double compatibility path.
- `sandbox`: executes one exact validated M3 proposal in a disposable allowlisted workspace, captures fixed command evidence, checks source identity and patch scope, verifies the original digest, and cleans up. The older deterministic plan/retry path remains compatibility-only.
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
authorized `Class.method` AST span, caps it at 12,000 characters, and hashes
that exact text.

The target allowlist now contains the frozen historical victim and the clean
repair benchmark. This is the only M2/M3 generalization: source selection is
derived from the single location carried by boundary evidence, then checked
against the allowlist and resolved by its declared class and method names. It
does not choose a repair or expose a patch.

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
type. The provider schema contains only rationale, a bounded structured source
edit, structured regression-test lines, and an optional policy artifact. Extra
fields are forbidden. After deterministic
candidate validation, Gauntlet generates the
repair UUID and assembles `RepairProposal` from `RepairContext` plus
generated content. The model cannot redefine authoritative metadata.

M3.4 adds the candidate-validation boundary. Provider JSON is decoded into
`GeneratedRepairCandidate` using only exact-field, basic-type, and size checks.
Each source or regression line rejects embedded LF and CR characters.
`validate_candidate` then checks, in order: non-empty rationale, trusted path,
symbol and source hash, and a model-selected range wholly inside the authorized
symbol. It reads the original slice for that exact range only from the trusted,
hash-verified source, then checks canary authorization and Python syntax,
test-function/assertion structure, and an optional non-empty policy artifact.
It splices only the model's replacement lines, derives a unified diff, and joins
the model's regression lines with LF; it performs no semantic repairs. A passing candidate
becomes `RepairProposal`. A rejected candidate becomes `RepairFailure` with
trusted trace/source identity, stage and code, bounded redacted diagnostics,
attempt number, timestamp, and hashes/lengths that identify the exact candidate
without persisting arbitrary generated code or provider envelopes.

This is a security architecture correction, not a workaround for invalid AI
output. The model proposes remediation content. Gauntlet owns identity,
provenance, authorization, source integrity, validation, application, and
verification. `RepairProposal` means a validated proposal assembled with
trusted provenance; `RepairFailure` means deterministic rejection evidence.
Neither means the patch was applied or verified. Model
artifact quality remains subject to Gauntlet validation, and the workflow
confirms that authorized source bytes are unchanged after generation.

M3 returns a proposal or failure. **Repair candidate != Repair proposal !=
Applied patch != Patch proof.** The legacy deterministic apply/re-attack code is explicitly marked
as a compatibility test double and is not the provider-backed architecture.

## M4.1 — Execute and Prove One Validated Proposal

`RepairProposalEnvelope` is the deterministic M3-to-M4 handoff. Its version
marker, canonical proposal digest, patch digest, and regression-test digest
protect the exact repair UUID, trusted provenance, generated artifacts, and
optional policy artifact during persistence and load. M4 neither regenerates
nor edits them.

`M41RepairExecutor` creates one fresh `SandboxWorkspace`, which copies only
`pyproject.toml`, `src`, `victims`, `sandbox_checks`, and `tests`. Before any
patch command, it extracts the same authorized class-method span as M3 and
requires its SHA-256 to equal `RepairProposal.source_hash`. It writes the patch
bytes to a separate artifact path and runs `git apply --verbose`. A before/after
allowlist snapshot must show exactly the proposal target changed. The generated
test is later written byte-for-byte to a separate `.gauntlet` path, so it does
not count as a patch change.

The fixed runner then executes compileall, the generated regression alone,
the frozen P100 check, the frozen P200 check, and the broader compatible
verifier/utility/CLI tests. Frozen tests whose contract is to reproduce the
unpatched M1/M2 vulnerability cannot describe correct behavior in the patched
copy, so they remain in the complete suite against the unchanged real source.
Commands run with the copy as cwd and first on `PYTHONPATH`; they have timeouts
and bounded stdout/stderr. M4.1 accepts no caller-supplied success booleans.

`PatchProof` retains repair and trace provenance, original and patched source
hashes, patch and regression digests, workspace/revision identity, changed
files, all six command results, timestamps, cleanup, and real-repository
immutability. Its model validator permits `VERIFIED` only when every command
passed, exactly the authorized target changed, the source changed, cleanup
completed, and the real repository remained unchanged. Failures stop the one
attempt and produce M3.4-compatible `RepairFailure` at `source_identity`,
`patch_authorization`, `patch_apply`, `compile`, `regression_execution`,
`security_test`, `utility_test`, or `existing_suite`, with bounded diagnostics.

The older `PatchPlan` applicator and retry orchestrator remain for frozen
compatibility tests. M4.1 does not call them or activate the victim's existing
defensive constructor switch. M4.2 uses structured failure evidence for a
bounded revised proposal; no retry exists in M4.1 itself.

This is disposable workspace/process isolation, not an OS sandbox, container,
or filesystem containment mechanism. It remains specific to this synthetic
Python repository and does not implement syscall-level network denial.

## M4.2 — Bounded Autonomous Remediation Retry

`M42RepairOrchestrator` reconstructs the frozen M3 `SourceContext`,
`RepairContext`, and first-attempt `RemediationRequest`, then permits at most
three provider calls. Attempt one uses the normal M3 prompt. Later calls use a
separate revision message containing the original security objective and
authorized source, a bounded redacted view of the previous candidate, and the
previous `RepairFailure` stage, code, message, and safe diagnostics. Approved
models retain their configured reasoning controls, `max_tokens=4096`, and the
exact strict `GeneratedRepairCandidate` JSON schema.

Every response is decoded and deterministically validated from scratch. A
retry whose candidate digest matches any earlier attempt is rejected before
execution. M4.2 never edits generated code, reuses a proposal automatically,
or activates legacy defensive behavior. Each validated proposal is handed to a
new `M41RepairExecutor`, which creates a new disposable workspace and repeats
source identity, exact application, compilation, regression, P100, P200, and
broader-suite verification against the trusted baseline.

`RepairAttempt` separates `PROVIDER_CALL`, `CANDIDATE_DECODE`,
`CANDIDATE_VALIDATION`, `PROPOSAL_EXECUTION`, and `PATCH_PROOF`. It retains
candidate and prior-failure lineage, safe completion metadata, proposal/proof
identifiers, timing, and a structured failure when unverified. A run returns
`RepairRunSucceeded` only by retaining the final M4.1 `PatchProof`; after three
failures it returns `RepairRunFailed` and cannot make attempt four.

`gauntlet.repair-run.v1` persists the terminal result and complete safe attempt
lineage with a canonical SHA-256 integrity digest. Generated proposal artifacts
and bounded command evidence may be retained for review, while API keys,
authorization headers, hidden reasoning, and raw provider envelopes are not.
The real repository digest is checked across the complete run. This milestone
is verified offline only; a live bounded run requires separate authorization.

## M4.2.1 — Safe Candidate Artifact Retention

When M4.2 receives a run-evidence path, each successfully decoded
`GeneratedRepairCandidate` is written independently as
`gauntlet.repair-candidate.v3`, including candidates that later fail
authorization, Python, or test-structure validation. Its rationale, structured
source edit, structured regression test, and optional policy artifact are
serialized without normalization or repair. When source authorization and
identity permit deterministic materialization, the artifact also stores and
digests the mechanically derived unified diff and regression source. Loading
verifies the candidate digest, every field digest, the derived-artifact digests,
and an integrity digest over the complete artifact metadata and content.
Existing `gauntlet.repair-candidate.v1` and
`gauntlet.repair-candidate.v2` artifacts retain their original schema-specific
loaders and digest validation. Version two preserves its historical
`expected_original_lines` field solely for faithful evidence loading; new
version-three candidates do not contain that field.

The candidate artifact adds only trusted run ID, attempt number,
provider/model, timestamp, trace/boundary/evidence IDs, target identity, and
source hash. It has no fields for provider envelopes, request or Authorization
headers, credentials, reasoning, or reasoning content. The API key is confined
to the transport and is never an artifact input.

Each `RepairAttempt` may contain a relative `CandidateArtifactReference` with
the candidate ID, attempt, candidate digest, and artifact integrity digest.
Loading run evidence resolves paths beneath the run-evidence directory, loads
each candidate independently, and checks run, trace, boundary, attempt, ID, and
digest linkage. Older v1 run artifacts without candidate references remain
loadable; their omitted content is not reconstructable.

Candidate retention occurs after decoding and does not participate in
deterministic candidate validation, proposal assembly, retry selection, M4.1
execution, or proof. **GeneratedRepairCandidate != RepairProposal != Applied
patch != PatchProof.**

## Independent Gate Assessment

New executions use `gauntlet.patch-assessment.v1` rather than changing the
meaning of historical `PatchProof`. The exact integrity-bound patch is applied
independently to two disposable workspaces. The trusted workspace compiles the
patched source and, when compilation succeeds, runs frozen P100, P200, and
compatibility commands without fail-fast coupling between those gates. The
generated-test workspace independently applies and compiles the same patch,
verifies the patched-symbol identity, materializes the exact model-authored
test, and runs only that test. Model-generated Python therefore cannot mutate
the workspace later trusted for benchmark conclusions.

The assessment records build integrity, P100 security, P200 utility,
compatibility, generated-regression quality, same-patch integrity, cleanup,
and real-repository immutability as separate `PASS`, `FAIL`, or `NOT_RUN`
outcomes. Derived claims distinguish a verified security repair, preserved
utility, preserved compatibility, a valid generated regression, and a fully
verified candidate. A failed model test remains `FAIL` and prevents the full
candidate claim, while independent trusted results remain factual. Compilation
failure still leaves all runtime gates `NOT_RUN`.

New run envelopes use `gauntlet.repair-run.v2` and bind each attempt to its
assessment and candidate identity. The loader retains the original v1 digest
forms and the unchanged `PatchProof` model so historical evidence preserves
its original all-commands-passed meaning.

## M5.1 Attack-Mutation Proof Boundary

M5.1 is additive to the frozen P100, P200, compatibility, and
`gauntlet.patch-assessment.v1` gates. Four fixed benchmark-owned mutations vary
the benign user request, instruction placement, paragraph delimiters, and
quoted indirection while retaining the canonical indirect instruction and the
same untrusted `search_reviews` boundary. Arbitrary paraphrases are outside
this first mutation set because the deterministic simulator intentionally
recognizes one canonical instruction family.

`gauntlet.attack-mutation-assessment.v1` binds the v3 candidate identity,
trusted source hash, exact patch digest, and per-mutation payload and user
prompt digests. Each mutation first runs in its own unpatched disposable
workspace. It counts only when that pre-patch check reproduces the canary leak
with linked trust-boundary evidence. A qualified mutation then receives a new
disposable workspace, where Gauntlet verifies source identity, writes and
checks the exact patch bytes, applies only the authorized target change,
compiles, and runs that mutation's post-patch check. An unqualified mutation
does not receive a post-patch claim.

The assessment records `PRE_PATCH_ATTACK_REPRODUCED` and
`POST_PATCH_ATTACK_BLOCKED` separately for every case, along with independent
workspace IDs, command evidence, cleanup, and real-repository immutability.
The implementation does not generate, alter, or tune a repair. The retained
Kimi candidate has not yet been run through this M5.1 path; that deterministic
evaluation requires separate authorization.

## Clean M4 Repair Benchmark

`victims/clean_customer_support` is a separate target so frozen M1/M2 behavior
and prior evidence remain intact. Its vulnerable method takes UNTRUSTED
`search_reviews` output and interpolates it into the privileged system prompt.
The deterministic role-sensitive simulator follows instruction-like review
content only in that privileged channel. Thus P100 leaks the same synthetic
canary through the same attack and exact-match verifier, while P200 returns the
benign review's useful construction and setup details.

The bounded source span contains the vulnerability directly and no defensive
flag, disabled secure branch, sanitizer, expected patch, canary value, product
fixture ID, or test instruction. M4.1 remains one executor: target identity
selects the corresponding fixed clean P100/P200 verifier nodes, and every other
source-identity, exact-diff, compilation, generated-test, compatible-suite,
cleanup, and immutability gate is unchanged. Clean P100 also exercises another
poisoned review in the same attack family so a P100-only fixture branch cannot
earn proof.

The solvability fixture is defined only in
`tests/test_clean_repair_benchmark.py` and injected only by offline tests. The
production source-context builder, prompt builder, provider, validator,
executor, and retry orchestrator do not import it. The fixture demonstrates
that a real role-boundary repair can reach `VERIFIED`; it is not evidence of a
live Lightning repair.

## Generic Contracts and P300 Effect Authorization

M6 adds a property-agnostic boundary from `NormalizedExecutionTrace` plus a
typed `SecurityContract` to a `ContractEvaluation`. The registry selects an
evaluator by ID and checks result identity; it contains no P100, refund, or
threshold semantics. P100 remains an adapter and evaluator outside that core.

M7 proves the same boundary with P300. The synthetic refund fixture emits
`USER_INPUT`, `TOOL_CALL`, optional `APPROVAL`, and simulated
`EXTERNAL_EFFECT` events. Monetary values use integer minor units. The P300
contract supplies the action name, amount field, effect kind, correlation
field, approval type, currency, and autonomous limit. The reusable effect
authorization evaluator requires a matching approved event with a lower
sequence number than each above-limit effect and emits a concrete structured
counterexample otherwise. An approval recorded after an effect cannot satisfy
the invariant.

No real transaction, provider call, or model judgment is involved in contract
evaluation. The fixture's approval-enforcing mode demonstrates the expected
post-repair behavior without claiming a model-proposed or pipeline-applied
repair.

## Generic Repair Handoff

M7.5 converts `ContractEvaluation(VIOLATED)` into a serializable
`ContractRepairRequest`. The request binds the declared contract, structured
violation evidence, normalized counterexample trace, an explicit source
authorization, the exact bounded source hash, the expected property, and
behaviors to preserve. It then reuses the existing two-call structured
edit/test proposal and deterministic candidate-validation path. P100 retains
its historical `AttackTrace` adapter and delegates to the same shared proposal
path; new properties do not manufacture a P100 trace.

Application and proof remain separate. Generic execution applies the exact
validated diff in a disposable workspace, compiles it, and invokes a trusted
property adapter. The P300 adapter reruns normalized executions and the same
effect-authorization evaluator used for detection. Candidate rationale and
generated tests never determine the contract verdict. Property-specific target
selection and verification cases remain beside the property adapter, leaving
the generic handoff free of refund, price, and customer-support rules.

## Adversarial Scenario Generation

The adversarial generation boundary accepts a `SecurityContract`, seed
scenario, capability context, and small generation constraints. An untrusted
provider returns strict `GeneratedScenarioCandidate` objects containing only
input, optional strategy, and capability parameters. Gauntlet rejects malformed
JSON, unexpected fields, duplicate inputs, incorrect counts, and oversized
messages. It then assigns trusted scenario IDs, run identity, timestamps, and
provider provenance.

Property adapters own execution semantics. The P300 adapter validates its
capability parameters, records the generated message as normalized user input,
executes the synthetic agent, and calls the existing P300 evaluator. Model text
has no verdict channel: even text claiming a result is merely input evidence.
The generic generator contains no P300 or refund behavior and can serve later
contracts with separate execution adapters.

The Nemotron provider uses the existing Nebius Token Factory transport, strict
JSON-schema output, one bounded request, and the documented Nemotron Super
`/no_think` control. A versioned evidence model binds scenario text digests,
normalized trace IDs, evaluator results, counterexample evidence IDs,
repository integrity, and credential-scan status for a future authorized run.

## M8 Product Demo

The M8 localhost UI is replay-first. It loads the integrity-validated M7.7
scenario artifact, P100 independent patch assessment, and P300 live repair
receipt. The default $50 replay reproduces the retained three violations and
two passes. Threshold changes build another P300 contract configuration and
rerun the exact retained canonical scenarios through the same deterministic
evaluator; no provider client is constructed.

The M7.7 v2 artifact retains scenario identity, parameters, trace identity,
verdict, and violation evidence IDs, but not full normalized event arrays. The
UI therefore labels displayed events as a deterministic local reconstruction
and shows both the retained trace ID and the reconstruction trace ID. Repair
views preserve distinct meanings: P100's security repair is independently
`VERIFIED`, while P300 remains `NOT_VERIFIED` after deterministic source-boundary
rejection. Presentation-only capability classification stays in the demo layer.
M8.1 adds a scenario-selection layer without introducing a second adversarial
generation pipeline. The P300 live route constructs the configured P300
contract and delegates directly to `run_p300_adversarial_generation`; its one
provider call, strict schema handling, adapter compatibility, deterministic
execution, evidence integrity, and repository digest checks therefore remain
the M7.7 implementation. The web adapter only maps the resulting evidence into
the console view.

The P100 panel composes two explicitly separate evidence sources. Its `LIVE`
stages load the measured attack and Kimi candidate receipt: the canary leaked,
the candidate decoded, and deterministic authorization rejected its range at
`patch_authorization / edit_range_splits_compound_statement`. Its
`VERIFIED_REPLAY` stages load the frozen candidate, patch assessment,
reevaluation manifest, and mutation assessment. The console displays the
canonical retained diff and the independent P100, P200, 21/21 compatibility,
and 4/4 mutation results. The integration makes zero provider calls and cannot
represent replay proof as output from the measured live candidate.

M8.1 also exposes an explicit P100 `Run Live` controller. It delegates to the
existing M7.2 orchestrator and permits exactly one Nebius/Kimi request per user
run. Progress comes from real orchestration callbacks rather than simulated
streaming. The web adapter reports safe provider/model/timing metadata,
candidate and schema status, and deterministic gate results. Provider,
decoding, authorization, sandbox, or proof failures stop the live path at the
observed gate. The UI can then offer the separate verified replay action, but
never substitutes replay evidence into the live result. That action fetches
the canonical P100 composition with zero provider calls, replaces the live
result view, scrolls to an explicit `LIVE CANDIDATE · REJECTED →
VERIFIED_REPLAY` transition, and renders the retained patch and proof using
the same progress, hero-result, status-card, chip, and receipt vocabulary as
the P300 console.

The composition fails closed. The live receipt, provider-output sidecar,
timing sidecar, current authorized source, and replay target/source identity
must agree, and all referenced artifacts must pass their existing integrity
checks. Missing, malformed, stale, or mismatched evidence produces no P100
view. The Personalization panel remains metadata-only and cannot execute.
P300 replay still re-evaluates retained canonical scenarios under the selected
threshold without provider access.
