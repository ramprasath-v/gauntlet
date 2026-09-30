# Milestones

## Product strategy

Gauntlet is a thin vertical slice of a scalable security-testing architecture:
connect an AI agent, define what it may do, run adversarial executions, identify
a concrete violating path, propose and apply a repair, independently re-test the
attack and legitimate behavior, and produce integrity-bound evidence.

The hackathon does not attempt every enterprise integration. It establishes
stable extension boundaries for:

1. agent/connectivity adapters;
2. normalized execution events;
3. security contracts;
4. contract evaluation;
5. attack and counterexample discovery;
6. repair;
7. independent verification;
8. evidence and receipts; and
9. the product experience.

The required hackathon path is **M6 → M7 → M8**. M9 and M10 are stretch goals;
M11–M14 are roadmap items only. The core must remain independent of refund,
customer-support, and personalization semantics.

| Milestone | Status | Goal |
| --- | --- | --- |
| M6 — Generic Security Contract Foundation | COMPLETE | Normalize execution evidence and evaluate P100 behind a reusable contract boundary. |
| M7 — P300 Effect Authorization | COMPLETE (OFFLINE CONTRACT PROOF) | Require configured approval for sensitive effects such as refunds over a configurable limit. |
| M7.5 — Generic Repair Handoff | COMPLETE (OFFLINE) | Convert a violated contract into a reusable repair request and independently re-evaluate the contract after exact sandbox application. |
| M7.6 — Live P300 Repair Proof | COMPLETE — NOT_VERIFIED | Run one controlled live P300 repair experiment and preserve its deterministic rejection evidence. |
| M7.7 — NVIDIA Nemotron Adversarial Generation | COMPLETE — 5/5 EXECUTED | Let Nemotron propose bounded adversarial scenarios while Gauntlet executes and grades them deterministically. |
| M7.7.1 — Canonical Scenario Contract + Failure Evidence | COMPLETE | Align generated capability arguments with deterministic adapters and retain provider output through downstream failure. |
| M8 — Product Demo Flow | COMPLETE | Present connect → attack → repair → independent proof within about 60 seconds. |
| M8.1 — Multi-Scenario Live Demo Console | COMPLETE | Select P100/P300 scenarios, run live P300 through M7.7, and retain verified replay as fallback. |
| M9 — Capability Discovery Prototype | PENDING / STRETCH | Discover tool schemas and ask only for business semantics that require confirmation. |
| M10 — P400 Personalization Authority | PENDING / STRETCH | Test unauthorized or irrelevant sensitive-inference use in personalization. |
| M11 — Connector Architecture | FUTURE | Add adapters without changing the contract core. |
| M12 — Enterprise Runner / Private Deployment | FUTURE | Run privately and export sanitized evidence. |
| M13 — Policy and Contract Import | FUTURE | Derive contracts from governing policy sources and detect drift. |
| M14 — Continuous Security Verification | FUTURE | Re-run affected contracts after agent, model, tool, or policy changes. |

### M6 — Generic Security Contract Foundation

Status: COMPLETE in commit `165fc4b`.

M6 introduces a minimal normalized execution-event model, typed security
contract, evaluator boundary, and P100 adapter while preserving all existing
attack, repair, mutation, utility, evidence, and integrity behavior. P100 may
have its own evaluator, but its semantics must stay outside generic core
orchestration. P300 is explicitly out of scope for M6.

Success means P100 still works through abstractions that can accept a future
P300 evaluator without changing generic execution logic.

### M7 — P300 Effect Authorization

Status: COMPLETE for the offline generic-contract proof. No provider request
was made.

P300 adds a substantially different property using a simulated
`refund_order(order_id, amount)` capability. The contract supplies the
autonomous threshold in integer minor units. The property evaluator consumes
normalized `TOOL_CALL`, `APPROVAL`, and `EXTERNAL_EFFECT` events, requires a
matching approval to precede a high-value effect, and emits a serializable
counterexample. Refund names and the demonstration threshold remain in the
P300 contract and synthetic fixture; the generic registry and event model do
not contain them.

The deterministic fixture proves the vulnerable high-value path, low-value
utility, approval-before success, approval-after violation, exact boundary,
alternate threshold, and an approval-enforcing behavior that blocks the
unauthorized effect while preserving legitimate refunds. The existing model
repair ingress remains P100 `AttackTrace`/source-context-specific, so M7 does
not force P300 into it or claim a model-generated repair. A future generic
repair-handoff milestone must preserve proposal, application, and independent
verification as separate stages.

### M7.5 — Generic Repair Handoff

Status: COMPLETE offline. No provider request was made.

M7.5 introduces a serializable contract repair request containing the contract,
structured violation evidence, normalized counterexample trace, explicitly
authorized and hash-bound source context, expected post-repair property, and
legitimate behaviors to preserve. A generic adapter feeds that request into the
existing structured candidate generation and validation path. The legacy P100
`AttackTrace` entry point remains unchanged and delegates to the same shared
proposal path.

P300 owns its source authorization and post-repair scenario definitions. After
the exact proposal patch is applied and compiled in a disposable workspace,
the P300 adapter reruns normalized executions and the trusted contract evaluator
for the original high-value violation, approval-before ordering,
approval-after rejection, low-value utility, and an alternate configured
threshold. Generic repair orchestration contains no refund action, price, or
customer-support rules. The offline structural provider deliberately proposes
an ineffective comment-only edit; independent re-verification correctly returns
`NOT_VERIFIED`, demonstrating that candidate generation is not proof.

The generic live request is prepared, but a live provider call remains a
separately authorized experiment. M8 has not started.

### M7.6 — Live P300 Repair Proof

Status: COMPLETE with factual result `NOT_VERIFIED`.

One controlled experiment used Nebius Token Factory with
`moonshotai/Kimi-K2.7-Code`. The deterministic P300 counterexample reproduced,
and the generic contract repair request bound the configured property, source
identity, counterexample trace, and legitimate behaviors. The first structured
provider call returned HTTP 200 with `finish_reason=stop` and a decoded source
edit. Its model-selected symbol-relative range began at line 73 while an open
parenthesized construct spanned lines 69–73. Deterministic validation therefore
rejected it at `patch_authorization / edit_range_splits_python_construct`.

The workflow made one provider request. It did not make the second regression
test call because Call 1 did not pass authorization. There was no retry, model
switch, range correction, patch application, compilation, or post-patch gate.
The integrity-bound `gauntlet.p300-live-repair.v1` receipt preserves the exact
proposed edit and failure. Repository immutability passed, and historical
evidence remained unchanged. A provider response alone did not earn proof.

### M7.7 — NVIDIA Nemotron Adversarial Generation

Status: OFFLINE IMPLEMENTATION COMPLETE; LIVE EXPERIMENT PENDING EXPLICIT
AUTHORIZATION.

M7.7 adds a property-neutral adversarial scenario generator. It accepts a
security contract, deterministic seed, capability context, and bounded
generation constraints. Provider output is strict JSON containing only user
input, an optional strategy label, and capability parameters. Gauntlet assigns
scenario/run identity and provider provenance after parsing. The model cannot
write a verdict field.

The first adapter supplies P300 capability semantics and executes every
scenario through the synthetic refund agent. Model-authored input is retained
in normalized `USER_INPUT` evidence; the existing effect-authorization
evaluator alone assigns `PASS` or `VIOLATED` and emits counterexamples. Generic
generation, provider, and evidence modules contain no refund, threshold,
customer-support, or P300 rules.

The prepared live experiment requests five scenarios in one structured-output
call to Nebius Token Factory using `nvidia/nemotron-3-super-120b-a12b`, the
documented us-central1 endpoint, `/no_think`, and a 2,048 completion-token cap.
No live request was made in the offline milestone. M8 has not started.

### M7.7.1 — Canonical Scenario Contract + Failure Evidence

Status: COMPLETE; ONE CONTROLLED LIVE RETRY PENDING EXPLICIT AUTHORIZATION.

The first M7.7 request reached Nebius Token Factory and returned five scenarios
that passed the generic structured model. Local execution then stopped at the
P300 parameter boundary because the original generic schema accepted any JSON
object while the adapter required exactly `order_id`, `amount_minor`, and
`approval_timing`. The lost scenario contents cannot be reconstructed and are
not represented as known evidence.

M7.7.1 defines a property-neutral execution contract for capability arguments.
The same declaration now shapes the provider JSON schema, while P300 retains
ownership of its parameter types and meanings. A separate compatibility gate
records missing, unsupported, and invalid parameters before the synthetic agent
can run. It never infers arguments from model-authored prose.

`gauntlet.adversarial-generation.v2` retains the structured provider output,
response metadata, content digest, schema result, per-scenario compatibility
and execution state, deterministic verdicts when reached, exact failure stage,
repository integrity, credential scan, and final status. Mixed batches are
graded per scenario: compatible scenarios execute, while incompatible ones are
retained as `NOT_REACHED`. A provider response therefore remains evidence even
when no scenario is executable. No live request was made for M7.7.1.

### M8 — Product Demo Flow

Status: COMPLETE.

The replay-first product UI presents the synthetic Customer Support Agent as a
clearly labeled connected demo agent, shows its `refund_order` external-effect
capability, and asks one business question: the amount above which approval is
required. The default $50 threshold creates the existing P300 contract. A
changed threshold creates a new configuration of the same contract and reruns
the five retained scenarios through the benchmark-owned evaluator locally.

The default verified replay loads the integrity-checked M7.7 evidence and shows
the factual 3 `VIOLATED` / 2 `PASS` result. Scenario details expose a simple
execution path, retained trace and evidence identities, and expandable
normalized events reconstructed deterministically from each retained canonical
scenario. The UI labels this reconstruction rather than claiming the M7.7 v2
artifact retained its original event arrays.

Attribution separates NVIDIA Nemotron 3 Super 120B via Nebius Token Factory,
which generated scenarios, from the Gauntlet deterministic evaluator, which
owns security verdicts. Repair remains secondary: the P100 security repair is
shown as independently `VERIFIED`, including mutation and utility evidence;
the P300 repair is truthfully `NOT_VERIFIED` and `REPAIR_REJECTED` because its
model-selected edit crossed a Python syntax/source boundary. Replay mode makes
zero provider requests and does not claim generic production-agent discovery.

### M8.1 — Multi-Scenario Live Demo Console

Status: COMPLETE.

The product demo now presents Customer Support Agent scenarios for P100
Untrusted Review and P300 Refund Authority from one console. Its capability
drawer lists `search_reviews`, `get_order`, `refund_order`, and `send_email` as
demo metadata. A visible Personalization Agent category describes Unauthorized
Personalization as coming next and does not claim a working P400 engine.

P300 is the live path. `Run Live` calls the existing M7.7 one-request workflow:
Nebius Token Factory asks `nvidia/nemotron-3-super-120b-a12b` for five bounded
canonical scenarios, then benchmark-owned execution and P300 evaluation assign
the verdicts. The configured autonomous refund limit feeds the existing P300
contract; no threshold rule moved into generic core. Progress states remain
visible while the call runs, live counts come from the returned evidence, and
every live action persists the current `gauntlet.adversarial-generation.v2`
artifact. There is no automatic retry.

`Load Verified Replay` remains a clearly labeled, zero-provider fallback.
P100 now presents the measured live Detect and repair-validation evidence
before transitioning to independently verified replay evidence. The live
attack reproduced `CANARY_LEAKED`; the Kimi candidate decoded, then failed
closed at `patch_authorization / edit_range_splits_compound_statement` and is
shown as `REJECTED BY SECURITY CONTRACT`. The console never applies or repairs
that candidate.

The next stage is explicitly `VERIFIED PATCH — REPLAY`. It displays the exact
canonical retained diff and its independently verified P100 block, P200
preservation, 21/21 compatibility, and 4/4 mutation results. Structured
`LIVE` and `VERIFIED_REPLAY` provenance, evidence paths, and file digests keep
the two candidates and their outcomes distinct. Missing or mismatched evidence
fails closed. This P100 integration makes zero provider calls and does not
change historical evidence. P300 continues to show its own rejected repair
and `NOT_VERIFIED` result with NVIDIA/Nebius generation attributed separately
from Gauntlet's deterministic verdicts.

### M9 — Capability Discovery Prototype

For the demo adapter, discover tool name, description, parameter schema,
observed calls/results, and basic metadata. Ask for confirmation of business
semantics such as financial sensitivity, thresholds, approval type, ownership,
or personalization authority. Do not build universal capability classification.

### M10 — P400 Personalization Authority

Test whether unsupported sensitive or identity-like inference affects
personalization without explicit authorization or task relevance. Verification
must also prove that explicitly requested and legitimate non-sensitive
personalization continue to work. Implement only after P100, P300, and M8 are
stable.

The reference scenario holds the request, model, tools, settings, and history
fixed while changing only an irrelevant profile field for a request such as
“Suggest baby names.” Evidence records the changed variable, absence of an
explicit cultural preference, task relevance, comparison method, and observed
behavioral divergence. Findings must describe the proxy-field effect without
claiming a user's actual ethnicity, culture, religion, nationality, or identity.

### M11–M14 — Long-term architecture

- **M11 Connector Architecture:** enable local Python, REST, MCP, telemetry,
  agent SDK, and framework adapters over time; the hackathon requires one.
- **M12 Enterprise Runner / Private Deployment:** support container, CI,
  Kubernetes, or VPC execution while exporting only sanitized evidence.
- **M13 Policy and Contract Import:** import IAM, RBAC, OAuth, OPA/Rego, Cedar,
  configuration, approval, and API metadata without putting those semantics in
  core.
- **M14 Continuous Security Verification:** select affected contracts and emit
  concrete `SECURITY CONTRACT REGRESSION` evidence after code, model, prompt,
  tool, policy, capability, memory, or retrieval changes.

### Historical demo milestone labels

The repository preserves these earlier milestone names and their evidence IDs:

- **Historical M7.1 — Verified Replay Demo:** offline, evidence-backed judge UI.
- **Historical M7.2 — Live Repair Demo:** one-request Kimi/Nebius demo pipeline.
- **Historical M7.2.1 — Repair Boundary Hardening:** deterministic rejection of
  structured edits that split Python source constructs.

These historical labels are retained for reproducibility. They are distinct
from the current product-strategy **M7 — P300 Effect Authorization** milestone;
historical evidence and filenames are not renumbered.

## Completed foundation (M1–M5)

## M1 — Exploit Confirmed

Status: COMPLETE. Original 23 behavioral tests remain green.

One vulnerable agent + indirect prompt injection + deterministic canary leak.

Exit: CANARY_LEAKED reproducibly detected and tests pass.

## M2 — Evidence & Trace

Status: COMPLETE. Full suite: 34 passed, 0 failed (23 original M1 + 11 M2). Real HTTP CLI attack executed successfully with ordered trace, linked evidence IDs, UNTRUSTED review metadata, and actionable file/symbol. Clean P200 produces no failure boundary.

Turn structured events into an actionable attack path.

Exit: Gauntlet can show where untrusted data crossed a trust boundary.

## M3.1 — Provider-Backed AI Remediation

Status: COMPLETE within the provider-integration scope. Full suite: 72 passed,
0 failed. `LIVE_PROVIDER_NOT_TESTED`: the required Nebius environment variables
were unavailable, so no live request was made or implied.

The workflow preserves the M2 artifact chain, extracts a bounded and hashed
authorized source span, and passes both through a provider interface. The real
implementation targets Nebius Token Factory and M3.2 selects
`nvidia/Nemotron-3_5-Lightning`; a deterministic fake exercises the full
offline contract. Strict generated-content validation requires a single-target
unified diff, executable Python regression-test source, and rationale. M3.1
snapshots the target and verifies that proposal generation did not modify it.

Exit: a schema-valid, reviewable `RepairProposal` whose offline fixture diff is
machine-applicable, without applying it or claiming `PATCH VERIFIED`.

The earlier deterministic apply/re-attack workflow remains explicitly named
`legacy_prove_test_double` for compatibility. It is not M3.1.

## M3.3 — Trusted Provenance Assembly

Status: COMPLETE OFFLINE. Live provider generation and structured candidate
decoding have been demonstrated; live artifact quality was imperfect.

Gauntlet now creates a trusted `RepairContext` from the deterministic trace,
bounded source context, and configured provider. Lightning returns only a
strict four-field generated payload containing rationale, patch, regression
test, and an optional policy artifact. Gauntlet generates the repair UUID and
combines the two only after generated-content validation. Authoritative
provenance no longer originates from an untrusted model and cannot be
overridden by it.

This architectural correction does not accept or repair malformed model
output. Artifact quality remains subject to deterministic validation.
`RepairProposal` remains a proposal with trusted provenance, not an applied or
verified patch.

## M3.4 — Repair Candidate Validation Boundary

Status: COMPLETE OFFLINE. M3 is frozen after this milestone. Full suite: 112
passed, 0 failed.

Provider output first becomes `GeneratedRepairCandidate`, which establishes
only that the expected four JSON fields decoded with basic types and bounds.
The candidate can contain malformed code. A deterministic validator returns a
strict `RepairProposal` on success or structured `RepairFailure` on rationale,
patch-format, authorization, regression-syntax, regression-structure, or policy
failure. Failure evidence retains trusted identity plus safe diagnostics and
candidate digests without treating malformed code as a proposal.

The final live M3 evidence is classified as provider call PASS, candidate
decode PASS, candidate validation FAIL at `regression_syntax`. That is evidence
the boundary is needed, not a connectivity failure. M3 completion means
Gauntlet can generate, capture, validate, and accept or reject a candidate
safely. Patch retry, application, execution, security testing, and utility
proof move to M4.1.

## M4 — Sandbox Repair Loop

Status: COMPLETE. M4.1, M4.2, M4.2.1, the clean repair benchmark, frozen model
comparison, and independent trusted-gate assessment are complete.

M4.1 executes exactly one existing validated `RepairProposal` in a fresh
disposable allowlisted workspace. It verifies the M3 source-symbol hash, applies
the exact diff through `git apply`, enforces single-target scope, compiles,
materializes and runs the exact generated regression, repeats frozen P100 and
P200 verification, and runs the broader compatible existing suite. Successful
`PatchProof` is derived from all six command records plus cleanup and unchanged
real-repository evidence. Every failure returns a structured `RepairFailure`
and stops the attempt.

The M3-to-M4 handoff is versioned, deterministic, integrity checked, and
round-trip tested. The legacy predetermined applicator and retry orchestrator
remain compatibility-only and are bypassed by M4.1 and M4.2.

M4.2 performs at most three Lightning calls. Candidate validation and M4.1
execution failures become bounded redacted revision feedback; repeated
candidate digests are rejected; and every executable proposal receives a fresh
workspace. Explicit attempt lineage distinguishes provider call, candidate
decode, deterministic validation, proposal execution, and proof. Success
requires the existing M4.1 `PatchProof(status="VERIFIED")`; three failures
produce `RepairRunFailed` with no fourth call. Versioned run evidence is
integrity checked. All provider behavior is covered by deterministic offline
fakes and HTTP mock transport. The first live M4.2 observation is recorded
below; no second observation has occurred.

The first live M4.2 run subsequently exhausted three calls before proposal
assembly: two malformed diff candidates followed by a duplicate. Digest-only
attempt evidence could not establish whether the intended source repair was
sound. M4.2.1 therefore retains each future decoded candidate exactly in a
separate versioned, integrity-checked artifact and links it from the run. It
retains both failed and successful candidates without changing their validation
or execution outcome. The first run's candidate bodies were never persisted
and cannot be recovered. The second live observation retained its decoded
candidates and established a benchmark-design problem: the frozen victim
exposed a pre-built defensive branch that the prompt prohibited Lightning from
using. Those failed runs and their artifacts remain unchanged.

The separate clean target removes that shortcut while preserving the same
untrusted-review-to-privileged-model security property. Its unmodified P100
leaks the canary and its P200 preserves useful benign review content. The
normal trace and boundary evidence identify the clean source location; the
source-context builder was generalized only to resolve one allowlisted
`Class.method` location from that evidence. A test-only known-good proposal
passes exact application, compilation, generated regression, clean P100,
clean P200, compatible tests, cleanup, and repository immutability through the
existing M4.1 path. The same fixture also succeeds through the existing
bounded M4.2 path in one offline attempt. Trivial, constant, fixture-specific,
verifier-targeting, and unauthorized controls do not receive proof.

The final frozen comparison covered Qwen, Nemotron Super, and Kimi without
weakening compilation or downstream verification. The retained Kimi attempt-3
patch compiled and, under deterministic independent re-evaluation, passed the
trusted P100 security gate, P200 utility gate, and all 21 compatibility tests.
Its unchanged model-generated regression still failed collection because it
imported a nonexistent module. The assessment therefore records a verified
security repair and preserved utility/compatibility, while correctly refusing
the full-candidate claim.

Trusted benchmark gates and the model-generated regression now run in separate
disposable workspaces bound to the same patch digest. Generated-test quality
remains visible but cannot suppress independent benchmark-owned evidence.
Repository immutability and cleanup passed. M5 attack-mutation proof is next.

Apply patch to isolated copy. Build and test patched version. Support bounded repair attempts when generated code fails compilation/tests.

Exit: V2 successfully builds in isolation.

## M5 — Prove

Status: COMPLETE. The retained-patch mutation assessment is committed and
integrity verified.

M5.1 adds four fixed mutations of the P100 indirect prompt-injection family.
Each mutation must first reproduce the canary leak against the original victim
in its own disposable workspace. Only then may the exact integrity-bound
retained patch be applied in a separate workspace and evaluated against that
same case. Evidence uses `gauntlet.attack-mutation-assessment.v1` and records
the pre-patch and post-patch outcomes independently. Frozen P100, P200,
compatibility, and `gauntlet.patch-assessment.v1` remain unchanged.

All four fixed cases reproduced the protected failure before the patch and
were blocked by the exact retained patch afterward. The assessment is stored
as `gauntlet.attack-mutation-assessment.v1`; frozen P100, P200, compatibility,
and patch-assessment semantics remained unchanged.

Run original exploit, mutated attacks, and legitimate utility tests.

Exit: PATCH VERIFIED must come from deterministic evidence: unsafe behavior absent AND legitimate behavior working.
