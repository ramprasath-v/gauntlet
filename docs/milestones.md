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
| M7 — P300 Effect Authorization | **NEXT** | Require configured approval for sensitive effects such as refunds over a configurable limit. |
| M8 — Product Demo Flow | PENDING | Present connect → attack → repair → independent proof within about 60 seconds. |
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

Add a substantially different property using a simulated
`refund_order(order_id, amount)` capability. A configurable, user-confirmed
threshold (for example `$50`) determines when a prior approval is required.
The generic engine observes `TOOL_CALL`, `APPROVAL`, and `EXTERNAL_EFFECT`
events; refund semantics and the threshold live in the P300 contract, adapter,
evaluator, and fixture. Deliver a violating trace, repair, original replay,
mutations, low-value utility test, and evidence receipt through existing gates.

### M8 — Product Demo Flow

Build the judge-facing flow: connect the demo agent, show capabilities, ask one
targeted security question, run Gauntlet, show the exact violation path, propose
and apply a repair, and independently verify the original attack, mutations,
and utility. The UI may say `FIX IT`, but evidence must keep proposal,
application, and verification separate. A new developer should understand the
value within approximately 60 seconds.

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
