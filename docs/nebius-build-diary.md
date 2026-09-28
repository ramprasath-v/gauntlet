# Nebius / NVIDIA Build Diary

## Entry

Date: 2026-09-27
Milestone: M1 — Exploit Confirmed

Nebius product used: Not used yet.
NVIDIA model used: Not used yet.

What we attempted:
Created an async model protocol, a deterministic vulnerable simulator, a Nebius adapter boundary, and environment-only future configuration. No live provider call was attempted.

Zero-to-hello-world onboarding:
- steps: not attempted for Nebius
- approximate time: not measured
- documentation used: no Nebius documentation evaluated in M1

What worked well:
Not used yet; no provider observations.

Specific friction / bugs:
Not evaluated.

Errors encountered:
No provider requests were made.

Latency:
Not measured.

Reliability:
Not measured.

Cost/token observations:
Not measured; no live model calls were made.

What would improve the product:
No evidence-based provider feedback yet.

Would we build with it again?
Why / why not?
Not evaluated. Intended Nemotron use through Nebius Token Factory: attack planning, actionable failure-path analysis, patch generation, regression-test generation, and attack mutation. Final verdicts remain deterministic application decisions based on execution evidence.


## Entry

Date: 2026-09-27
Milestone: M2 — Evidence & Trace

Nebius product used: Not used yet.
NVIDIA model used: Not used yet.

What we attempted: Local deterministic event linking, trust metadata, source-location recording, and plain-text trace rendering. No provider requests.

Zero-to-hello-world onboarding:
- steps: not attempted
- approximate time: not measured
- documentation used: none for Nebius in M2

What worked well: No provider observations.
Specific friction / bugs: Not evaluated.
Errors encountered: No provider requests.
Latency: Not measured.
Reliability: Not measured.
Cost/token observations: Not measured.
What would improve the product: No evidence-based provider feedback yet.
Would we build with it again? Why / why not? Not evaluated yet.

## Entry

Date: 2026-09-27
Milestone: M3.1 — Single Live-Provider Smoke Validation

Nebius product used: Token Factory chat-completions API.
NVIDIA model requested: `nvidia/nemotron-3-super-120b-a12b`.
Configured base URL: `https://api.tokenfactory.nebius.com/v1`.

What we attempted: Loaded the local, gitignored `.env` without printing the API
key and ran the existing `nebius-repair-smoke` command once. The command built
the P100 `AttackTrace`, `FailureBoundary`, and bounded `SourceContext`, then made
exactly one real remediation request. No retry was attempted.

Result: FAILED. Token Factory returned HTTP `422 Unprocessable Entity` from
`/v1/chat/completions`. The command exited with status 2 and produced no
`RepairProposal` output.

Validation results:
- API request succeeds: FAIL (`422 Unprocessable Entity`)
- structured output validates as `RepairProposal`: NOT EVALUATED; no proposal returned
- trace/boundary/evidence provenance preserved: NOT EVALUATED; no proposal returned
- returned patch is machine-applicable: NOT EVALUATED; no patch returned
- generated regression test is valid Python: NOT EVALUATED; no test returned
- repository source remains unchanged: PASS; pre/post source-tree digests matched

Latency: 2.45 seconds end-to-end wall time for the local trace construction and
single provider attempt. API-only latency was not separately instrumented.

Errors and friction: The current client raises on non-success HTTP status
without retaining the provider response body, so this run established the 422
status but not Token Factory's detailed validation message. Diagnosing it would
require a future authorized request; none was made in this smoke validation.

Reliability observation: 0 of 1 live requests succeeded. A single failed
request is insufficient to characterize general service reliability.

Cost/token observations: Unknown. No completion was returned and usage data was
not captured.

Patch handling: No patch or regression test was returned, no repair was
applied, and M4.1/M5 were not started.

## Entry

Date: 2026-09-27
Milestone: M3.1 — Provider-Backed AI Remediation

Nebius product used: Token Factory API integration implemented; live service not called.
NVIDIA model selected: `nvidia/nemotron-3-super-120b-a12b`.

What we attempted: Implemented the documented OpenAI-compatible
`/v1/chat/completions` boundary with Bearer authentication and JSON-schema
structured output. The provider receives only M2 evidence plus the bounded,
hashed authorized source symbol and returns a strict `RepairProposal`.

Why this model: Nebius's official model cookbook lists Nemotron 3 Super as an
available NVIDIA reasoning/instruction-following model with structured-output
support. Its model identifier and the us-central1 Token Factory base URL are
recorded in `.env.example` rather than inferred at runtime.

Zero-to-hello-world onboarding:
- setup: export `NEBIUS_API_KEY`, `NEBIUS_BASE_URL`, and `NEBIUS_MODEL`, then run `python -m gauntlet.cli nebius-repair-smoke`
- authentication: Bearer token from `NEBIUS_API_KEY`; secrets are never logged or committed
- API compatibility: OpenAI-compatible chat-completions request implemented directly with existing `httpx`
- structured output: request uses `response_format.type=json_schema` with the Pydantic-generated `RepairProposal` schema
- documentation used: Nebius Token Factory structured-output documentation and the official Nebius Token Factory cookbook page for Nemotron 3 Super
- approximate live onboarding time: not measured

What worked well: A mock transport verified the final URL, Bearer header, exact
model ID, and structured-output request. The deterministic provider exercised
the entire evidence-to-proposal flow, and its diff passed `git apply --check`.

Specific friction / bugs: An initial relative URL began with `/`, which would
have discarded `/v1` under standard base-URL resolution; the final transport
uses a trailing-slash base and relative `chat/completions`. The initial offline
fixture diff lacked enough context for `git apply`; contextual hunks fixed it.

Errors encountered: No provider response errors because no live request was made.
Latency: Not measured.
Reliability: Live reliability not evaluated; mocked request-contract and offline flow tests pass.
Cost/token observations: Not measured; no paid request was made.
Live request made: No. `NEBIUS_API_KEY`, `NEBIUS_BASE_URL`, and `NEBIUS_MODEL` were unset. `LIVE_PROVIDER_NOT_TESTED`.

What would improve the product: A documented non-billable validation endpoint
or schema-only request mode would allow credential and model-access checks
without a generation charge. Live error and latency observations require a
configured account.

Would we build with it again? The integration contract is straightforward and
testable, but no conclusion about live service behavior is justified until the
explicit smoke command runs with credentials.

## Entry

Date: 2026-09-27
Milestone: M3 — Evidence-Guided Patch + Re-Attack

Nebius product used: Not used yet.
NVIDIA model used: Not used yet.

What we attempted: Consumed serialized M2 evidence to plan one constrained
local repair, re-ran the same exploit, checked legitimate behavior, and linked
the results in a deterministic proof artifact. No provider request was made.

Zero-to-hello-world onboarding:
- steps: not attempted
- approximate time: not measured
- documentation used: none for Nebius in M3

What worked well: No provider observations.
Specific friction / bugs: Not evaluated.
Errors encountered: No provider requests.
Latency: Not measured.
Reliability: Not measured.
Cost/token observations: Not measured.
What would improve the product: No evidence-based provider feedback yet.
Would we build with it again? Why / why not? Not evaluated yet.

## Entry

Date: 2026-09-27
Milestone: M4 — Isolated Sandbox Repair Loop

Nebius product used: Not used yet.
NVIDIA model used: Not used yet.

What we attempted: Applied the existing M3 plan to disposable local project
copies, ran fixed build/test commands, captured structured failures, exercised
a three-attempt bound, and verified cleanup plus an unchanged source digest.
A deterministic repair-proposal client exercised the future provider boundary.
No provider request was made.

Zero-to-hello-world onboarding:
- steps: not attempted
- approximate time: not measured
- documentation used: none for Nebius in M4

What worked well: No provider observations.
Specific friction / bugs: Not evaluated.
Errors encountered: No provider requests.
Latency: Not measured.
Reliability: Not measured.
Cost/token observations: Not measured.
What would improve the product: No evidence-based provider feedback yet.
Would we build with it again? Why / why not? Not evaluated yet.

## Entry

Date: 2026-09-27
Milestone: M3.1 — Offline Investigation After Live HTTP 422

Live request made during this investigation: No.

Observed facts:
- The one earlier live smoke used `https://api.tokenfactory.nebius.com/v1` with `nvidia/nemotron-3-super-120b-a12b` and returned HTTP 422.
- The current official Nemotron-3-Super cookbook uses `https://api.tokenfactory.us-central1.nebius.com/v1/` for that exact model.
- Nebius's structured-output documentation shows `response_format.type=json_schema` with a Pydantic-generated schema supplied directly as `response_format.json_schema`, which matches Gauntlet's envelope.
- Gauntlet's prior request added `temperature: 0`; the cited Nemotron quickstart and structured-output example omit that optional field.
- The generated `RepairProposal` schema is valid JSON Schema and contains `additionalProperties`, `anyOf`, `default`, `minItems`, `minLength`, `pattern`, `properties`, `required`, `title`, and `type` keywords.
- The earlier client discarded the provider's validation response body after `raise_for_status`, so the server's exact 422 detail is unavailable.

Changes made offline:
- Updated the local gitignored `.env` and `.env.example` to the documented regional endpoint, including its trailing slash.
- Enforced the regional host whenever the configured model is Nemotron-3-Super.
- Removed the optional `temperature` parameter so the serialized request matches the documented minimal model request more closely.
- Retained strict JSON-schema output; there is no unstructured fallback and `RepairProposal` validation was not weakened.
- Added bounded provider-error body capture with recursive credential/header redaction and truncation at 4,000 characters.

Root-cause assessment: The endpoint/model mismatch is the strongest offline
hypothesis and is directly supported by the model-specific cookbook. It cannot
be proven from the previous run because the 422 body was lost. The documented
structured-output envelope is not a likely cause. Unsupported individual schema
keywords or an optional request parameter remain unconfirmed possibilities;
the documentation reviewed does not identify any of the emitted keywords as
unsupported. The next authorized live response will preserve Nebius validation
details if the request is still rejected.

Offline verification: The exact serialized request now contains only `model`,
`messages`, and `response_format` at the top level; targets the regional
`/v1/chat/completions` URL; and retains the complete strict schema. Mock tests
cover exact serialization, structured-output shape, regional endpoint
enforcement, HTTP 422 detail preservation, and credential redaction. Full suite:
74 passed, 0 failed.
