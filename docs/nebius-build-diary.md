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
- Nebius's structured-output page includes a direct Pydantic-schema example, while its complete valid-schema example uses a named `name`/`schema` wrapper. Attempt #2's provider response resolved that ambiguity for this endpoint by explicitly requiring the wrapper.
- Gauntlet's prior request added `temperature: 0`; the cited Nemotron quickstart and structured-output example omit that optional field.
- The generated `RepairProposal` schema is valid JSON Schema and contains `additionalProperties`, `anyOf`, `default`, `minItems`, `minLength`, `pattern`, `properties`, `required`, `title`, and `type` keywords.
- The earlier client discarded the provider's validation response body after `raise_for_status`, so the server's exact 422 detail is unavailable.

Changes made offline:
- Updated the local gitignored `.env` and `.env.example` to the documented regional endpoint, including its trailing slash.
- Enforced the regional host whenever the configured model is Nemotron-3-Super.
- Removed the optional `temperature` parameter so the serialized request matches the documented minimal model request more closely.
- Retained strict JSON-schema output; there is no unstructured fallback and `RepairProposal` validation was not weakened.
- Added bounded provider-error body capture with recursive credential/header redaction and truncation at 4,000 characters.

Root-cause assessment at that time: The endpoint/model mismatch was the
strongest offline hypothesis because the first 422 body was lost. Attempt #2
later disproved that hypothesis and conclusively identified the missing
`json_schema.name` and `json_schema.schema` wrapper fields. No provider response
identified an unsupported schema keyword or model-parameter problem.

Offline verification: The exact serialized request now contains only `model`,
`messages`, and `response_format` at the top level; targets the regional
`/v1/chat/completions` URL; and retains the complete strict schema. Mock tests
cover exact serialization, structured-output shape, regional endpoint
enforcement, HTTP 422 detail preservation, and credential redaction. Full suite:
74 passed, 0 failed.

## Entry

Date: 2026-09-27
Milestone: M3.1 — Second Single Live-Provider Smoke Validation

Endpoint: `https://api.tokenfactory.us-central1.nebius.com/v1/chat/completions`.
Model: `nvidia/nemotron-3-super-120b-a12b`.
Request count: exactly 1; no retry.
End-to-end latency: 3.43 seconds, including local P100 trace/context construction and the provider attempt.

Result: `LIVE_PROVIDER_FAILED`. Nebius returned HTTP 422 and no completion or
`RepairProposal` output.

Sanitized provider validation detail:
- location: `body.response_format.json_schema.name`; error: `Field required`
- location: `body.response_format.json_schema.schema`; error: `Field required`

Observed cause: This endpoint expects `response_format.json_schema` to be a
wrapper containing at least `name` and `schema`. Gauntlet sent the raw Pydantic
schema directly in `json_schema`, so request validation failed before model
generation. This conclusion comes directly from the captured Nebius response
and is not a hypothesis about model behavior or schema keyword support.

Validation results:
- HTTP/API success: FAIL (`422 Unprocessable Entity`)
- strict `RepairProposal` validation: NOT EVALUATED; no proposal returned
- trace, boundary, evidence, target, source-hash, provider, and model provenance: NOT EVALUATED; no proposal returned
- patch applicability: NOT EVALUATED; no patch returned
- regression-test Python syntax: NOT EVALUATED; no test returned
- repository source digest unchanged: PASS

No patch was applied. No repository source was modified. M4.1 and M5 were not
started. Per the smoke-test instruction, no provider changes and no retry were
made after this response.

## Entry

Date: 2026-09-27
Milestone: M3.1 — Offline Structured-Output Envelope Correction

Live request made during this correction: No.

Attempt #2 established conclusively that the regional endpoint accepted the
request far enough to validate its structured-output contract, then rejected
the malformed `json_schema` envelope. Nebius returned two precise validation
errors: `response_format.json_schema.name` was required and
`response_format.json_schema.schema` was required. This proves the 422 was
caused by Gauntlet sending the raw Pydantic schema directly, not by use of the
regional endpoint.

The serializer now emits:

```json
{
  "response_format": {
    "type": "json_schema",
    "json_schema": {
      "name": "repair_proposal",
      "schema": "<complete RepairProposal JSON schema>"
    }
  }
}
```

The complete `RepairProposal.model_json_schema()` remains unchanged inside the
`schema` field. Strict model validation, regional endpoint enforcement,
sanitized error preservation, credential redaction, disabled redirects, and
disabled environment proxies remain enabled. There is no plain-JSON fallback.

Offline tests now compare the full serialized schema wrapper and reproduce the
previous malformed envelope before proving the serializer adds both required
fields. Full suite: 75 passed, 0 failed. A third single live smoke is justified
to validate this exact correction, but no request was made in this task.

## Entry

Date: 2026-09-27
Milestone: M3.1 — Third Single Live-Provider Smoke Validation

Endpoint: `https://api.tokenfactory.us-central1.nebius.com/v1/chat/completions`.
Model: `nvidia/nemotron-3-super-120b-a12b`.
Request count: exactly 1; no retry.
End-to-end latency: 14.38 seconds, including local P100 trace/context construction and the provider attempt.

Result: `LIVE_PROVIDER_FAILED`. The corrected request envelope passed Nebius
request validation and the API returned a model message through a successful
HTTP response. The client does not currently retain the exact successful status
code. Strict `RepairProposal` parsing then failed because the returned message
was not valid JSON: Pydantic found an unescaped control character in a JSON
string at line 1, column 1539.

Validation results:
- HTTP/API transport: PASS (successful response with model content; exact 2xx status not retained)
- strict `RepairProposal` validation: FAIL (`json_invalid` due to an unescaped control character)
- trace, boundary, evidence, target, source-hash, provider, and model provenance: NOT EVALUATED; no `RepairProposal` could be constructed
- generated patch inspection/applicability: NOT EVALUATED; invalid JSON prevented safe artifact extraction
- generated regression-test inspection/syntax: NOT EVALUATED; invalid JSON prevented safe artifact extraction
- repository source digest unchanged: PASS

Provider friction recorded at attempt time: Nebius accepted the named schema
wrapper, but the returned content failed JSON-level validation due to an
unescaped control character. The exact origin remained under investigation
until the response extraction and parsing path could be analyzed offline.

No patch was applied. No repository source was modified. M4.1 and M5 were not
started. Per the smoke-test instruction, no retry was made.

## Entry

Date: 2026-09-27
Milestone: M3.1 — Offline Response-Path and JSON-Control-Character Analysis

Live request made during this investigation: No.

Response-path finding: The Nebius client calls `response.json()` once to decode
the outer OpenAI-compatible response envelope, selects
`choices[0].message.content`, verifies that it is non-empty text, and returns
that exact Python string. The remediation provider performs no concatenation,
unescaping, newline conversion, or serialization. The workflow previously
passed that exact string directly to `RepairProposal.model_validate_json()`.

Offline nested-response tests preserve both correctly escaped inner JSON and an
inner JSON string containing a literal newline byte-for-byte at the semantic
`message.content` level. This establishes that Gauntlet did not transform a
valid escaped inner JSON document into the malformed attempt #3 content. The
literal control character was present in the semantic provider content after
the required outer-envelope decode. The exact attempt #3 code point cannot be
recovered because the raw content was not retained; the prior Pydantic error
reported only the `U+0000`–`U+001F` class and its line/column.

Hardening added:
- A strict `parse_repair_proposal` boundary still uses Pydantic and never repairs malformed output.
- JSON-level failures now report content length, parser line/column, the exact code point when available, and a bounded diagnostic window.
- Diagnostic windows are JSON-escaped so literal controls cannot enter logs, and common credential fields plus bearer tokens are redacted.
- Full provider content is not logged by default.
- The remediation prompt now explicitly requires standards-compliant JSON, no Markdown fences, and JSON escapes for every newline, tab, carriage return, or other control character inside string values.

Schema review: Multiline `patch`, `regression_test`, and optional policy values
remain standards-compliant JSON strings when escaped correctly. A nested object
would still carry a multiline string, while line arrays would change the M4
artifact contract and could still contain improperly encoded controls. The
smallest standards-compliant change is therefore the explicit escaping contract
plus strict diagnostics; no schema field or validation rule was removed.

Offline regression coverage now proves that literal newline/tab controls are
rejected, correctly escaped multiline diff and Python test strings are accepted,
Nebius content extraction is exact, diagnostic windows escape and redact their
content, and malformed output never creates a `RepairProposal`. Full suite: 79
passed, 0 failed.

Attempt #4 is justified to evaluate the clarified prompt and improved
diagnostics, but no live request was made in this task.

## Entry

Date: 2026-09-27
Milestone: M3.1 — Fourth Single Live-Provider Smoke Validation

Endpoint: `https://api.tokenfactory.us-central1.nebius.com/v1/chat/completions`.
Model: `nvidia/nemotron-3-super-120b-a12b`.
Request count: exactly 1; no retry.
End-to-end latency: 41.70 seconds, including local P100 trace/context construction and the provider attempt.

Result: `LIVE_PROVIDER_FAILED`. The API returned a successful HTTP response and
the outer response envelope parsed, but `choices[0].message.content` was empty
or non-text. The client does not retain the exact successful 2xx status. The
application failure was: `Nebius response content was empty or non-text`.

Validation results:
- HTTP/API transport: PASS (successful response envelope; exact 2xx status not retained)
- non-empty model content: FAIL
- strict `RepairProposal` validation: NOT EVALUATED; no text content was available
- provenance fields: NOT EVALUATED; no proposal was constructed
- generated patch quality/applicability: NOT EVALUATED; no patch was returned
- generated regression-test quality/syntax: NOT EVALUATED; no test was returned
- repository source digest unchanged: PASS
- M3.1 live quality gate: FAIL

Provider friction: The accepted request produced an outer completion response
without usable text in `message.content`. The response path did not preserve
refusal or other message metadata, so this run does not establish why content
was absent. No speculative fix is recorded.

No patch was applied. No repository source was modified. M4.1 and M5 were not
started. Per the smoke-test instruction, no retry was made.

## Entry

Date: 2026-09-27
Milestone: M3.1 — Offline Successful-Response Observability

Live request made during this work: No.

Attempt #4 facts remain: HTTP transport succeeded, end-to-end latency was
41.70 seconds, the completion envelope parsed, `message.content` had no usable
text, no `RepairProposal` was constructed, and the repository source digest
remained unchanged. The earlier client did not retain enough successful-response
metadata to determine whether the response represented a refusal, token limit,
reasoning-only output, tool call, or another empty-content condition. None of
those explanations is assigned retroactively.

Previous response handling retained only `choices[0].message.content`. It used
the HTTP status for the error check and then discarded the successful status,
response ID, object type, returned model, choice count/index, finish reason,
message role and field shape, refusal/reasoning/tool-call metadata, and usage
token counts.

The client now retains and logs a sanitized `NebiusCompletionMetadata` snapshot
before validating content. When available it contains exact HTTP status,
response ID, object type, returned model, choice count, selected index, finish
reason, message role, message field names and types, content type/length,
refusal/reasoning/reasoning-content presence and types, tool-call presence/count,
and prompt/completion/total token counts. Generated refusal and reasoning text,
tool arguments, raw responses, authorization headers, and credentials are not
logged. A successful textual completion is still returned unchanged through
`message.content`; no other field is used as a proposal fallback.

Empty-content diagnostics now distinguish `MISSING_CHOICES`, `NON_LIST_CHOICES`,
`EMPTY_CHOICES`, `NON_OBJECT_CHOICE`, `MISSING_MESSAGE`, `NON_OBJECT_MESSAGE`,
`CONTENT_MISSING`, `CONTENT_NULL`, `CONTENT_EMPTY`, `CONTENT_WHITESPACE`,
`CONTENT_NON_STRING`, `REFUSAL_PRESENT`, `LENGTH_TERMINATED_WITHOUT_CONTENT`,
`REASONING_WITHOUT_CONTENT`, `TOOL_CALLS_WITHOUT_CONTENT`, and a final
`UNKNOWN_EMPTY_CONTENT` case.

Offline tests cover normal text, null/empty/missing/non-string content, refusal
metadata, normal-stop and length termination, reasoning/reasoning-content-only
messages, tool-call-only messages, missing/empty choice structures, exact 2xx
status retention, usage counts, and credential exclusion from both errors and
logs. Full suite: 93 passed, 0 failed.

Attempt #5 is justified because the next single response will provide enough
sanitized evidence to classify an absent-content outcome, but no live request
was made in this task.
