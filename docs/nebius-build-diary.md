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

## Entry

Date: 2026-09-27
Milestone: M3.1 — Fifth Single Live-Provider Smoke Validation

Result: `LIVE_PROVIDER_FAILED`; M3.1 live quality gate: FAIL.

Request facts:
- endpoint: `https://api.tokenfactory.us-central1.nebius.com/v1/chat/completions`
- configured model: `nvidia/nemotron-3-super-120b-a12b`
- request count: exactly 1; no retry
- end-to-end latency: 39.79 seconds
- repository source digest unchanged: PASS

Sanitized completion metadata:
- HTTP status: 200
- response ID: `chatcmpl-8e7f939327d5c545`
- object type: `chat.completion`
- returned model: `nvidia/nemotron-3-super-120b-a12b`
- choice count: 1
- selected choice index: 0
- finish reason: `length`
- message role: `assistant`
- message field names/types: `annotations:null`, `audio:null`, `content:null`, `function_call:null`, `reasoning:str`, `reasoning_content:str`, `refusal:null`, `role:str`, `tool_calls:null`
- content type: `null`; content length: unavailable
- refusal field present with type `null`; this is not evidence of a refusal
- reasoning and reasoning_content fields present with type `str`; their contents were not logged or used
- tool_calls field present with type `null`; tool-call count unavailable
- prompt tokens: 1,641
- completion tokens: 8,192
- total tokens: 9,833

Failure classification: `LENGTH_TERMINATED_WITHOUT_CONTENT`. The HTTP request
succeeded and the envelope was valid, but generation ended with
`finish_reason=length` at 8,192 completion tokens while `message.content` was
null. This metadata establishes token-length termination; it does not establish
anything about the undisclosed reasoning text.

Strict `RepairProposal` parsing was not reached because there was no text in the
accepted content channel. No proposal, patch, regression test, or policy
artifact was produced for review. No fallback field was used, no patch was
applied, and M4.1/M5 were not started.

## Entry

Date: 2026-09-27
Milestone: M3.1 — Offline Nemotron-3-Super Reasoning Control

Live request made during this work: No.

Attempt #5 facts are unchanged: Nebius returned HTTP 200 after 39.79 seconds;
the response reported 1,641 prompt tokens, 8,192 completion tokens, 9,833 total
tokens, `finish_reason=length`, string-valued `reasoning` and
`reasoning_content` fields, and `content=null`. No reasoning text was logged or
used. The completion reached its 8,192-token completion limit before producing
the final structured response. The response metadata establishes exhaustion of
the completion budget; it does not establish what the hidden reasoning said.

The current official NVIDIA reasoning guide identifies a model-specific
control for `nvidia/nemotron-3-super-120b-a12b`: put `/think` or `/no_think` at
the beginning of the system prompt. It separately documents request-level
thinking-token fields for Nano variants, not for this Super model. Gauntlet
therefore selects `/no_think`, preserving the existing remediation system
instructions after that directive. It does not send `reasoning_effort`,
`max_thinking_tokens`, chat-template kwargs, or undocumented `extra_body`
fields.

Sources reviewed:
- [Nebius Nemotron-3-Super model cookbook](https://github.com/nebius/token-factory-cookbook/blob/main/models/nemotron/nemotron3-super-120B.md)
- [NVIDIA: Enable Reasoning for Nemotron 3 Super](https://docs.nvidia.com/rag/latest/enable-nemotron-thinking.html#enable-reasoning-for-nemotron-3-super)
- [Nebius inference generation parameters](https://docs.tokenfactory.nebius.com/ai-models-inference/overview#generation-parameters)
- [vLLM ChatCompletionRequest parameter reference](https://docs.vllm.ai/en/latest/api/vllm/entrypoints/openai/chat_completion/protocol/)

The next request is now serialized with the first system message beginning
`/no_think` and with `max_tokens=4096`. Nebius documents that its API supports
the full vLLM parameter set, and vLLM documents `max_tokens` as a supported
chat-completion output limit. A 4,096-token ceiling bounds cost and latency while
leaving ample space for this small single-file diff, concise rationale,
regression test, and provenance fields once extended reasoning is disabled.
The strict named `repair_proposal` JSON-schema envelope and complete
`RepairProposal` schema are unchanged.

Offline tests verify exact request serialization, preservation of the existing
system prompt, the 4,096-token output ceiling, byte-for-structure equality of
the complete schema, rejection of undocumented reasoning directives before any
request, and the existing rule that `message.content` is the sole proposal
channel. Sanitized completion metadata remains unchanged and continues to
report reasoning presence/type without recording reasoning text.

Attempt #6 is justified as one controlled live smoke request after the complete
offline suite passes. No attempt #6 was made here, no repair was applied, and
M4.1/M5 were not started.

## Entry

Date: 2026-09-27
Milestone: M3.1 — Sixth and Final Nemotron-3-Super Live-Provider Smoke Validation

Result: `LIVE_PROVIDER_FAILED`; M3.1 live quality gate: FAIL.
Model decision: `EVALUATE_ALTERNATE_MODEL`.

Request facts:
- endpoint: `https://api.tokenfactory.us-central1.nebius.com/v1/chat/completions`
- configured and returned model: `nvidia/nemotron-3-super-120b-a12b`
- request count: exactly 1; no retry
- end-to-end latency: 21.75 seconds
- reasoning directive: `/no_think` at the start of the system prompt
- explicit output limit: `max_tokens=4096`
- repository/victim Python source digest before and after: `6e9e3d56ca352e4f1296354ce42f68b0f5811a8384541aeebb6bc3ce096fdc46`; unchanged

Sanitized completion metadata:
- HTTP status: 200
- response ID: `chatcmpl-9dda10fee30d3849`
- returned model: `nvidia/nemotron-3-super-120b-a12b`
- finish reason: `length`
- prompt tokens: 1,647
- completion tokens: 4,096
- total tokens: 5,743
- content type: `null`; content length: unavailable
- reasoning: present, type `str`; text was not logged or used
- reasoning_content: present, type `str`; text was not logged or used
- refusal field: present, type `null`; this is not evidence of a refusal

The structured-output request was accepted and the completion envelope parsed,
but the model exhausted the explicit 4,096-token completion budget with
`finish_reason=length` and no content in the sole accepted proposal channel.
Based only on observable metadata, `/no_think` did not prevent the attempt #5
failure mode: both runs ended at their completion limit with reasoning fields
populated and `message.content=null`. Attempt #6 used fewer completion tokens
because Gauntlet explicitly lowered the ceiling; it did not produce final
content.

No `RepairProposal` was constructed, so strict proposal validation and all
provenance checks were not reached. Patch quality, patch applicability, and
regression-test quality were not evaluated because no patch or test was
returned. No JSON repair, heuristic extraction, fallback field, retry, or
configuration change was used. No repair was applied, and M4.1/M5 were not
started.

This was the final controlled smoke attempt for the current model
configuration. Because provider transport succeeded but structured final
content failed again, this model does not pass the M3.1 quality gate and should
not proceed to M4.1 under the stated decision rule. A future separately
authorized task may evaluate an alternate model; none was selected or called
here.

## Entry

Date: 2026-09-27
Milestone: M3.2 — Offline Alternate-Model Selection

Live request made during this work: No.

Hackathon requirement: The official Nebius x NVIDIA Global AI Hackathon rules
require a working application that runs on Nebius Token Factory or Nebius AI
Cloud and uses at least one NVIDIA open-source model. NVIDIA is therefore a
project requirement, not an optional bonus. The Coding and Agentic Engineering
track specifically covers developer tools that write, run, and test code.

Current official-source shortlist:

1. `nvidia/Nemotron-3_5-Lightning` (NVIDIA Nemotron 3.5 Lightning). Nebius's
   current Physical AI Token Factory documentation uses this exact ID as its
   default text-generation model and the global Token Factory endpoint. NVIDIA
   describes the 30B-total/3B-active model as a compact execution model with
   strong coding quality and low latency. Its OpenAI-compatible API documents
   `chat_template_kwargs: {"enable_thinking": false}` for concise output and
   explicitly recommends disabling thinking for structured JSON. The current
   Token Factory catalog lists a 1M context window, while NVIDIA's standalone
   NIM guide documents a 262,144-token native context; either is far above this
   workload's approximately 1.5K-token input. NVIDIA documents JSON mode; the stricter Nebius
   `json_schema` envelope remains to be verified by one live smoke.

2. `Qwen/Qwen3.5-397B-A17B` (Alibaba/Qwen). The Nebius cookbook documents the
   exact Token Factory ID, 262K context, hybrid thinking, strong coding and
   instruction-following performance, including HumanEval and LiveCodeBench.
   Token Factory generally supports JSON-schema structured output, but the
   model page does not state a model-specific schema guarantee or exact
   non-thinking request control. It also does not satisfy the hackathon's NVIDIA
   model requirement by itself and is larger than this workload needs.

3. `MiniMaxAI/MiniMax-M3` (MiniMax). The Nebius cookbook documents the exact
   Token Factory ID, 1M context, frontier coding/cowork performance, and a
   `thinking` parameter with `enabled`, `adaptive`, and `disabled` modes. It is
   a much larger multimodal model than this small text repair needs, and it does
   not satisfy the NVIDIA requirement by itself. Model-specific JSON-schema
   support is not stated on its cookbook page.

Selected next model: `nvidia/Nemotron-3_5-Lightning`. It is the only shortlisted
candidate that simultaneously meets the NVIDIA requirement, has documented
coding strength, is optimized for fast specialized agent execution, and has an
explicit documented non-thinking mode for structured JSON. This is a better fit
than Nemotron 3 Super for Gauntlet's bounded repair artifact because it provides
a request-level control that reserves the completion budget for visible JSON.
Selection does not assert that Token Factory's strict schema path has already
worked; that is the purpose of the next single controlled smoke test.

Offline configuration and provider changes:
- select the documented global endpoint `https://api.tokenfactory.nebius.com/v1/`
  and `NEBIUS_MODEL=nvidia/Nemotron-3_5-Lightning`
- retain `max_tokens=4096` and the complete named `repair_proposal` JSON schema
- send `chat_template_kwargs={"enable_thinking": false}` only for Lightning
- retain `/no_think` only for the retired Super model's historical adapter path
- send no model-specific reasoning control for unrecognized or non-Nemotron models

The `RepairProposal` schema, provenance checks, bounded source context, strict
JSON parser, sanitized diagnostics, `message.content` channel, and patch
authorization rules are unchanged. Attempts #1–#6 remain historical evidence
about the prior model/configuration/workload, not failures of Nebius generally.

Official sources:
- https://nebiusglobalaihackathon.devpost.com/rules
- https://github.com/nebius/nebius-physical-ai/blob/main/docs/workbench/token-factory.md
- https://github.com/nebius/token-factory-cookbook/blob/main/models/nemotron/README.md
- https://docs.nvidia.com/nim/large-language-models/2.0.10/get-started/advanced/get-started-nemotron-3.5-lightning.html
- https://github.com/nebius/token-factory-cookbook/blob/main/models/qwen-3.5.md
- https://github.com/nebius/token-factory-cookbook/blob/main/models/minimax-m3.md

One alternate-model live smoke test is justified after offline verification.
No live request, M4.1 work, or M5 work occurred during this investigation.

## Entry

Date: 2026-09-27
Milestone: M3.2 — First Nemotron-3.5-Lightning Live Quality Gate

Result: `LIVE_PROVIDER_FAILED`; M3.2 Lightning quality gate: FAIL.
M3 status: `NOT_READY_FOR_M4_1`.

Request facts:
- endpoint: `https://api.tokenfactory.nebius.com/v1/chat/completions`
- configured model: `nvidia/Nemotron-3_5-Lightning`
- request count: exactly 1; no retry
- end-to-end latency: 5.21 seconds
- reasoning configuration: `chat_template_kwargs={"enable_thinking": false}`
- output limit: `max_tokens=4096`
- structured output: complete named `repair_proposal` JSON schema
- `/no_think` was not sent

Sanitized completion metadata:
- HTTP status: 200
- response ID: `chatcmpl-59bb4ec8`
- returned model: `nvidia/Nemotron-3_5-Lightning`
- finish reason: `stop`
- prompt tokens: 1,645
- completion tokens: 731
- total tokens: 2,376
- content type: `str`; content length: 2,335 characters
- reasoning field: present, type `null`
- reasoning_content field: present, type `null`
- refusal field: present, type `null`; this is not evidence of refusal

The request succeeded and returned final text in `message.content`. Observable
metadata shows that `enable_thinking=false` avoided the prior Super behavior:
generation stopped normally after 731 completion tokens, both reasoning fields
were null, and 2,335 characters of final content were present.

The returned content was valid enough at the JSON level to enter strict
`RepairProposal` model validation, but the proposal was rejected because its
`regression_test` value was not syntactically valid Python. The sanitized
Pydantic diagnostic was:

```text
regression_test
  Value error, regression_test must be valid Python source
  input_value="import asyncio from vict..._': asyncio.run(main())"
```

No malformed-JSON repair, heuristic extraction, reasoning/refusal fallback, or
schema relaxation was attempted. Because strict validation failed, no
`RepairProposal` was constructed. Provenance, patch authorization, security
repair quality, and exact patch applicability were not evaluated. Regression
test quality failed at the Python-syntax requirement. No optional policy
artifact was available for review.

Provider friction: Lightning and Token Factory accepted the strict structured
request and produced concise final content without reasoning-token exhaustion,
but JSON-schema conformance alone did not satisfy Gauntlet's semantic contract
that `regression_test` be executable Python.

Repository/victim Python source digest before and after was
`19f515bfaff87bbab338e29576910e271cd5b1dad77e27a7bd1239f35f56a0f1`;
repository immutability passed. No patch was applied. M4.1 and M5 were not
started.

## Entry

Date: 2026-09-27
Milestone: M3.2 — Offline Lightning Regression-Test Contract Hardening

No live provider request was made. The configured model remains
`nvidia/Nemotron-3_5-Lightning`, with
`chat_template_kwargs={"enable_thinking": false}`, `max_tokens=4096`, and the
unchanged strict named `repair_proposal` JSON schema. The endpoint and
provider-selection behavior were not changed.

Response-path analysis established that Gauntlet decodes the outer HTTP JSON
envelope once, selects `choices[0].message.content` without changing it, and
passes that exact string to `RepairProposal.model_validate_json()`. That call
performs the one required inner JSON decode. An offline transport test proves
that JSON `\\n` escapes in `regression_test` become actual newline characters,
remain in their original positions, and produce source accepted by
`ast.parse()`. Gauntlet does not remove newlines, replace them with spaces, join
lines, normalize indentation, or double-decode the field.

The attempt #1 excerpt was reproduced offline as the invalid source form
`import asyncio from foo import thing`. Python rejected it on line 1 with the
message `Did you mean to use 'from ... import ...' instead?`. This establishes
that the reproduced problem is invalid Python statement construction; it does
not support a newline-loss hypothesis. The complete provider-returned source
from attempt #1 was intentionally not retained, so the exact original parser
offset cannot be recovered retrospectively.

Strict validation still requires `ast.parse(regression_test)` and a pytest-style
test function containing an assertion. Invalid source is not repaired or
normalized and cannot construct a `RepairProposal`. Syntax failures now retain
the parser message, line, offset, total source length, and a bounded escaped
window around the failure. The window escapes control characters, redacts
common credential forms, and the shared strict-model configuration prevents
Pydantic from echoing the full input value in validation messages.

Only the regression-test instructions in the remediation prompt were expanded.
They now require complete executable pytest-compatible Python 3, valid import
statements, preserved newlines and indentation, JSON-escaped newlines, an
`ast.parse()`-valid result, and no Markdown or prose. A small formatting-only
example illustrates multiline Python in a JSON string without P100, the canary,
victim details, or repair logic.

Attempt #1 is characterized as provider/transport success, reasoning-control
success, concise-generation success, and JSON structured-output success. Strict
proposal construction failed solely because the generated regression test was
invalid Python. No patch-quality conclusion is possible because no proposal was
constructed. The complete offline suite passed with 105 tests. `git diff` for
the victim tree remained empty, confirming that victim source was unchanged.
One Lightning live attempt #2 is justified.

## Entry

Date: 2026-09-27
Milestone: M3.2 — Second Nemotron-3.5-Lightning Live Quality Gate

Result: `LIVE_PROVIDER_FAILED`; M3.2 Lightning quality gate: FAIL.
M3 status: `NOT_READY_FOR_M4_1`. Model decision: `REEVALUATE`.

Pre-transport verification passed:
- endpoint: `https://api.tokenfactory.nebius.com/v1/chat/completions`
- configured model: `nvidia/Nemotron-3_5-Lightning`
- reasoning configuration: `chat_template_kwargs={"enable_thinking": false}`
- output limit: `max_tokens=4096`
- response format: `json_schema`
- schema name: `repair_proposal`
- schema: the complete strict `RepairProposal` schema, including required
  `regression_test` and `additionalProperties=false`
- `/no_think` was not sent

Exactly one live inference request was made and no retry occurred. Sanitized
completion metadata:
- HTTP status: 200
- response ID: `chatcmpl-5b29b892`
- returned model: `nvidia/Nemotron-3_5-Lightning`
- finish reason: `stop`
- end-to-end latency: 3.149 seconds
- prompt tokens: 1,772
- completion tokens: 690
- total tokens: 2,462
- content type: `str`; content length: 2,147 characters
- reasoning field: present, type `null`
- reasoning_content field: present, type `null`
- refusal field: present, type `null`; this is not evidence of refusal
- tool_calls field: present, type `null`

The completion supplied usable text through `message.content`, which remained
the only proposal channel. The content passed JSON decoding and reached strict
`RepairProposal` validation. Proposal construction then failed with two
validation errors:

```text
repair_id
  Value error, badly formed hexadecimal UUID string
regression_test
  Value error, regression_test must contain a test function with an assertion
```

The regression source reached the post-`ast.parse()` semantic validator, so
Python syntax validation succeeded. It did not satisfy the existing requirement
for a `test_*` function containing an assertion. No JSON or Python repair,
heuristic extraction, fallback field, or retry was used.

Because strict proposal construction failed, provenance comparison, patch
authorization, security-repair quality, exact patch applicability, semantic
regression-test quality, and the optional policy artifact were not evaluated.
No patch or regression test was applied or executed.

The victim-source digest before and after was
`dd6abf761d1dcff03c19255f5a604fbb2694507f1f903ecb86758d22c161fc26`;
repository immutability passed. Provider transport, reasoning control, concise
generation, and JSON decoding succeeded, but Lightning failed the strict
proposal contract on both its final planned attempts. M3 is not ready for M4.1,
and model/configuration strategy must be reevaluated before any further live
request. M4.1 and M5 were not started.

## Entry

Date: 2026-09-27
Milestone: M3.3 — Trusted Repair Provenance Assembly

Result: offline architecture correction complete; 106 tests passed. No live
Nebius request was made. M3 remains in progress and is not yet ready for M4.1.

Evidence motivating the correction: Lightning attempt #2 reached Nebius with
HTTP 200, `enable_thinking=false`, `finish_reason=stop`, concise structured JSON,
and substantially lower latency than Nemotron 3 Super. Its content nevertheless
included a malformed value for the authoritative `repair_id` field. That field
was state Gauntlet already owned and should never have been delegated to an
untrusted generative model.

Before M3.3, the provider response schema was the complete `RepairProposal` and
asked the model to reproduce the repair UUID, trace/boundary/evidence IDs,
provider/model identity, authorized path and symbol, source hash, and failure
type alongside the creative remediation artifacts. The workflow then compared
the echoed values with local state.

After M3.3, Gauntlet constructs a strict `RepairContext` from the deterministic
trace, bounded `SourceContext`, and configured provider. The provider response
schema is now the strict `GeneratedRepair` schema containing only:

- `rationale`
- `patch`
- `regression_test`
- `optional_policy_artifact`

`additionalProperties=false` prevents generated output from supplying or
overriding authoritative fields. The patch must still be a structurally valid
single-target unified diff. The regression test must still be non-empty, parse
with `ast.parse()`, contain a `test_*` function, and contain an assertion. No
malformed JSON, Python, patch, or missing assertion is repaired, rewritten, or
heuristically extracted.

Only after `GeneratedRepair` validates does Gauntlet generate `repair_id` with
`uuid4()` and assemble the final `RepairProposal` using trusted values for:

- trace ID, boundary ID, and evidence IDs
- provider and model identity
- authorized target path and symbol
- source hash
- failure type

This is not a workaround for accepting invalid AI output. It is a security
architecture correction: authoritative provenance originates from the
deterministic harness, while the model proposes remediation content. Gauntlet
owns identity, provenance, authorization, source integrity, validation,
application, and verification. A generated patch is not trusted merely because
generation succeeded. `RepairProposal` means a validated proposal assembled
with trusted provenance. **Repair proposed != Patch applied != Patch verified.**

The selected generation model remains `nvidia/Nemotron-3_5-Lightning`, with
`chat_template_kwargs={"enable_thinking": false}`, `max_tokens=4096`, and strict
JSON-schema output. Lightning remains selected because it demonstrated
provider success, effective thinking control, normal-stop concise completion,
structured JSON, and lower latency. Nemotron 3 Super remains an evaluated model
whose reasoning/output-budget behavior was unsuitable for this workload.
Artifact quality remains subject to Gauntlet validation.

Offline verification covers the exact content-only schema, absence of every
trusted field from the provider schema, deterministic valid UUID creation,
trusted provenance/target/source/provider assembly, rejection of attempted
metadata overrides, strict diff and Python-test validation, and the unchanged
M1/M2 behavior. Full suite: 106 passed, 0 failed. Victim digest before and after:
`dd6abf761d1dcff03c19255f5a604fbb2694507f1f903ecb86758d22c161fc26`.
The victim tree has no diff. One final controlled Lightning live validation of
the corrected content-only contract is justified. M4.1 and M5 were not started.
