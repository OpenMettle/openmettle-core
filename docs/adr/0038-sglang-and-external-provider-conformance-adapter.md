# 0038 — SGLang and external-provider conformance adapter

Proposed for Wave 18d, V1-08 PR1, 21 November 2026. Refs #9. PR1 records the design.
PR2 supplies the Rust adapter and wire fixtures. PR3 qualifies each deployed profile.
[V1-08 acceptance and dependencies](https://github.com/OpenMettle/openmettle-core/issues/9).

## Decision and sources

The API and worker share one Rust adapter for model inference through the selected
gateway (initially LiteLLM and the existing boundary). Only the gateway routes to the
owned SGLang build or a configured external endpoint. It holds backend keys and enforces
model access, rates and budgets. V1-06 supplies the per-user gateway credential for a
completion or a worker credential bound to the admitted actor and scope. Resolve it at
dispatch. Keep it out of run snapshots and client responses. [Architecture](../../ARCHITECTURE-v1.md#architecture-baseline),
[gateway boundary](../../SOURCE-REFERENCES.md#s01) and [V1-06](https://github.com/OpenMettle/openmettle-core/issues/7).

| Pinned reference | Behaviour to qualify |
| --- | --- |
| `serving-fork` `8a53e9c2bf28` | Owned SGLang profile carrying the `qwen3_coder` fix for separator whitespace in streamed parallel calls. [Serving reference](../../SOURCE-REFERENCES.md#s27) and [SGLang PR 37408](https://github.com/sgl-project/sglang/pull/37408). |
| OpenMettle Open WebUI main `e02e69af9717` | Caller tool ownership and provider-specific declarations for reasoning replay. [Pinned contract notes](https://github.com/OpenMettle/open-webui/blob/e02e69af9717cc8443f22fa2a0c89570a74abc9b/backend/docs/api-reasoning-tools.md). |
| `workstation` `e42bed1d97fe` | Explicit reasoning controls, context reporting and account errors on the workstation branch. [Architecture source baseline](../../ARCHITECTURE-v1.md#what-the-fork-actually-contains). |
| `workstation-stack` `f9c8844b94fa` | Selected gateway, deployment configuration and stack lock. [Stack reference](../../SOURCE-REFERENCES.md#s15). |

Use these pins for behaviour and independent fixtures. A server-controlled profile binds
an opaque model ID to the checkpoint, template, tool and reasoning parsers, runtime,
gateway and profile revisions. It declares the supported routes, streaming modes, tool
and parallel-call support, schema subset, image inputs, reasoning controls and replay,
context/output limits, usage fields and cancellation semantics. Unknown support stays
unknown. Validate each explicit request against that declaration before dispatch, including
schema constraints and control combinations. An unsupported operation gives a typed
capability error (`400 validation` at the application boundary). Never infer support from
a model name, simplify a schema or silently switch protocols.

## Who owns a turn

**Server-owned run.** An explicit admission pins the branch, input and effective
configuration. The worker consumes the versioned input and configuration snapshots from
ADR 0036's proposed `RunReplay`, including attachment revisions, omissions, selected
controls, sources and target profile. Use those bytes on every round. If the version
cannot be decoded or the pinned profile cannot be served, stop before dispatch. The
worker rechecks current authority for each model or tool step. The adapter returns ordered
visible answer parts, separate reasoning blocks, proposed tool calls and authoritative
usage when reported. The worker owns the model/tool loop. Before dispatching a tool it
checks the required approval or permitted YOLO decision and records the fenced intent.
It publishes the final answer and advances the branch in the fenced settlement transaction.
[ADR 0036](0036-conversation-branches-presets-and-effective-model-config.md) and
[ADR 0035](0035-approvals-permitted-yolo-and-effect-ledger.md).

The ADR 0033 runner (`worker::run`) calls `worker::Executor::step` with a `StepContext`. Check its
stop signal before sending. Race setup, reads and downstream backpressure against that
signal and the earlier of the context deadline and adapter timeout. On `Stop::Cancel`,
`Stop::Deadline`, `Stop::Shutdown` or `Stop::LeaseLost`, immediately drop the HTTP
future, body and connection, discard unfinished calls, and return `StepResult::Stopped`.
Apply the same stop behaviour when the step's deadline expires during a read.
A stalled peer cannot hold the step open until another byte or `[DONE]` arrives. A stop
after dispatch can leave an effect or charge uncertain. Leave reconciliation to its owner
and make no further writes after lease loss. The client-facing run event stream only
observes durable events. Disconnecting or reconnecting that subscriber never stops or
restarts inference. [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md)
and [ADR 0034](0034-ordered-events-and-replayable-sse.md).

**Caller-owned completion.** The V1-09 ACP facade in `openmettle-api` authenticates the
caller and uses the same adapter and gateway. Capture tool ownership at the entry point,
before applying any preset. A nonempty `tools` array declares the caller's tools. The
caller executes validated calls after terminal success and supplies the follow-up results.
Preserve `tools: []` on the wire as an explicit opt-out. Omitted `tools` stays absent. Neither
case offers any tools, and an unsolicited call fails the turn. A preset, tool ID, provider
delta or retry cannot start a server loop. Delegation requires a separate admitted run.
Dropping a caller-owned completion closes its own upstream request.

## Wire contract

Reuse the address checks, TLS, HTTP/1.1 framing, header limits, deadlines and
caller-driven connection in `src/provider_http.rs` and `provider_http::transport`.
Today `Route::send` collects the bounded response and admits only `Accept` and
`Content-Type` as caller headers. PR2 adds an inference-specific path that consumes body
chunks as they arrive and attaches one internally supplied bearer to the exact configured
gateway route. Keep token, document and exporter header admission intact. Caller headers,
redirects, environment proxies and model output cannot select the credential or
destination. Send once per call. The implementation adds zero crates. Use the locked
`serde_json`, `http` types and `bytes` with the existing transport and Tokio. This
excludes `reqwest` and OpenAI SDK crates. [ADR 0010](0010-provider-http-transport.md).

| Wire case | Required translation |
| --- | --- |
| Request | For Chat Completions, encode ordered `messages` and correlate tool-role results by `tool_call_id`. For Responses, encode `input` items and correlate `function_call_output` by `call_id`. Validate history, schemas and call/result pairing before sending either request. |
| Non-streamed JSON | Decode one bounded `application/json` response and check its finish state. Map Chat Completions message content and tool calls, or Responses output items and function calls, into the same turn result. Preserve item order, reasoning and usage. An error, incomplete response or malformed envelope fails the turn. |
| Server-sent events (SSE) | Require `text/event-stream`. Frame bytes incrementally across HTTP chunks, split UTF-8 characters and split line endings. Join SSE `data:` lines within one event, then decode the complete payload. Handle comments, blank lines, empty deltas and usage-only chunks. Enforce finite limits before growing a line, event, call buffer or assembled turn, and cap total response bytes and call count. |
| Stream completion and failure | For Chat Completions require each returned choice to finish and the terminal `[DONE]`. For Responses require the declared terminal event (for success, `response.completed`). An explicit error, failed/incomplete event, malformed JSON, invalid UTF-8, exceeded bound or premature EOF ends the turn with a typed failure. After streaming begins, signal failure in the active protocol. Never convert a partial stream into a successful answer or dispatch its calls. |
| Parallel calls | Key Chat deltas by choice and tool index, bind each stable call ID and name, and append argument fragments in arrival order for that call. For Responses, bind output items and argument deltas to their item/call IDs. A content delta cannot close a call. In the `qwen3_coder` regression, separator whitespace arrives before the first call's closing brace. Exercise this ordering incrementally. The patched profile must yield two distinct named calls with intact arguments, preserve genuine answer text and emit no separator as answer text. |
| Tool validation | At completion, validate the whole call group against the offered names and schemas. Reject conflicting identities, duplicate fields, incomplete/non-object JSON or mismatched results. Dispatch nothing from an invalid group. A server run may return a fixed, structured model-visible tool error and continue within its round limit. Otherwise end the turn with a bounded failure. Never execute repaired or partial arguments. |

**Reasoning and usage.** If a client or preset explicitly selects the advertised default
effort, resolve it to the declared level, retain the selecting layer and send the level.
If all layers omit effort, omit the wire field and report a null value with
`source=gateway_default`. The gateway's actual choice remains unknown.

Keep structured reasoning in bounded blocks with their source format and producing
profile revision. Replay only when the target's qualified `replay_format` covers the
source format, template and parser revisions. A missing, unknown or mismatched declaration
omits prior reasoning even on a same-model retry. Open WebUI main's declaration for
`reasoning_content` on llama.cpp does not qualify SGLang. A reasoning-only result can
have zero visible parts. When omitting its reasoning on replay, omit an otherwise empty
assistant message and preserve any valid tool-call/result pair. Never insert reasoning
into visible text or invent a placeholder answer. [ADR 0036](0036-conversation-branches-presets-and-effective-model-config.md#catalog-presets-and-context-budget).

Return the gateway-reported, validated input/output counts for the final model call with their
source. Missing counts stay unknown. Keep prompt estimates separate. The gateway owns
accounting across calls, including duplicate or delayed usage reports reconciled by V1-06.

## Errors and redaction

Classify failures at the point that can establish their cause. Map them to the existing
application problem codes before a response starts. [ADR 0007](0007-application-api-contract.md#errors).

| Evidence | Outcome |
| --- | --- |
| V1-06 confirms the authorized user's gateway entitlement is missing | `503 provisioning` with a fixed account-provisioning message. |
| Gateway confirms a broken operator/service credential | Operator credential failure, `502 provider_failure` with fixed public text. An unexplained upstream 401/403 is a provider failure of unknown cause. It cannot establish missing entitlement. |
| Upstream rate limit | `429 rate_limited`. Accept a single integer `Retry-After` in the ADR 0007 wire range (0–86400 seconds). Omit invalid, duplicate or out-of-range values. The delay is advisory. |
| Bad gateway or unavailable service | `502 provider_failure` for an upstream bad gateway, `503 unavailable` for service unavailability, `504 timeout` for a caller-facing timeout. |
| Successful HTTP status with invalid media, framing or payload | Distinct malformed-upstream outcome mapped to `502 provider_failure`. Keep parser diagnostics and upstream bodies private. |

Use fixed error text and the typed log, span and metric allowlists. Prompts, completions,
reasoning, tool arguments and bearer keys must never enter errors, logs, traces, metrics,
audit details or run-event projections. Include upstream error text and header values in
this rule even when a provider echoes the request. [ADR 0024](0024-process-telemetry-and-redaction.md)
and [ADR 0028](0028-telemetry-contract-and-metrics.md).

## Delivery and qualification

**PR1** delivers this record and the forward pointer in ADR 0010. Issue #9 stays open.

**PR2** delivers the pure Rust adapter and a local mock HTTP server over test TLS. Reuse
the PLAN-03 and API-01 through API-05 cases with synthetic inputs. Run each applicable
case through both Chat Completions and Responses, streamed and non-streamed. For an
undeclared operation, assert the refusal and zero upstream requests.

| Fixture family | Required observation |
| --- | --- |
| PLAN-03 / API-01 | Compare the same schema and history on the wire and at the caller. Exercise omitted, empty and explicit tools, unsolicited calls, two tool rounds and interleaved parallel calls including the separator regression. Assert exact calls and zero server dispatches for every caller-owned case. |
| API-02 | Exercise later-turn replay with matching and mismatched formats, an unqualified SGLang profile, malformed history and reasoning-only output. Inspect the next request and visible parts independently. |
| API-03 | Fragment UTF-8, SSE lines and arguments. Exercise terminal events, error-after-delta, malformed/truncated JSON, premature disconnect, invalid arguments, upstream statuses and limit boundaries. Stall after one event, signal each worker stop and expire the deadline. Observe prompt peer socket closure, bounded return, zero retries and zero tool dispatches. |
| API-04 | Compare explicit default effort with omission in the captured request. Verify effective control sources, rejected schemas/controls, inherited and unknown context limits, measured and absent usage. |
| API-05 | Require authenticated inference to return the expected result on each claimed route. Require that same route to deny absent/wrong credentials. A mock that always returns 403 must fail qualification. Put distinct synthetic canaries in the bearer, prompt, completion, reasoning, tool arguments and echoed errors. On success and failure, inspect error surfaces, captured stderr and decoded trace/metric exports. Require evidence that the sinks were exercised and zero canary matches. |

PR2's passing adapter suite unblocks V1-07 PR4's live turn executor in `src/worker.rs`.

**PR3** delivers the owner-gated live harness. Run the applicable matrix against both
the pinned SGLang profile and a documented compatible external endpoint through the
selected gateway. For each, record the deployed revision tuple, fixture revision,
authenticated route and mode, expected and observed outcomes, refusals, failures and
redaction results. Verify tool rounds, reasoning replay, cancellation and reported usage
on the exact route that claims them. Use safe profile aliases in shared evidence.
A model listing or catch-all 403 cannot qualify inference.
Compare a base model with a preset that omits its context window. Verify the effective
window, source, output reserve and usable input against the documented base limits, and
record unknown capacity when evidence is absent. Only the tested profile, route and
operations gain qualification. [Architecture qualification baseline](../../ARCHITECTURE-v1.md#backends-and-the-curated-stack).
