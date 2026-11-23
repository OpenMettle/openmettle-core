# 0038 — SGLang and external-provider conformance adapter

Proposed for Wave 18d, V1-08 PR1, 21 November 2026. Refs #9. PR1 recorded the design.
Implementation status: PR2 (`provider_http::inference` bounded gateway inference adapter and
wire conformance fixtures) is merged on `main`; PR3 qualifies each deployed profile.
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
configuration. On an API admission retry, `find_run` returns the `RunReplay` idempotency
record keyed by `(scope_id, actor_user_id, idempotency_key)`. The worker takes
`(scope_id, run_id)` from the `ClaimedRun` in `ActiveRun::claim` and loads `snapshot_format`,
`snapshot_version`, `input_snapshot`, `config_snapshot`, `conversation_id`, `branch_id`,
`input_message_id` and `actor_user_id` from `openmettle.runs` (`id = run_id`).
Use the stored snapshot bytes on every round for the pinned path, attachment revisions,
controls, sources, omissions and target profile. Fail before dispatch if the snapshot
version cannot be decoded or the pinned profile cannot be served.

Under ADR 0036, `openmettle_api` lacks `SELECT` on `openmettle.message_turns.reasoning_blocks`.
The `input_snapshot` references prior reasoning only by immutable ancestor message ID.
When building a replay-eligible upstream request, `openmettle_worker` uses its `SELECT`
privilege to read the blocks for those pinned IDs in the claimed scope and conversation.

`worker::run` calls `recheck_claim`, whose default request has `capabilities: &[]` and
`extra_target: None`. Before **each** model or tool step, the turn executor must call
`recheck_leased` with the current claim's lease, the pinned capabilities and any
`extra_target` for that step. Dispatch only on `RunRecheckOutcome::Continue`.
The adapter returns ordered visible answer parts, separate reasoning blocks, proposed
tool calls and authoritative usage when reported. The worker owns the model/tool loop.
Before dispatching a tool it checks the required approval or permitted YOLO decision
and records the fenced intent.
It publishes the final answer and advances the branch in the fenced settlement transaction.
[ADR 0036](0036-conversation-branches-presets-and-effective-model-config.md) and
[ADR 0035](0035-approvals-permitted-yolo-and-effect-ledger.md).

**Stops and timeouts.** `StepContext::deadline` is a static, pre-renewal snapshot of the
stop point when the runner enters the step (`sent + 2/3 * L` for a full lease of duration
`L` with a later execution deadline). Renewal can move the live lease stop point while a
stream is open. `worker::monitor` tracks that point and the execution stop point. The
runner signals the cause through `cx.stop`, including shutdown from its drain path.
Check `cx.stop` before sending. During setup, reads and downstream backpressure, race
`cx.stop`, the fixed `ActiveRun::execution_deadline` and the applicable adapter timeouts.
Expiry of the `StepContext::deadline` snapshot alone does not interrupt a healthy stream.

On any stop or timeout, immediately drop the HTTP future, body and connection and discard
unfinished calls. The executor returns `StepResult::Stopped` only when `cx.stop` signals
`Stop::Cancel`, `Stop::Deadline`, `Stop::Shutdown` or `Stop::LeaseLost`. If the hard
execution deadline is observed first, close the request and let the runner signal the stop.
If only the adapter's setup, per-chunk idle-read or overall request timeout fires while
`cx.stop` is `None`, return a typed timeout error. The server executor maps it to
`StepResult::Failed(FailReason::StepFailed)`. A caller-owned completion maps it to
`504 timeout` before headers or a timeout in the active stream. Reporting a standalone
adapter timeout as `Stopped` can hit ADR 0033 Rule 11 (`InvalidInput`) and leave a run
unsettled until lease expiry and reclaim.

A stop after dispatch can leave an effect or charge uncertain. Leave reconciliation to
its owner and make no further writes after lease loss. The client-facing run event stream
only observes durable events. Disconnecting or reconnecting that subscriber never stops
or restarts inference. [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md)
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
gateway route. Before DNS, reject an empty token, a token over the gateway header byte
limit, or one containing whitespace or control characters. Construct one `Authorization`
header within that limit and mark it with `HeaderValue::set_sensitive(true)`.
Keep token, document and exporter header admission intact. Caller headers, redirects,
environment proxies and model output cannot select the credential or destination.

Use a dedicated process-wide gateway DNS slot semaphore, separate from OIDC `DNS_SLOTS`.
The blocking lookup holds its permit until it exits, even if the request is dropped.
The setup timeout covers the DNS queue, lookup, TCP connect and TLS. Apply a separate
idle-read timeout while waiting for each body chunk, including the first. The overall
request timeout runs from setup through completion and never resets on progress.
Send once per call. The implementation adds zero crates. Use the locked
`serde_json`, `http` types and `bytes` with the existing transport and Tokio. This
excludes `reqwest` and OpenAI SDK crates. [ADR 0010](0010-provider-http-transport.md).

Parse the response `Content-Type` as a media type with parameters. Accept
`application/json` for JSON and `text/event-stream` for SSE, both with or without
`; charset=utf-8`. Match media types and charset names case-insensitively. Reject a
non-UTF-8 charset as malformed upstream content before decoding.

| Wire case | Required translation |
| --- | --- |
| Request | For Chat Completions, encode ordered `messages` and correlate tool-role results by `tool_call_id`. For Responses, encode `input` items and correlate `function_call_output` by `call_id`. Validate history, schemas and call/result pairing before sending either request. |
| Non-streamed JSON | Decode one bounded `application/json` response and check its finish state. Map Chat Completions message content and tool calls, or Responses output items and function calls, into the same turn result. Preserve item order, reasoning and usage. An error, incomplete response or malformed envelope fails the turn. |
| Server-sent events (SSE) | Require `text/event-stream`. Frame bytes incrementally across HTTP chunks, split UTF-8 characters and split line endings. Join SSE `data:` lines within one event, then decode the complete payload. Handle comments, blank lines, empty deltas and usage-only chunks. Enforce finite limits before growing a line, event, call buffer or assembled turn, and cap total response bytes and call count. |
| Stream completion and failure | For Chat Completions require each returned choice to finish and the terminal `[DONE]`. For Responses require the declared terminal event (for success, `response.completed`). An explicit error, failed/incomplete event, malformed JSON, invalid UTF-8, exceeded bound or premature EOF ends the turn with a typed failure. After streaming begins, signal failure in the active protocol. Never convert a partial stream into a successful answer or dispatch its calls. |
| Parallel calls | Key Chat deltas by choice and tool index, bind each stable call ID and name, and append argument fragments in arrival order for that call. For Responses, bind output items and argument deltas to their item/call IDs. A content delta cannot close a call. In the `qwen3_coder` regression, separator whitespace arrives before the first call's closing brace. Exercise this ordering incrementally. The patched profile must yield two distinct named calls with intact arguments, preserve genuine answer text and emit no separator as answer text. |
| Tool validation | At completion, validate the whole call group against the offered names and schemas. Unsolicited calls and calls with missing or conflicting IDs fail the turn. Reject duplicate keys, incomplete or non-object arguments, and mismatched results. Never repair arguments or dispatch from an invalid group. For invalid arguments, a server run may return a fixed, structured model-visible tool error and continue within its round limit only if it offered tools and every call has a non-conflicting ID. Otherwise fail the turn. |

For Chat Completions, apply these rules to each choice in JSON and SSE. A null or absent
`finish_reason` on an intermediate delta leaves the choice open.

| Terminal `finish_reason` | Outcome |
| --- | --- |
| `stop` | Complete an answer, including a reasoning-only answer. Tool calls on this choice make the response malformed. |
| `tool_calls` | Close a nonempty call group and apply whole-group validation. An empty group is malformed. |
| `length` | Fail the turn as incomplete. Discard partial calls. |
| `content_filter` | Fail the turn as filtered. Discard partial calls. |
| Unknown, or missing at completion | Fail the turn as malformed, including `[DONE]` with an unfinished choice. |

In PR2, use a custom `serde::de::Visitor` that rejects repeated keys in each JSON object,
including nested objects, while decoding envelopes and complete tool arguments.
Decoding directly to `serde_json::Value` loses duplicate keys before validation.

For server runs, enforce ADR 0036's storage ceilings while assembling output. Allow at
most 64 KiB of visible UTF-8 text across the entire message and contiguous part ordinals
in `0..=127` starting at zero. Allow at most 128 reasoning blocks. For present reasoning,
the stored JSONB must satisfy `octet_length(reasoning_blocks::text) BETWEEN 1 AND 65536`.
Count PostgreSQL's text representation, including its formatting. Store absent reasoning
as SQL NULL. Exceeding any bound fails the turn before publication.

**Reasoning and usage.** Apply controls in model → preset → project → request order.
If a request, project or preset explicitly selects the advertised default effort, resolve
it to the declared level, retain the selecting layer and send the level.
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
| Unexpected upstream `4xx`, including `400`, `404` or `422` from profile or schema drift | `502 provider_failure` with fixed text. Discard the upstream body. |
| Bad gateway or unavailable service | `502 provider_failure` for an upstream bad gateway, `503 unavailable` for service unavailability, `504 timeout` for a caller-facing timeout. |
| Incomplete or filtered output | Preserve the typed cause internally and map it to `502 provider_failure` with fixed text. |
| Successful HTTP status with invalid media, framing or payload | Distinct malformed-upstream outcome mapped to `502 provider_failure`. Keep parser diagnostics and upstream bodies private. |

Use fixed error text and the typed log, span and metric allowlists. Prompts, completions,
reasoning, tool arguments and bearer keys must never enter errors, logs, traces, metrics,
audit details or run-event projections. Include upstream error text and header values in
this rule even when a provider echoes the request. [ADR 0024](0024-process-telemetry-and-redaction.md)
and [ADR 0028](0028-telemetry-contract-and-metrics.md).

If PR2 instruments gateway inference metrics, update `contracts/telemetry/v1.json`,
`src/telemetry/metrics.rs` and the Prometheus alert checks together under ADR 0028.
Keep rule selectors and their firing and non-firing fixtures consistent with the
contract and run `promtool check rules` and `promtool test rules`. Metric labels must
use closed, low-cardinality enums. Never label by model, profile, run ID or user ID.

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
| API-03 · wire | Fragment UTF-8, SSE lines and arguments. Exercise terminal events and finish reasons, errors after a delta, malformed or truncated JSON, nested duplicate keys, premature disconnect and invalid arguments. Cover upstream statuses (including unexpected 4xx), charsets and transport and storage limits. Assert the typed outcome and zero dispatches from a failed turn. |
| API-03 · timing | Continue a stream past the original step deadline after lease renewal. Stall after one event and signal each worker stop in turn. Separately reach the execution deadline, and expire each adapter timeout with `cx.stop` still `None`. Check the stop or timeout result, prompt peer closure for open sockets, bounded return, zero retries and zero tool dispatches. |
| API-04 | Compare explicit default effort with omission in the captured request. Verify effective control sources, rejected schemas/controls, inherited and unknown context limits, measured and absent usage. |
| API-05 | Require authenticated inference to return the expected result on each claimed route. Require that same route to deny absent/wrong credentials. A mock that always returns 403 must fail qualification. Put distinct synthetic canaries in the bearer, prompt, completion, reasoning, tool arguments and echoed errors. On success and failure, inspect error surfaces, captured stderr and decoded trace/metric exports. Require evidence that the sinks were exercised and zero canary matches. |

PR2's passing adapter suite unblocks V1-07 PR4's live turn executor in `src/worker.rs`.

**Recorded fixtures.** `tests/fixtures/sglang-recorded/` holds responses recorded on
23 Nov 2026 from one real SGLang deployment (patched fork, commit unverified).
`tests/provider_inference/recorded_sglang.rs` replays them through `Gateway::caller`, with
each stream re-chunked per event and per byte. They cover plain, streamed, reasoning and
parallel tool-call Chat turns. `known_gap_*` tests pin the length cut-off, an aborted stream,
unread reasoning tokens, the unchecked response model, Responses HTTP 500 and the tool-call
separator. They are evidence from one deployment, not qualification. They contain no
successful Responses output and do not replace PR3's live harness. See the fixture README.

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
