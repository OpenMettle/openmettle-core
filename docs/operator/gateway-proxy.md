# Gateway proxy (not deployable)

> **Not deployable**, for two reasons:
>
> - **The dispatch secret would travel in cleartext.** The worker's transport requires an
>   `https://` endpoint and the proxy listens on plain HTTP, so the two cannot be connected
>   until increment 7.
> - **A hold without a final report stays forever.** A handed-off request keeps its hold until
>   a final usage report arrives, and nothing reconciles one that never does until increment 3.
>
> Run it only on an isolated test host with synthetic data. There is no image target, chart
> or network policy for it yet.

`openmettle-gateway` is OpenMettle's own inference proxy (V1-06,
[ADR 0044](../adr/0044-own-inference-proxy-and-binding-free-dispatch.md)). It sits between a
caller and one SGLang server. It authenticates the caller by the dispatch secret of one
handed-off gateway request, allows that request one dispatch, checks the model, and turns the
usage the server reports into a usage report for the request's hold, through the settlement
path of [ADR 0037](../adr/0037-gateway-provisioning-and-usage-reconciliation.md). Caller
authentication, single dispatch and the model check are delivered. No gateway binding, key or
policy is provisioned for it.

## What it does

- **One route.** `POST /v1/chat/completions` is forwarded to the same path on the upstream.
  Every other path answers 404, as do `/v1/responses` (the recorded server answers it with
  500) and `/v1/models`. `/healthz` and `/readyz` behave as in the API and the worker.
- **Correlation.** The caller sends exactly one `x-request-id` holding the canonical lowercase
  UUID of a gateway request; an ID the caller names in `Connection` counts as absent. A
  missing or malformed ID is refused with `400 validation`. So is a request with a
  `Connection` value that is not visible ASCII, before the ID or the credential is looked at:
  such a value could hide a nomination. Refusals use the application API's problem document
  (`application/problem+json`).
- **Authentication.** The caller sends exactly one `Authorization: Bearer` header holding the
  request's 32-byte dispatch secret as 43 unpadded base64url characters. Only the worker that
  reserved the round holds that secret. A missing, repeated or malformed header, one named in
  `Connection`, a wrong secret, an unknown request and a request not handed off are all
  refused alike with `401 unauthenticated` and `WWW-Authenticate: Bearer`. So is a request
  that was not dispatched yet and whose run is cancelled, finished, or past its lease or its
  execution deadline. Nothing is sent upstream, and the answer does not reveal whether the
  request exists.
- **Single dispatch.** The database records the request's one dispatch before the body is
  read. A second dispatch with the right secret is refused with `409 conflict`, also after
  the run was cancelled or has finished. Of two concurrent dispatches exactly one is
  forwarded.
- **The secret stays in the proxy.** The proxy sends PostgreSQL the SHA-256 of the secret,
  which is what the request row stores, and never the secret. A server that logs statement
  parameters therefore records nothing a caller could present, and no logging setting is
  required for the gateway's login.
- **Routing fields.** The installation, scope, report source, principal and model of the
  report come from the stored request; nothing else is taken from the caller. The report
  source is the request's installation, and the principal is the user the request acts for.
- **Model.** The stored model must be the one in `MODEL`, or the request is refused with
  `403 policy`. The body must be one JSON object whose top-level `model` is that model,
  without a repeated `model` key, or it is refused with `400 validation`. SGLang answers any
  model name from its loaded model, so nothing else checks it.
- **Forwarding.** The request body (at most 2 MiB, read within 10 s) is sent upstream byte
  for byte on a new connection, with only `Content-Type`, `Accept`, `Accept-Encoding:
  identity` and the request ID. `Authorization`, cookies, other caller headers and any field
  the caller names in `Connection` are not forwarded.
- **HTTP/1.1 only.** Any other version is refused with `505 http_version_not_supported`
  before anything else: an HTTP/1.0 caller could not tell a cut stream from a complete one.
- **Identity bodies only.** A request with a `Content-Encoding` other than `identity`, or a
  `Transfer-Encoding` other than one `chunked`, is refused with `415 unsupported_media_type`
  before anything is sent upstream. An upstream answer with either is not relayed: the caller
  gets `502 provider_failure` and the upstream connection is closed without reading the
  body.
- **Relay.** The upstream status, `Content-Type` (unless the upstream names it in
  `Connection`) and body are relayed chunk by chunk as they arrive. A server-sent event
  reaches the caller before the upstream has finished. The caller's response ends cleanly only
  if the upstream body completed and the caller received every chunk. Otherwise the caller
  receives a prefix of the upstream bytes and an unclean end of the HTTP body (no terminal
  chunk, or fewer bytes than `Content-Length`); how much of that prefix arrives is not
  promised.
- **Usage.** A copy of each chunk is read for the usage object. When the upstream answered
  200, the body completed (a JSON document, or a stream ending with `data: [DONE]`) and a
  valid usage object arrived, one final report is written. In a stream, only a usage object
  in the last data event before `[DONE]` counts; an earlier one may be interim. This holds
  whatever the `finish_reason`, including `length`: the proxy records what the upstream
  reports it consumed.
- **Caller leaving.** A caller that disconnects, or takes no relayed chunk for an idle
  timeout, gets nothing more. If the usage is not in hand yet, the upstream connection is
  closed so the server stops generating. If it may be (a stream whose last event carried
  usage, or a JSON body within its parse bound), the relay reads on to finish the accounting,
  rechecking after every read, and stops once one idle timeout has passed since the caller
  left. A body that ends at that moment still counts.

## What it records

| Report field | Value |
| --- | --- |
| `request`, `installation`, `principal`, `scope`, `source` | The stored handed-off request: `source` is its installation and `principal` the user it acts for |
| `report_id`, `revision`, `final` | The request ID, `0` and `true` |
| `prompt_tokens`, `completion_tokens` | The upstream's counts; both are required |
| `reasoning_tokens` | Top-level `reasoning_tokens` or `completion_tokens_details.reasoning_tokens`, which must agree when both are present and cannot exceed `completion_tokens` |
| `reasoning_included` | `true` whenever reasoning tokens are recorded, because SGLang counts them inside `completion_tokens` (recorded 23 Nov 2026). Settlement then measures `prompt + max(completion, reasoning)` |
| `cost`, `unit` | Not recorded |

A valid usage object is a JSON object inside a JSON object, with non-negative integer counts
that fit a `bigint`, no duplicate keys, and a `completion_tokens_details` that is `null` or an
object.

The report is written by the task that relays the response, so the write does not depend on
the caller staying connected. Each attempt is bounded by five `DB_TIMEOUT_MS` (10 s by
default), also when its database connection stops answering, and a transient failure or an
expired attempt is retried twice (after 100 ms and 500 ms). An attempt is never cancelled in
flight: one past its bound is left to finish or fail on its own while the retry runs, which is
safe because settlement accepts the identical report once. There is no local spool. If no
attempt confirms the write, the proxy logs `gateway.usage.failed`: the gateway could not confirm
the write, and an earlier attempt may still have committed it. Check the request's usage report
and hold before acting. If no report exists, the hold stays in place: nothing releases or
reconciles it until increment 3.

The report identity is derived from the request, so a retried write stores the same report.

### When nothing is recorded

A request is dispatched once. Every case below except `dispatch_unconfirmed` has spent the
request: it cannot be sent again. `dispatch_unconfirmed` may or may not have. Nothing is
written, the hold stays in place until increment 3 reconciles it, and one
`gateway.usage.unrecorded` event (warn) names the gateway request and the reason
(`error.type`):

| Reason | Cause |
| --- | --- |
| `dispatch_unconfirmed` | The database exchange that records the dispatch failed, did not answer within five `DB_TIMEOUT_MS`, or lost its caller first (`503 unavailable`). Nothing was forwarded. The dispatch may or may not have been consumed: if it was, the request stays handed off with its hold until increment 3, and a retry answers `409 conflict` |
| `model_not_served` | The request was reserved for a model other than `MODEL` (`403 policy`); nothing was forwarded |
| `model_mismatch` | The body was not a JSON object naming the reserved model exactly once (`400 validation`); nothing was forwarded |
| `request_body` | The request body exceeded 2 MiB, did not arrive within 10 s, or the caller left while sending it (`400 validation`); nothing was forwarded |
| `upstream_status` | The upstream answered with a status other than 200; its response is still relayed |
| `upstream_transport` | The upstream could not be reached or failed before a response head (caller gets `502 provider_failure`) |
| `upstream_encoding` | The upstream answered with a content coding other than `identity` or a transfer coding other than `chunked` (caller gets `502 provider_failure`) |
| `upstream_timeout` | Connect, response-head or idle-read timeout (`504 timeout` if no head arrived), or the upstream did not finish within one idle timeout after the caller left |
| `incomplete` | The body broke off, or a stream ended without `[DONE]` |
| `caller_disconnected` | The caller left or stopped reading before the usage was in hand, or the usage went out of reach while the relay read on; the upstream connection is closed |
| `no_usage` | The response completed without a usage object, for example a stream requested without `stream_options.include_usage`, or a stream whose last data event before `[DONE]` carried none |
| `unparsable` | A parse bound was exceeded, or the usage was not a valid usage object |

Increment 3 replaces these gaps with explicit incomplete reports.

## Configuration

The gateway reads the same process settings as the API and the worker under the
`OPENMETTLE_GATEWAY_` prefix: `BIND` (default `127.0.0.1:8082`), `DATABASE_URL`,
`DB_MAX_CONNECTIONS`, `DB_TIMEOUT_MS`, `SHUTDOWN_TIMEOUT_MS`, `LOG_FORMAT`, `LOG_LEVEL` and the
`OTLP_*` export settings, with the ranges in the README. `DATABASE_URL` must be a login of
`openmettle_gateway`; the proxy needs only that role's existing grants. It never reads
`ARTIFACTS_DIR` or `AUTH_CONFIG`, and it refuses to start while
`OPENMETTLE_API_ISSUANCE_DATABASE_URL` is present.

| Setting (`OPENMETTLE_GATEWAY_` prefix) | Range | Default |
| --- | --- | --- |
| `UPSTREAM_URL` | `http://host[:port]` with at most a `/` path | Required |
| `MODEL` | The catalog model ID the upstream serves, 1–128 bytes | Required |
| `UPSTREAM_CONNECT_TIMEOUT_MS` | 1–30,000 ms | 5,000 |
| `UPSTREAM_IDLE_TIMEOUT_MS` | 1–3,600,000 ms | 120,000 |

`UPSTREAM_URL` names one origin. User information, another path, a query and a fragment are
refused, and a bracketed host must be an IPv6 address followed by nothing or a port. The idle
timeout bounds the wait for the response head (SGLang sends a non-streamed head only after
generating the whole answer), each later body read, a caller that does not accept a relayed
chunk (it is then treated as gone), and how long the relay reads on once the caller has gone.

`MODEL` must equal the model ID that run admission stores, which is the catalog's. One
gateway process serves one model.

A refusal exits 78 with one fixed line, for example `configuration error: UPSTREAM_URL is
required`, `configuration error: UPSTREAM_URL must use http://`, `configuration error:
invalid UPSTREAM_URL`, `configuration error: MODEL is required` or `configuration error:
invalid MODEL`. The line never contains the value.

## Bounds

| Bound | When exceeded |
| --- | --- |
| Request body, 2 MiB (the worker's largest inference request) | `400 validation`; nothing is forwarded |
| Non-streamed response read for usage, 2 MiB | The body is still relayed in full; nothing is recorded (`unparsable`) |
| One SSE line 128 KiB, one event 256 KiB (the worker decoder's framing) | The stream is still relayed in full; nothing is recorded (`unparsable`) |

## Shutdown

`SIGTERM` or `SIGINT` stops accepting connections. Responses in flight keep streaming, and
reports whose usage was read are written before the database pool closes, all within
`SHUTDOWN_TIMEOUT_MS`. A response still streaming at the deadline is cut and records nothing,
and the process exits 1. So does a database exchange still running on a connection that
stopped answering: the pool waits for every connection when closing.

## Known gaps

- **Plain HTTP on both sides.** The packaged worker's transport requires an `https://`
  endpoint, so it cannot use this proxy yet, and without TLS the dispatch secret would cross
  the network in cleartext. The default bind is loopback.
- **Holds without a final report stay.** A request that was handed off and never dispatched,
  refused after its dispatch was recorded, cancelled, cut or failed keeps its hold. Nothing
  releases or reconciles it until increment 3.
- **A broad database role.** `openmettle_gateway` still has the grants the superseded
  reconciler needed. Increment 6 narrows it to what the proxy uses.
- **No family policy.** Quiet and study hours are enforced nowhere until increment 4.
- **Chat completions only.** The Responses API is not routed.
- **No concurrency limit** on relayed requests.
- **Identity bodies only.** Compressed requests and answers are refused rather than relayed.

## Testing

`tests/schema/gateway_proxy.rs` runs the binary as `openmettle_gateway` against a stand-in that
replays the recorded SGLang responses in `tests/fixtures/sglang-recorded/`. Its requests are
run rounds reserved and handed off through the library, without a gateway binding. It needs
an isolated PostgreSQL 18 service in `TEST_DATABASE_URL`, like the other schema tests:

```sh
cargo test --locked --test schema gateway_proxy -- --ignored
```

With `TEST_GATEWAY_UPSTREAM_URL` set to an `http://` SGLang origin, the
`live_upstream_usage_matches_what_the_caller_received` case sends the recorded requests to that
server instead and checks each report against the usage the caller received.
