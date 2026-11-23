# Gateway proxy (increment 1, not deployable)

> **Not deployable.** `openmettle-gateway` has no caller authentication, no TLS and no model
> enforcement in this increment. Run it only on an isolated test host with synthetic data.
> There is no image target, chart or network policy for it yet.

`openmettle-gateway` is the first increment of OpenMettle's own inference proxy (V1-06). It
sits between a caller and one SGLang server and turns the usage the server reports into a
usage report for the request's gateway hold, through the same settlement path as
[ADR 0037](../adr/0037-gateway-provisioning-and-usage-reconciliation.md).

## What it does

- **One route.** `POST /v1/chat/completions` is forwarded to the same path on the upstream.
  Every other path answers 404, as do `/v1/responses` (the recorded server answers it with
  500) and `/v1/models`. `/healthz` and `/readyz` behave as in the API and the worker.
- **Correlation.** The caller sends exactly one `x-request-id` holding the canonical lowercase
  UUID of a gateway request in state `handed_off`; an ID the caller names in `Connection`
  counts as absent. Its installation, scope, report source
  and binding principal are read from the database; nothing else is taken from the caller. A
  missing or malformed ID is refused with `400 validation`, and an unknown request or one not
  handed off with `404 not_found`, before anything is sent upstream. Refusals use the
  application API's problem document (`application/problem+json`).
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
| `request`, `installation`, `principal`, `scope`, `source` | The stored handed-off request and its binding |
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
and hold before acting; if no report exists, the hold stays for reconciliation.

The report identity is derived from the request, so a retry writes the same report. A second
dispatch of the same request is still forwarded in this increment; if the upstream reports the
same usage, settlement accepts the identical report once, and if it reports different usage
the second write is refused as a conflict (`gateway.usage.failed`, `conflict`). Increment 2
refuses a second dispatch.

### When nothing is recorded

Nothing is written, the hold stays as it was and one `gateway.usage.unrecorded` event (warn)
names the gateway request and the reason (`error.type`):

| Reason | Cause |
| --- | --- |
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
| `UPSTREAM_CONNECT_TIMEOUT_MS` | 1–30,000 ms | 5,000 |
| `UPSTREAM_IDLE_TIMEOUT_MS` | 1–3,600,000 ms | 120,000 |

`UPSTREAM_URL` names one origin. User information, another path, a query and a fragment are
refused, and a bracketed host must be an IPv6 address followed by nothing or a port. The idle
timeout bounds the wait for the response head (SGLang sends a non-streamed head only after
generating the whole answer), each later body read, a caller that does not accept a relayed
chunk (it is then treated as gone), and how long the relay reads on once the caller has gone.

A refusal exits 78 with one fixed line, for example `configuration error: UPSTREAM_URL is
required`, `configuration error: UPSTREAM_URL must use http://` or `configuration error:
invalid UPSTREAM_URL`. The line never contains the value.

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

## Known gaps in this increment

- **No caller authentication.** Anything that can reach the listener and knows a handed-off
  request ID can spend upstream capacity against it. The default bind is loopback.
- **No model enforcement.** The `model` field is forwarded unchecked, and the recorded server
  answers an unknown model name from its loaded model.
- **Incomplete responses record nothing.** Cancelled, cut and failed requests leave their
  holds for reconciliation until increment 3.
- **Plain HTTP on both sides.** The packaged worker's transport requires an `https://`
  endpoint, so it cannot use this proxy yet.
- **Chat completions only.** The Responses API is not routed.
- **A second dispatch of one request is forwarded.** Settlement does not double-charge it.
- **No concurrency limit** on relayed requests.
- **Identity bodies only.** Compressed requests and answers are refused rather than relayed.

## Testing

`tests/schema/gateway_proxy.rs` runs the binary as `openmettle_gateway` against a stand-in that
replays the recorded SGLang responses in `tests/fixtures/sglang-recorded/`. It needs an
isolated PostgreSQL 18 service in `TEST_DATABASE_URL`, like the other schema tests:

```sh
cargo test --locked --test schema gateway_proxy -- --ignored
```

With `TEST_GATEWAY_UPSTREAM_URL` set to an `http://` SGLang origin, the
`live_upstream_usage_matches_what_the_caller_received` case sends the recorded requests to that
server instead and checks each report against the usage the caller received.
