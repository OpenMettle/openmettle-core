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
  UUID of a gateway request in state `handed_off`. Its installation, scope, report source
  and binding principal are read from the database; nothing else is taken from the caller. A
  missing or malformed ID is refused with `400 validation`, and an unknown request or one not
  handed off with `404 not_found`, before anything is sent upstream. Refusals use the
  application API's problem document (`application/problem+json`).
- **Forwarding.** The request body (at most 2 MiB, read within 10 s) is sent upstream byte
  for byte on a new connection, with only `Content-Type`, `Accept` and the request ID.
  `Authorization`, cookies and other caller headers are not forwarded.
- **Relay.** The upstream status, `Content-Type` and body are relayed chunk by chunk as they
  arrive. A server-sent event reaches the caller before the upstream has finished. If the
  upstream body breaks off, the caller's response is cut as well rather than ending cleanly.
- **Usage.** A copy of each chunk is read for the usage object. When the upstream answered
  200, the body completed (a JSON document, or a stream ending with `data: [DONE]`) and a
  usage object arrived, one final report is written. This holds whatever the
  `finish_reason`, including `length`: the proxy records what the upstream reports it
  consumed.

## What it records

| Report field | Value |
| --- | --- |
| `request`, `installation`, `principal`, `scope`, `source` | The stored handed-off request and its binding |
| `report_id`, `revision`, `final` | The request ID, `0` and `true` |
| `prompt_tokens`, `completion_tokens` | The upstream's counts; both are required |
| `reasoning_tokens` | Top-level `reasoning_tokens` or `completion_tokens_details.reasoning_tokens`, which must agree when both are present |
| `reasoning_included` | `true` whenever reasoning tokens are recorded, because SGLang counts them inside `completion_tokens` (recorded 23 Nov 2026). Settlement then measures `prompt + max(completion, reasoning)` |
| `cost`, `unit` | Not recorded |

The report is written by the task that relays the response, so the write does not depend on
the caller staying connected. A transient database failure is retried twice (after 100 ms and
500 ms). There is no local spool: if the write still fails, the proxy logs
`gateway.usage.failed` and the hold stays for reconciliation.

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
| `upstream_status` | The upstream answered with a status other than 200; its response is still relayed |
| `upstream_transport` | The upstream could not be reached or failed before a response head (caller gets `502 provider_failure`) |
| `upstream_timeout` | Connect, response-head or idle-read timeout (`504 timeout` if no head arrived) |
| `incomplete` | The body broke off, or a stream ended without `[DONE]` |
| `caller_disconnected` | The caller left before the usage arrived; the upstream connection is closed |
| `no_usage` | The response completed without a usage object, for example a stream requested without `stream_options.include_usage` |
| `unparsable` | A parse bound was exceeded, or the usage could not be read |

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
refused. The idle timeout bounds the wait for the response head (SGLang sends a non-streamed
head only after generating the whole answer), for each later body read, and for a caller that
does not accept a relayed chunk; a caller that slow is treated as gone.

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
and the process exits 1.

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
