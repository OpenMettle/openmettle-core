# Gateway proxy (not deployable)

> **Not deployable.** There is no image target, chart or network policy for it yet (increment
> 7). Run it only on an isolated test host with synthetic data.

`openmettle-gateway` is OpenMettle's own inference proxy (V1-06,
[ADR 0044](../adr/0044-own-inference-proxy-and-binding-free-dispatch.md)). It sits between a
caller and one SGLang server. It authenticates the caller by the round bearer of one
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
  `Connection` value holding anything but visible ASCII and spaces, a tab included, before
  the ID or the credential is looked at: such a value could hide a nomination. Refusals use
  the application API's problem document (`application/problem+json`).
- **Authentication.** The caller sends exactly one `Authorization: Bearer` header holding the
  request's 32-byte round bearer as 43 unpadded base64url characters. The worker generates
  that bearer when it hands the round off and sends it to this proxy over HTTP; the proxy
  receives and decodes it. Both send only its SHA-256 to PostgreSQL, which stores that. The
  request's dispatch secret is a different value: it crosses only the worker's database
  connection and is not accepted here. No zeroization guarantee is made for either value. A
  missing, repeated or malformed header, one named in `Connection`, a wrong bearer, an
  unknown request and a request not handed off are all refused alike with
  `401 unauthenticated` and `WWW-Authenticate: Bearer`. So is a request that was not
  dispatched yet and whose run is cancelled, finished, claimed again by another worker, or
  past its lease or its execution deadline. Nothing is sent upstream, and the answer does not
  reveal whether the request exists.
- **Single dispatch.** The database records the request's one dispatch before the body is
  read. A second dispatch with the right bearer is refused with `409 conflict`, also after
  the run was cancelled or has finished. Of two concurrent dispatches at most one is
  forwarded.
- **The bearer stays out of the database.** The proxy sends PostgreSQL the SHA-256 of the
  bearer, which is what the request row stores, and never the bearer; the worker does the
  same when it hands the round off. A server that logs statement parameters therefore
  records nothing a caller could present, and no logging setting is required for the
  gateway's login.
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
  reports it consumed. Every other end of a dispatched request is reported too, without
  counts and with its reason: see [When there is no usage](#when-there-is-no-usage).
- **Caller leaving.** A caller that disconnects, or takes no relayed chunk for an idle
  timeout, gets nothing more. If the usage is not in hand yet, the upstream connection is
  closed so the server stops generating, and the request is closed as `caller_disconnected`.
  If it may be (a stream whose last event carried
  usage, or a JSON body within its parse bound), the relay reads on to finish the accounting,
  rechecking after every read, and stops once one idle timeout has passed since the caller
  left. A body that ends at that moment still counts.

## What it records

| Report field | Value |
| --- | --- |
| `request`, `installation`, `principal`, `scope`, `source` | The stored handed-off request: `source` is its installation and `principal` the user it acts for |
| `report_id`, `revision`, `final` | The request ID, `1` and `true`. Revision `0` on unbound requests is reserved to the worker's maintenance sweep (`openmettle_owner`, increment 3b): a higher final revision with both counts or a proxy reason corrects a lower one, so a report of the proxy that arrives late replaces the sweep's `unreported` record |
| `prompt_tokens`, `completion_tokens` | The upstream's counts. A report with usage has both; a report without usage has neither |
| `incomplete` | Empty for a report with usage. Otherwise the reason the request has none, from the table under [When there is no usage](#when-there-is-no-usage) |
| `reasoning_tokens` | Top-level `reasoning_tokens` or `completion_tokens_details.reasoning_tokens`, which must agree when both are present and cannot exceed `completion_tokens` |
| `reasoning_included` | `true` whenever reasoning tokens are recorded, because SGLang counts them inside `completion_tokens` (recorded 23 Nov 2026). Settlement then measures `prompt + max(completion, reasoning)` |
| `cost`, `unit` | Not recorded (refused on unbound requests); `usage_cost_micros` holds settle inside PostgreSQL from the reported token counts and the `Profile.cost_bound` (`cost_fixed_micros`, `cost_micros_per_token`) the worker recorded on `gateway_requests` at handoff (migration 34) |

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
and hold before acting. If no report exists, the worker's maintenance sweep closes the hold as
`unreported` at revision `0` once 15 minutes have passed after the run's execution deadline
(increment 3b). This applies to a report with usage and to one without.

The report identity is derived from the request, so a retried write stores the same report.

### When there is no usage

A request is dispatched once. Every case below except `dispatch_unconfirmed` has spent the
request: it cannot be sent again. For each of them the proxy logs one
`gateway.usage.unrecorded` event (warn) that names the gateway request and the reason
(`error.type`), and stores one final report that carries the same reason in `incomplete` and
no counts. That report closes the request:

- the token hold becomes `settled` with nothing held and nothing charged, and a cost hold is
  closed the same way;
- the request leaves the scan of outstanding requests (`settled_final`).

**Nothing is charged for a request without usage**, whether or not it reached the model
server. The owner decided this on 24 November 2026 for now, to be revisited; ADR 0044 lists
the alternatives. The reasons fall into two groups so that the rule can change for the second
one alone:

| Reason | Sent upstream | Cause |
| --- | --- | --- |
| `model_not_served` | No | The request was reserved for a model other than `MODEL` (`403 policy`) |
| `model_mismatch` | No | The body was not a JSON object naming the reserved model exactly once (`400 validation`) |
| `request_body` | No | The request body exceeded 2 MiB, did not arrive within 10 s, or the caller left while sending it (`400 validation`) |
| `upstream_connect` | No | No connection to the upstream was made, in time or at all (`502 provider_failure` or `504 timeout`), or the caller left before one was |
| `not_dispatched` | No (worker sweep, revision 0) | The request was handed off without a binding, never dispatched, and its run can no longer dispatch it (failed, cancelled, reclaimed, or past its lease or execution deadline) |
| `upstream_transport` | Yes or unknown | The exchange on an open upstream connection failed before a response head (`502 provider_failure`) |
| `upstream_timeout` | Yes or unknown | No response head or no further body bytes within the idle timeout (`504 timeout` if no head arrived), or the upstream did not finish within one idle timeout after the caller left |
| `upstream_status` | Yes | The upstream answered with a status other than 200; its response is still relayed |
| `upstream_encoding` | Yes | The upstream answered with a content coding other than `identity` or a transfer coding other than `chunked` (`502 provider_failure`) |
| `incomplete` | Yes | The body broke off, or a stream ended without `[DONE]` |
| `caller_disconnected` | Yes or unknown | The caller left or stopped reading before the usage was in hand, or the usage went out of reach while the relay read on; the upstream connection is closed |
| `no_usage` | Yes | The response completed without a usage object, for example a stream requested without `stream_options.include_usage`, or a stream whose last data event before `[DONE]` carried none |
| `unparsable` | Yes | A parse bound was exceeded, or the usage was not a valid usage object |
| `unreported` | Yes or unknown (worker sweep, revision 0) | The request was dispatched without a binding and had no settlement 15 minutes past its run's execution deadline (`dispatch_unconfirmed`, `gateway.usage.failed`, or a proxy stop mid-relay). A late proxy report at revision `1` supersedes it |

To list the requests that ended this way:

```sql
SELECT r.request_id, r.incomplete
  FROM openmettle.gateway_settlements s
  JOIN openmettle.gateway_usage_reports r USING (request_id, revision, final)
 WHERE r.incomplete IS NOT NULL;
```

One case is only logged by the proxy, because the proxy never learned whether the dispatch was
spent:

| Reason | Cause |
| --- | --- |
| `dispatch_unconfirmed` | The database exchange that records the dispatch failed, did not answer within five `DB_TIMEOUT_MS`, or lost its caller first (`503 unavailable`). Nothing was forwarded. If the dispatch was not consumed, the worker sweep closes it as `not_dispatched` once the run can no longer dispatch it; if it was consumed, a retry answers `409 conflict` and the worker sweep closes it as `unreported` 15 minutes past the run's execution deadline |

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
so its request keeps its hold until the worker sweep closes it as `unreported` 15 minutes past
the run's execution deadline, and the process exits 1. So does a database exchange still running
on a connection that stopped answering: the pool waits for every connection when closing.

## Known gaps

- **Plain HTTP on both sides.** The proxy listens on plain HTTP. The packaged worker may call
  it with an `http://` route inside the cluster, whose `private_cidrs` must hold every address
  the proxy's name resolves to; a public address is never reached. The round's bearer and the
  prompt and response bodies then cross the cluster network unencrypted, and an interceptor
  could alter the answer and token counts the worker stores, while the proxy settles the
  upstream's own usage. The bearer authorizes one dispatch of one request. Admit only the worker pods with a NetworkPolicy, or terminate TLS in front
  of the proxy and give the worker an `https://` route; see
  [plain HTTP inside the cluster](worker-turn-execution.md#plain-http-inside-the-cluster).
  The default bind is loopback.
- **A broad database role.** `openmettle_gateway` still has the grants the superseded
  reconciler needed. Increment 6 narrows it to what the proxy uses.
- **No family policy.** Quiet and study hours are enforced nowhere until increment 4.
- **Chat completions only.** The Responses API is not routed.
- **No concurrency limit** on relayed requests.
- **Identity bodies only.** Compressed requests and answers are refused rather than relayed.

## Testing

`tests/schema/gateway_proxy.rs` runs the binary as `openmettle_gateway` against a stand-in that
replays the recorded SGLang responses in `tests/fixtures/sglang-recorded/`. Its requests are
run rounds reserved and handed off through the library, without a gateway binding, and given
a bearer the test knows, because each test presents a request the worker would not send. Each
reason above is produced through the binary and checked against the stored report, the hold
and the accounting drift verifier. It needs an isolated PostgreSQL 18 service in `TEST_DATABASE_URL`, like the other schema tests:

```sh
cargo test --locked --test schema gateway_proxy -- --ignored
```

`tests/schema/live_turns/worker_gateway.rs` runs the real path: the packaged worker claims a
queued run and sends its round, with the bearer it made, to this binary over plain HTTP and,
in a second case, through a TLS terminator; the stand-in answers with a recorded response
and the test checks the stored usage, the dispatch, the settled hold and the published
answer. Two more cases cover a proxy serving another model, whose refusal closes the hold, and
an unreachable proxy, whose undispatched request is closed by the packaged worker's own
maintenance sweep with `not_dispatched`. Like
the packaged-worker tests, they need `TEST_GATEWAY_HOST` naming a private address of the
host (see `.github/workflows/checks.yml`):

```sh
cargo test --locked --test schema worker_gateway -- --ignored
```

With `TEST_GATEWAY_UPSTREAM_URL` set to an `http://` SGLang origin, the
`live_upstream_usage_matches_what_the_caller_received` case sends the recorded requests to that
server instead and checks each report against the usage the caller received.
