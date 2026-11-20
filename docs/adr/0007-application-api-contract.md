# 0007 — Application API contract and consumer fixtures

Status: coordinator-agreed first V1-03 increment, 17 November 2026. Related: core #4 and
sprint #34. Independent review remains required. The first increment published the contract
and its checks. The second adds an internal
capability evaluator and qualification tests. Neither adds a route, authentication,
authorization enforcement, cursor signing or runtime HTTP error handling. Final V1-03
acceptance belongs to the coordinator after review and owner merge.

Update, 20 November 2026 (V1-05 PR4b, ADR 0027): the contract gains fourteen project,
membership, conversation and artifact operations, and all fifteen operations are served,
authenticated and authorized when `OPENMETTLE_API_AUTH_CONFIG` is set. V1-04 settled both
security schemes. See [Served operations](#served-operations-v1-05-pr4b). Cursors, run
idempotency and SSE remain unimplemented.

Update, 20 November 2026 (V1-15 PR2, ADR 0031): four artifact operations add multipart uploads,
revision metadata and byte-range downloads, and the `416 range_not_satisfiable` problem. See
[Artifact payload operations](#artifact-payload-operations-v1-15-pr2).

Update, 20 November 2026 (V1-12 PR1): [ADR 0034](0034-ordered-events-and-replayable-sse.md)
proposes the run snapshot and event stream operations, wire event types, cursor MACs, replay
retention, resynchronization and authorization during replay, and proposes replacing the
`Last-Event-ID`/`after` conflict rule below with header precedence. Nothing is served yet.

## Canonical source and versions

`contracts/openapi/openmettle-v1.json` is the single hand-maintained source. It uses
OpenAPI 3.2.1 (published 10 September 2026) and the OpenAPI 3.2 Schema Object dialect
`https://spec.openapis.org/oas/3.2/dialect/2026-02-26`, which is JSON Schema 2020-12 plus the
OAS base vocabulary. The contract uses only 2020-12 keywords. JSON rather than YAML keeps the
source parseable by the Python standard library and serde_json without another parser.

OpenAPI 3.2 is selected for native sequential media types: `itemSchema` describes each parsed
`text/event-stream` item, and `components.mediaTypes` holds the reusable stream description
without adding an operation. The OpenAPI version does not prevent breaking changes to this
application API. Compatibility comes from the additive v1 policy below and the executable
compatibility tests.

Generated fixtures live in `contracts/fixtures/`; do not edit them by hand. Regenerate them with
`python3 scripts/contract_fixtures.py`. Consumers pin a core commit, as REPOSITORIES.md requires.
`info.version` is `1.0.0-draft.1` until the owner releases a contract.

## Scope of the published contract

| Area | Contract | Not implemented |
| --- | --- | --- |
| Endpoints | `GET /v1/capabilities` and, since V1-05, the project, membership, conversation and artifact operations; each `x-openmettle-implementation: implemented`, authenticated | Served only with `OPENMETTLE_API_AUTH_CONFIG`; otherwise 404. Capability data sources: the list is empty |
| Authentication | `browserSession` (`__Host-openmettle-session` cookie, CSRF `Origin` binding) and `nativeSession` (bearer OpenMettle session credential), settled by V1-04 (ADRs 0019 and 0029) | — |
| Errors | RFC 9457 `Problem` with code/status binding | Runtime mapping and redaction are implemented for `/v1` (ADR 0027 PR4b) |
| Pagination | `cursor`/`limit` parameters and `PageInfo` | Cursor issuance, binding and MAC; no list operation |
| Idempotency | `Idempotency-Key` parameter and `idempotency_conflict` | Implemented for the V1-05 writes through the authorization audit; run request identity storage (V1-10) |
| Events | `RunEvent` envelope, `RunEventItem` and `RunEventStream` media type, `Last-Event-ID`/`after` | SSE endpoint, retention, resync (V1-12) |
| Capabilities | `CapabilityList`, `Capability`, `Readiness` | Provider adapters, authenticated serving and authorization (V1-04/05) |

Run states, wait reasons, persistence identity digests, grant assignment formats and other
storage vocabulary from ADRs 0004–0006 are not wire policy. Run resources are excluded until
their lifecycle is agreed. No voice, provider-compatibility or MCP endpoint is defined.

## Wire rules

- **Identifiers:** canonical lowercase UUID strings (`Uuid`). Identifiers are random, never
  derived from secrets, digests or request content.
- **Timestamps:** RFC 3339 UTC, exactly six fractional digits and `Z`, for example
  `2026-11-17T09:00:00.000000Z`.
- **Large integers:** byte sizes and counters use `NonNegativeDecimal`: a canonical decimal
  string from 0 to 9223372036854775807 with no sign, leading zero, exponent or fraction.
  Event sequences use `PositiveSequence` (1 to the same maximum). Consumers parse them exactly
  and reject values outside signed 64-bit. JSON numbers are used only for small bounded values
  such as `status`, `limit`, `retry` and `type_version`.
- **Bounds:** every string has `maxLength`, every array `maxItems`, every integer a minimum and
  maximum. Idempotency keys are 1–128 visible ASCII characters (0x21–0x7E), so character and
  byte length are equal.
- **Requests:** request objects must set `additionalProperties: false` or
  `unevaluatedProperties: false`. Unknown request fields fail with `validation`. A contract lint
  enforces the rule and is tested against an injected open body; the server decodes every body
  into a closed type that refuses unknown, duplicate and wrongly typed members.
- **Responses:** response objects are extensible. Consumers ignore unknown fields. String
  vocabularies in responses (`code`, `kind`, readiness `state`, event `type`) are open:
  consumers map unrecognized values to an explicit unknown or unrecognized case and never
  infer a capability or success from them.

## Versioning

The path prefix carries the major version. Every response carries
`OpenMettle-API-Version: 1.<minor>`. Within v1, changes are additive only: new optional
response fields, new values in open vocabularies, new operations, new optional request fields.
A minor increment is not required for every additive change, but each one must keep every
existing fixture valid and must add fixtures for the new shape. Removing or renaming fields,
changing types, tightening a response constraint, adding a required request member or changing
the meaning of a value requires a new major path. Consumers accept any newer minor and reject an
unsupported major explicitly rather than decoding a best-effort response. During a rolling
upgrade an older server rejects a newer client's unknown request fields with `validation`.

## Idempotency

The server scopes `Idempotency-Key` to the authenticated actor, the operation and the
authorized scope context. It never trusts an actor or user identity supplied in a request body.
The same key with the identical request returns the original outcome. The same key with a
different request returns 409 `idempotency_conflict`. Retries after an uncertain outcome
(timeout, connection loss, unknown commit) must resend the identical request, including any
client-chosen input identity such as a message UUID: ADR 0004 binds that UUID into run identity.
There is no retention-period, expiry or exactly-once promise. The V1-05 writes implement these
rules through the append-only authorization audit (ADR 0027 PR4b); V1-10 implements them for
runs.

## Pagination

Cursors are opaque, unpadded base64url strings up to 512 characters. A cursor is valid only for
the caller, operation, filters and sort order that produced it. Malformed, foreign, expired or
tampered cursors fail with 400 `invalid_cursor`. Binding will need server-side integrity
protection. No MAC or signature is implemented or claimed here, and cursors must not be plain
encodings of internal identifiers or of the caller's identity.

## Events and replay

Each SSE item has an opaque `id` (the resume cursor) and a `data` string containing one JSON
`RunEvent`: `run_id`, `sequence`, `type`, `type_version`, `occurred_at` and an object `data`.
`contentSchema` is not asserted automatically, so consumers and the contract tests decode `data`
and validate it explicitly. This revision defines no event types. Clients ignore event types they
do not recognize but still advance their cursor; they ignore sequences they have already applied.
A client resumes with `Last-Event-ID` or `after`. If both are present and differ, the request is
invalid (`validation`); ADR 0034 proposes replacing this with `Last-Event-ID` precedence.
Retention, expired-cursor resynchronization, snapshots, buffering and authorization during
replay belong to V1-12 (ADR 0034).

## Errors

Problems use `application/problem+json` with `type` (v1 emits `about:blank`), `title`,
`status`, stable `code`, optional bounded `detail` (at most 512 characters), `request_id` and
optional `errors` locations. Client-supplied values are never echoed.

| Status | Codes |
| --- | --- |
| 400 | `validation`, `invalid_cursor` |
| 401 | `unauthenticated` |
| 403 | `policy`: only when the caller is already authorized to know the resource exists |
| 404 | `not_found`, also concealing resources the caller may not know about |
| 409 | `conflict`, `idempotency_conflict` |
| 416 | `range_not_satisfiable` |
| 429 | `quota`, `rate_limited` |
| 500 | `internal` |
| 502 | `provider_failure` |
| 503 | `unavailable`, `provisioning` |
| 504 | `timeout` |

422 is not used. The schema binds each known code to its status. Unknown codes are allowed with
any 4xx/5xx status and are classified by status class. `detail` never carries credentials,
upstream provider bodies, identity claims, internal identifiers or information about other
users. Synthetic fixtures show the intended shape only. Runtime problems of the `/v1` routes are
tested separately: see [Served operations](#served-operations-v1-05-pr4b).

## Capabilities

Each capability reports three independent dimensions:

- `installed` (boolean): deployment configuration.
- `authorization`: `true`, `false` or `null` (not determined). `null` is unknown, never false.
  The field exists only in this authenticated contract.
- `readiness`: present only when installed. `ready`, `degraded` and `unavailable` are
  observations and require `observed_at`. `unknown` means no current observation and is neither
  unavailable nor ready. Consumers treat unrecognized states as not ready.

No dimension implies another. An empty list is a valid core-only installation. Capability
readiness is not an input to `/readyz`, which remains a PostgreSQL check (ADR 0002). Capability
objects never carry provider endpoints, credentials, model secrets or other users' inventory;
a contract lint rejects sensitive property names, but it is not a complete privacy scanner.
There is no unauthenticated capability endpoint. The internal evaluator and isolation tests
are described below.

## Validation and fixtures

`tests/contract.rs` runs offline in the normal test suite:

- the document validates against the vendored official OAS 3.2 `schema-base` (2026-11-12), which
  also validates every Schema Object against the OAS dialect and the JSON Schema 2020-12
  metaschema bundled by the validator; a malformed Schema Object is rejected;
- vendored schema files match pinned SHA-256 digests; any reference that is not vendored,
  including `https:` and `file:` references, is refused and tested;
- every component schema compiles; every generated fixture validates as declared, with format
  assertion enabled. Invalid fixtures must fail at the declared instance path with the declared
  keyword. SSE `data` content is decoded and validated against its `contentSchema`;
- lints require authentication, an implementation status of `implemented` or
  `not-implemented`, settled (not provisional) security schemes, version headers and
  problem-only error responses on operations, and bounded, closed and privacy-safe schemas.
  Each lint is shown to fire on a mutated document. The browser scheme's cookie name is the one
  the server sets;
- an independent typed consumer (`tests/contract/consumer.rs`), sharing no types with any server
  code, decodes every valid and compatible fixture. It maps unknown values explicitly, rejects
  structural failures, unsupported majors and out-of-range sequences, advances SSE cursors over
  unrecognized events and drops replayed sequences;
- the API binary started without `OPENMETTLE_API_AUTH_CONFIG` returns 404 for every contract
  path;
- the API binary started with a version-2 document and its native profile, over a database
  that never answers, returns problems that validate against `Problem`, carry the version and
  `no-store` headers and echo no request value, for every operation without a session and for
  each pre-database refusal.

`scripts/contract_fixtures.py` (standard library) generates fixtures from Example Objects with
`x-openmettle-fixture`. Besides declared mutations, it adds an unknown root field to each object
response example (compatible) and removes each root-required property (invalid). `--check`
fails on missing, changed or stale files. It never judges validity. Fixtures are synthetic.
Capability identifiers in examples are illustrative, not a catalogue.

## Dependencies

Development-only, exact pins; the production dependency graph and features are unchanged
(`cargo tree -e normal,build` compared before and after).

| Crate | Version | Origin | Licence | Purpose |
| --- | --- | --- | --- | --- |
| jsonschema | 0.61.2, `default-features = false` | https://github.com/Stranger6667/jsonschema | MIT | JSON Schema 2020-12 validation; HTTP and file retrieval disabled |
| serde | 1.0.229 (`derive`) | https://github.com/serde-rs/serde | MIT OR Apache-2.0 | Typed consumer; already locked |
| serde_json | 1.0.154 | https://github.com/serde-rs/json | MIT OR Apache-2.0 | JSON parsing; already locked |

jsonschema's registry checksum is
`0e37f27df77c7887edbc5f5a59ecd8e5ec4a669319266ec1b61068667a603183`; rust-version 1.85.0.
Resolution added 47 packages to `Cargo.lock` with no change to existing entries:

ahash 0.8.12, aho-corasick 1.1.5, bit-set 0.8.0, bit-vec 0.8.0, borrow-or-share 0.2.4,
bumpalo 3.20.4, bytecount 0.6.9, data-encoding 2.11.1, email_address 0.2.10, fancy-regex 0.20.2,
fluent-uri 0.4.1, fraction 0.17.0, getrandom 0.3.4, js-sys 0.3.107, jsonschema 0.61.2,
jsonschema-regex 0.61.2, jsonschema-value 0.61.2, micromap 0.3.0, num 0.4.3, num-bigint 0.4.8,
num-cmp 0.1.0, num-complex 0.4.6, num-integer 0.1.47, num-iter 0.1.46, num-rational 0.4.2,
outref 0.5.2, r-efi 5.3.0, ref-cast 1.0.27, ref-cast-impl 1.0.27, referencing 0.61.2,
regex 1.13.1, regex-automata 0.4.18, regex-syntax 0.8.11, rustversion 1.0.23, strum 0.28.0,
strum_macros 0.28.0, unicode-general-category 1.1.0, uuid-simd 0.8.0, vsimd 0.8.0,
wasip2 1.0.4+wasi-0.2.12, wasm-bindgen 0.2.130 (and -macro, -macro-support, -shared),
wit-bindgen 0.57.1, zerocopy 0.8.63, zerocopy-derive 0.8.63.

Declared licences are MIT, Apache-2.0, MIT-0, BSD-2-Clause, Unlicense or LLVM-exception
alternatives. `r-efi` also offers LGPL-2.1-or-later as one alternative alongside MIT and
Apache-2.0. Several packages (wasm-bindgen, js-sys, wasip2, wit-bindgen, r-efi) are lock entries
for other targets and are not compiled on Linux or macOS hosts. The V1-42 gate reads every
`Cargo.lock` package, so each new package is an unreviewed distribution blocker. No clearance
is claimed.

The vendored OAS schema files come from https://spec.openapis.org (source repository
https://github.com/OAI/OpenAPI-Specification, Apache-2.0; no NOTICE file upstream). They are
retained unmodified with the licence in `contracts/vendor/oas-3.2/` and recorded as a pending
component in `provenance/register.json`.

## Remaining V1-03 work

Keep #4 open for independent review, final-head CI evidence, owner merge and the
coordinator's audit of all four criteria. This increment leaves the initial contract,
generated fixtures and independent consumer unchanged as the compatibility baseline.

## Internal capability evaluation

`src/capabilities.rs` evaluates one entry using deployment installation/enabled flags,
a supplied caller visibility/authorization decision and a lazy observation future. These
inputs are for future server policy; they must never be populated from client claims.
This helper does not implement authorization or discover any user inventory.

Hidden entries return no result. Visible entries retain Allowed, Denied or Unknown
independently of installation. Uninstalled entries have no readiness. Installed entries
start unknown. Disabled entries retain unknown readiness with reason `disabled`; they
are never offered or queried. Denied and unknown authorization also skip observation.
Only installed, enabled, explicitly allowed entries call the observer. This is a deliberate
privacy boundary: a non-allowed caller receives unknown readiness, not an inference about
provider health. The schema permits independent observations such as denied authorization
with observed unavailable readiness; this evaluator does not produce every valid combination.
Example reasons such as `not_observed` and `provider_unreachable` are illustrative open
vocabulary. This evaluator emits only the reason codes described below and `disabled`;
skipped observations for non-allowed callers carry no reason.

The seam accepts bounded enum outcomes, never raw errors, URLs, credentials or user data.
Ready, degraded and unavailable observations carry a completion `SystemTime`; unknown
and unrecognized status vocabulary have no observation timestamp and are not offered.
Provider failure produces unavailable with reason `provider_failure` and an observation
time. Timeout produces unknown with reason `timeout`: it does not establish provider
status. Deadlines are clamped to 1 ms–5 s. Cancellation drops the observation future.
Observers must yield and be cancellation-safe; this does not stop blocking code,
detached tasks or external side effects. There are no adapters or detached tasks here.
The offer predicate is a discovery hint; consumers must recognize capability kinds and
recheck current permissions on execution. No production HTTP serializer is supplied.

`tests/capabilities.rs` exercises dimension combinations, lazy-call counts, failures,
unknown vocabulary, timeout and drop cancellation. `tests/contract.rs` validates test
projections of actual results against the canonical schema. Its fixed timestamp checks
the projected shape, not production time formatting. Existing independent consumer
checks cover unknown kinds, readiness vocabulary and API versions without Flutter.

The ignored `tests/runtime.rs` PostgreSQL test starts the real API binary and probes
`/readyz` while the evaluator in the harness fails, is disabled or is actively pending.
It checks timeout and cancellation cleanup, readiness afterward, and the absent product
route. The existing CI runtime command runs it against isolated PostgreSQL. This is a
regression guard for the current runtime. Structural inspection establishes isolation:
there is no optional observation in the production health/readiness path. The test does not
qualify an in-process adapter or future API handler; the first handler to host an observer
must supply that evidence.

Acceptance evidence: schemas/fixtures and compatibility are supplied by the first
increment; dimension separation by evaluator tests, and current optional failure isolation by
structural separation plus passing runtime regression tests. Policy, provisioning, validation, quota, timeout and provider
failure remain distinct contract error categories. Bounded evaluator outcomes add no
raw diagnostic fields, but do not prove HTTP error mapping, cross-user enforcement or
runtime redaction. Those are downstream V1-04/05 responsibilities, not circular closure
prerequisites for the contract/evaluator. No dependency or feature changes are required.

## Downstream implementation

Authenticated serving of `/v1/capabilities`, runtime problem mapping and runtime redaction
tests are delivered by V1-05 PR4b (below). Run idempotency (V1-10), SSE replay (V1-12),
deploy (V1-32), and ACP consume the qualified contract. These dependents are not
prerequisites for closing #4: V1-04 itself depends on V1-03. Contract fixtures do not
establish runtime privacy or consumer adoption; those require separate evidence in their
owning tickets.

## Served operations (V1-05 PR4b)

`src/v1.rs` serves the fifteen V1-05 operations, and the four artifact operations below, when
`OPENMETTLE_API_AUTH_CONFIG` is set. Their
authorization and lifecycle rules are recorded in ADR 0027. The wire rules of this record apply
as follows.

- **Problems.** Every error is `application/problem+json` with `type: about:blank`, the
  status's reason phrase as `title`, one fixed `detail` per category and the request ID that
  telemetry logged for the request. No request value, identifier, credential, database error
  or internal policy reason appears. A path or method the contract does not define under `/v1`
  is `404 not_found`. Request target and header limits, a missing or malformed
  `Idempotency-Key`, a malformed path UUID, a wrong media type and a refused body are
  `400 validation`. A full in-flight bound or an unreachable primary is `503 unavailable`;
  an elapsed session or database deadline is `504 timeout`. A wrong `Origin` on the cookie
  channel is `401 unauthenticated`, so `403 policy` stays reserved for callers who may know the
  target exists.
- **Versions and caching.** Every response, success or problem, carries
  `OpenMettle-API-Version: 1.0` and `Cache-Control: no-store`.
- **Media types.** A body is one JSON object with `Content-Type: application/json`, optionally
  `; charset=utf-8`, of at most 64 KiB, except the streamed artifact uploads below. Operations
  without a body refuse a non-empty one.
- **Idempotency.** The server derives the stored request key as a SHA-256 digest of
  `openmettle/v1-idempotency/1`, the `operationId`, the path identifier and the client key. The
  audit table is unique per actor, so the client key is scoped to the actor, the operation and
  its target. A create replays to `201` with the project; a delete replays to `204`.
- **Numbers and times.** `revision` and `last_revision` are `NonNegativeDecimal`; `created_at`
  and `generated_at` are `Timestamp` values in UTC with six fractional digits.

`tests/contract.rs` validates live problems of the mounted binary without PostgreSQL, and the
independent consumer decodes the new response fixtures. `tests/schema/authz_http.rs` exercises
every operation over PostgreSQL 18 on both session channels and decodes each response with the
same consumer.

## Artifact payload operations (V1-15 PR2)

Storage, publication and reconciliation are ADR 0031. These operations follow every rule above;
the additions are:

| Operation | Request | Success |
| --- | --- | --- |
| `createArtifact` `POST /v1/artifacts` | Optional `scope_id` (default: the caller's personal scope) and `max_bytes` query; multipart body | `201` `ArtifactRevision`, revision `1` |
| `createArtifactRevision` `POST /v1/artifacts/{artifact_id}/revisions` | Optional `max_bytes`; multipart body | `201` `ArtifactRevision`, the next revision |
| `getArtifactRevision` `GET /v1/artifacts/{artifact_id}/revisions/{revision_id}` | — | `200` `ArtifactRevision` in any state |
| `downloadArtifactRevision` `GET …/{revision_id}/content` | Optional `Range` | `200` or `206` bytes |

- **Multipart.** OpenAPI 3.2 `multipart/form-data` with an `encoding` per part: one `file`
  part (binary, explicit `Content-Type`, optional `filename` kept as `display_name`) and one
  `metadata` part (`application/json`, the closed `ArtifactUploadMetadata` object, currently
  `{}`), in either order. `createArtifact` carries both orders as `serializedValue` wire
  examples under different boundaries; `tests/contract.rs` parses them to the same upload, and refuses
  their truncated and repeated-part variants.
- **Order of refusals.** After the shared route, bound, permit and session-channel steps: the
  path identifiers, `Idempotency-Key`, the query (`scope_id` a canonical UUID and only on
  `createArtifact`; `max_bytes` a canonical decimal from 1 to 67108864; nothing else, each at
  most once) and one multipart `Content-Type` with a valid boundary, or for a download the
  `Range`, are `400 validation`. Then a server without `OPENMETTLE_API_ARTIFACTS_DIR` answers
  `503 provisioning`. Only then is the session validated and the target authorized.
- **Authorization.** `createArtifact` needs the personal scope's owner or a project editor:
  a missing, deleted or invisible project is `404`, a viewer `403 policy`, an archived project
  `409 conflict`. `createArtifactRevision` needs write access to the artifact: an item the
  caller may not read is `404`, a reader `403`, an archived project `409`. Reads need current
  read access on every request; a revision of another artifact is `404`.
- **Idempotency.** The request key binds the operation, the target (the effective scope of a
  new artifact, or the artifact) and the client key. The reservation identity adds
  `max_bytes`; the settlement adds size, SHA-256, media type and display name. An exact retry,
  with any boundary or part order, replays `201` with the same body and one charge. A changed
  request, or a key whose upload failed, is `409 idempotency_conflict`; a key whose upload is
  still streaming is `409 conflict`. Quota is `429 quota`; unconfigured storage limits are
  `503 provisioning`.
- **`ArtifactRevision`.** `artifact_id`, `revision_id`, `revision` and `size_bytes`
  (`NonNegativeDecimal`), `scope_kind`, `scope_id`, `project_id`, `media_type` as normalized
  by the parser, `sha256` (64 lowercase hex digits), nullable `display_name`, `state` (open:
  `active`, `retained`, `purging`, `purged`) and `created_at`. No storage path or reservation.
- **Downloads.** Only `active` revisions serve bytes; another state is `409 conflict`. The
  response carries the stored media type as `Content-Type`, an exact `Content-Length`,
  `Accept-Ranges: bytes`, `X-Content-Type-Options: nosniff` and `Content-Disposition:
  attachment` with the display name as an RFC 8187 `filename*` in which every byte outside
  `attr-char` is percent-encoded. `Range` takes one RFC 9110 byte range (`first-last`,
  `first-` or `-suffix`) and answers `206` with `Content-Range: bytes first-last/size`. A
  range that does not overlap the content, including any range of an empty file and `-0`, is
  `416 range_not_satisfiable` with `Content-Range: bytes */size`. A list of ranges, another
  unit, a reversed or malformed range, or a repeated field is `400 validation`. With
  `If-Range` the whole content is sent, because the server issues no validator. `HEAD` answers
  like `GET` without a body. A missing or resized stored file is `500 internal`.

`tests/contract.rs` checks the live refusals above without PostgreSQL, the multipart examples
and the consumer's `decode_revision`. `tests/schema/authz_http.rs` exercises uploads, retries
with a new boundary and part order, quota, lifecycle, downloads, ranges, `HEAD`, share and
membership revocation, interrupted uploads and `reconcile_expired` over PostgreSQL 18 on both
session channels.
