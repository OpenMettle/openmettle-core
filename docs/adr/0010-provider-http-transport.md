# 0010 — Provider token transport

Status: coordinator-agreed V1-04 increment, 17 November 2026. Related: core #5 and sprint #34.
Independent review is required. This increment partly addresses the first #5 acceptance
criterion; #5 stays open.

## Decision

`src/provider_http.rs` adds `ProviderTransport`, the production `AsyncHttpClient` for the
existing `ExchangePermit::exchange` (ADR 0009). It sends one public-client token `POST` to one
deployment-configured HTTPS endpoint. hyper's HTTP/1.1 client connection parses the response,
and rustls with the explicit ring provider handles TLS through tokio-rustls. There is no
hand-written HTTP or TLS protocol code.

reqwest was rejected. Its documented defaults follow up to 10 redirects, retry "protocol
NACKs", pool connections in background tasks, read system proxies and use aws-lc-rs. It
exposes no HTTP/1 header byte limit. Each of these would need to be disabled or worked
around. A per-request hyper connection supplies exact parser bounds and a connection
driven by the caller.

The address policy, endpoint and trust parsing, TLS configuration, DNS resolution, connection
and response framing live in the crate-internal `provider_http::transport` core (V1-29). It
takes caller-owned limits and a caller-owned DNS slot pool, accepts only `GET` with an empty
body or `POST`, and allows only `Accept` and `Content-Type` caller headers. `ProviderTransport`
keeps its stricter admission, its limits and the process-wide pool described below. Another
configured client, such as an OTLP exporter, supplies its own pool and cannot consume
provider DNS slots.

Not implemented: discovery, JWKS fetch or refresh, configuration loading, routes, cookies,
sessions, admission, confidential clients, HTTP/2, proxies and real-provider qualification.

## Destination authority

Deployment configuration supplies the token endpoint, the trust anchors and an optional
private-range allowlist. Tokens, metadata, DNS answers and response content are untrusted.
A request can never select a destination.

- **Endpoint:** a canonical `https` URL with a DNS host name. The input must equal its own
  `url` serialization: lowercase host, no default `:443`, no dot segments, no percent-encoding,
  user information, query, fragment, backslash, whitespace or trailing dot. IP literals are
  refused, as are numeric forms the URL parser turns into IP addresses. A single-label host
  such as `localhost` is also refused.
- **Before any DNS work:** the request must be `POST` and HTTP/1.1, and its URI must equal
  the configured URL exactly. It may carry only distinct `Accept` and `Content-Type` headers:
  at most 4 headers, 1 KiB in total, and a body of at most 32 KiB. `Authorization`,
  `Cookie`, `Proxy-Authorization`, `Host` and every other header fail.
- **Outbound request:** origin-form path, `Host` taken from the configured authority,
  `Connection: close`, the library body, and no `Accept-Encoding` or `TE`.

### Address policy

Every DNS answer must pass before any connection is made; one refused answer refuses them
all. The tables follow the [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/)
and [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/) special-purpose
registries (both updated 2025-10-09) and the
[IPv6 unicast assignments](https://www.iana.org/assignments/ipv6-unicast-address-assignments/)
(updated 2025-10-10).

1. **Hard denies, which always win:** `100.100.100.200`, `168.63.129.16` and
   `fd00:ec2::254`, known cloud platform and metadata endpoints.
2. **Private ranges** (RFC 1918, CGNAT `100.64/10`, ULA `fc00::/7`): allowed only inside a
   configured allowlist entry.
3. **IPv4 refused:** every other special-purpose block plus multicast: `0/8`, `127/8`,
   `169.254/16`, `192.0.0/24`, documentation, benchmarking, `240/4`, broadcast,
   `192.88.99/24`. AS112 and AMT blocks are listed as globally reachable but are refused
   conservatively.
4. **IPv6 public:** only space that IANA has allocated to the RIRs (34 prefixes), minus the
   AS112 delegation `2620:4f:8000::/48`. Everything else is refused rather than decoded:
   loopback, unspecified, IPv4-mapped and IPv4-compatible addresses, NAT64 `64:ff9b::/96` and
   `64:ff9b:1::/48`, the whole `2001::/23` IETF block (including Teredo), 6to4, discard and
   dummy prefixes, SRv6, link-local, multicast and unallocated `2000::/3`. A future IANA
   allocation fails closed until the table is updated.

The private allowlist defaults to empty and holds at most 32 entries. Each entry must be in
canonical text, have no host bits, and lie within one RFC 1918, CGNAT or ULA block, so
loopback, link-local, public and over-broad ranges are refused. A self-hosted provider
therefore needs an explicit CIDR and valid certificate trust. This policy does not replace
deployment egress control such as a Kubernetes NetworkPolicy, which remains a deploy
concern.

## DNS, connection and TLS

- **One lookup per request.** The operating-system resolver runs through `ToSocketAddrs` on
  Tokio's blocking pool, and only the configured host and port enter that job. The job can
  return at most 64 answers; a 65th answer fails the request instead of being truncated.
- **Accepted residual.** A blocking lookup cannot be cancelled. A process-wide semaphore of
  8 slots bounds outstanding lookups, including abandoned ones. The owned permit moves into
  the blocking closure, so a slot is released only when the lookup actually finishes.
  Queueing, lookup, TCP connect and TLS share a 5-second setup budget. A dropped request
  can leave only a bounded DNS job behind, never HTTP or credential-bearing work. Tokio's
  runtime shutdown waits for such jobs, bounded by the OS resolver's own timeouts.
- **Connection.** The transport connects only to the validated addresses. It may try the next
  address after a TCP connect failure, before any TLS or HTTP bytes are sent, within the same
  budget. DNS rebinding cannot redirect a connection that is already validated.
- **TLS.** rustls 0.23 with the ring provider, TLS 1.3 and 1.2, ALPN `http/1.1`, and no
  client certificate, session resumption or early data. The certificate is verified against
  the configured host name, never the connected address.
- **Trust.** A configured PEM bundle (1–256 certificates, at most 1 MiB) *replaces* the native
  roots. Any non-certificate PEM section (for example a CRL), parse error or rejected certificate fails
  construction. `Trust::Native` uses rustls-native-certs; `SSL_CERT_FILE` and `SSL_CERT_DIR`
  are deployment authority when set. Any native load error, or zero usable roots, fails
  closed. No insecure verifier exists.
- **Not supported.** Proxy environment variables are never read, and there is no proxy
  support. Requests are never retried and redirects are never followed: a 3xx response
  returns to the library, and `ExchangePermit` reports `Error::Exchange`. The authorization
  code is therefore used once, even after an ambiguous failure once the request was sent.

## Response bounds

- **Parser limits.** hyper's parser enforces at most 32 response headers and 8 KiB of header
  bytes, status line included, with its 8 KiB minimum read buffer. hyper documents
  `max_header_size` as also bounding chunked trailers.
- **Rejected before any body read:** a declared `Content-Length` over 64 KiB.
- **Body.** It streams through `http_body_util::Limited` at 64 KiB, chunked bodies included,
  and the exact `Content-Length` must arrive.
- **Framing.** Exactly one `Content-Length`, or a `Transfer-Encoding` of exactly `chunked`; a
  close-delimited body (including HTTP/1.0 without a length) is refused, except for 204 and
  304. Both length and chunked together, duplicate `Content-Length`, `Content-Type` or
  `Transfer-Encoding` headers, any non-`identity` `Content-Encoding`, and trailers are
  refused. Nothing is decompressed.
- **Interim responses.** hyper consumes interim 1xx responses; an endless stream of them is
  bounded by the deadline.
- **Deadlines.** The whole request has a 10-second deadline, the same as the existing exchange
  deadline and not an extension of it.
- **Errors.** `provider_http::Error` is fieldless with fixed text. It never carries a URL,
  host, address, header or body. `Debug` for the transport prints `ProviderTransport(..)`.

## Concurrency and cancellation

The hyper connection future is polled inside the request future, together with the response
future. Nothing HTTP- or TLS-related is spawned or pooled. Dropping the request drops the
connection and closes the socket.

## Dependencies

All direct dependencies are exact pins. Every package new to the lock is an automatic V1-42
distribution blocker; the register is unchanged and no waiver is implied.

| Crate | Version | Origin | Licence | Use |
| --- | --- | --- | --- | --- |
| tokio-rustls | 0.26.6, defaults off, `ring`, `tls12` | https://github.com/rustls/tokio-rustls | MIT OR Apache-2.0 | **New.** Async rustls stream. Checksum `c9cc2678c2cdd569ef8215e2afd7954ada2ae20b4fdd2c5fe6139a3b02d105db` |
| want | 0.3.2 | https://github.com/seanmonstar/want | MIT | **New**, through the hyper `client` feature. Checksum `ec4cdd0dd910afe868b7ef477227d8d538b46b3075031afee8a9f2acb0a2ed0b` |
| try-lock | 0.2.5 | https://github.com/seanmonstar/try-lock | MIT | **New**, through want. Checksum `e421abadd41a4225275504ea4d6566923418b7f05506fbc9c0fe86ba7396114b` |
| hyper | 1.12.0, `client`, `http1` | hyperium | MIT | Already locked; adds `client` |
| hyper-util | 0.1.21, `tokio` | hyperium | MIT | Already locked; `TokioIo` |
| http-body-util | 0.1.5 | hyperium | MIT | Already locked; `Limited`, `Full` |
| rustls | 0.23.46, `ring`, `std`, `tls12` | rustls | Apache-2.0 OR ISC OR MIT | Already locked; feature set unchanged |
| rustls-native-certs | 0.8.5 | rustls | Apache-2.0 OR ISC OR MIT | Already locked through sqlx |
| bytes | 1.12.1, `std` | tokio-rs | MIT | Already locked |
| rcgen (dev only) | 0.14.10, defaults off, `ring` | https://github.com/rustls/rcgen | MIT OR Apache-2.0 | **New.** In-memory synthetic CA and leaf certificates. Minimum Rust 1.88. Checksum `8774e05a7d0de114588e6a28fe7e71694b82614ed569d86d8b389dfbc98b8ad8` |
| yasna (dev only) | 0.6.0 | https://github.com/qnighy/yasna.rs | MIT OR Apache-2.0 | **New**, through rcgen. Checksum `b5f6765e852b9b4dc8e2a76843e4d64d1cea8e79bcde0b6901aea8e7c7f08282` |

Measured `Cargo.lock` change: 317 → 333 packages, 16 added and none removed. No existing
package changed version or checksum; edges changed only for hyper, the workspace and feature
unification. On the macOS host:

- 3 new packages compile for production: tokio-rustls, want and try-lock.
- 2 new packages compile only for tests: rcgen and yasna. `time` was already locked.
- 11 are lock-only entries that no enabled feature compiles, because rcgen's optional
  `x509-parser` is recorded by Cargo: x509-parser, asn1-rs, asn1-rs-derive, asn1-rs-impl,
  der-parser, oid-registry, rusticata-macros, nom, minimal-lexical, bit-vec 0.9.1 and
  synstructure 0.13.2.

No aws-lc-rs, HTTP/2 (`h2`), reqwest or proxy crate is present. The local inventory lists 333 Rust packages. The
distribution gate still fails closed: it reports 334 Cargo blockers (16 more than before this
change) and 433 blockers in total.

## Evidence

Unit tests in `tests/provider_http_support/tests.rs` (mounted under `cfg(test)`) use an
in-process TLS server on loopback with an rcgen CA, leaf, wrong-CA and expired certificates
generated in memory. No key or certificate file is tracked. Server connection and request
counts are asserted exactly.

- **Valid exchange:** exactly one connection and one request. The test checks method, path,
  `Host`, `Connection: close` and content type, and the absence of credential, proxy,
  encoding and upgrade headers.
- **End to end:** `login::tests::real_tls_transport_exchanges_once_and_never_follows_redirects`
  drives `ExchangePermit::exchange` over the real transport to the existing `FakeProvider`.
  It yields a verified identity from one request. A 307 response yields `Error::Exchange`,
  and the redirect target gets zero connections.
- **Redirects:** 302 and 307 responses are returned and not followed; the second server sees
  zero connections.
- **Rejected before DNS or connect:** wrong host, port, path, query or scheme; `GET`;
  HTTP/1.0; credential, `Host`, forwarding, framing or duplicated headers; an oversized body.
  The lookup and connection counts stay zero.
- **Production policy:** the production constructor plus a test resolver returning loopback
  is refused, with or without a private allowlist. Mixed answers (loopback with metadata,
  private, IPv4-mapped or hard-denied addresses), a wrong answer port, empty answers and 65
  answers are refused with zero connections. 64 answers are accepted.
- **Policy boundaries:** a table of IPv4 and IPv6 boundaries, embedded and transition forms,
  unallocated space, allowlist containment, hard-deny precedence and invalid or over-broad
  ranges. Endpoint canonical-form refusals and trust-bundle failures are also covered.
- **TLS:** a wrong CA, a wrong host name and an expired leaf each produce `Error::Tls` with
  zero HTTP requests read.
- **Size and header limits:** an exact 64 KiB body passes. A declared 64 KiB + 1 fails as
  `TooLarge` before the body; the server stalls, so a body read would time out instead. A
  68 KiB chunked body fails, as do 33 headers (32 pass) and more than 8 KiB of headers.
- **Framing:** gzip encoding, duplicate type or length, length with chunked, other transfer
  codings, a signed length, close-delimited and HTTP/1.0 bodies, a short body, trailers, an
  unterminated chunked body, HTTP/2 and garbage all fail as `Protocol`. `identity`, chunked,
  `100 Continue` followed by 200, and 204 pass.
- **Deadlines:** a stalled head, a stalled fixed-length body, a dripping chunked body and
  endless `102 Processing` responses all reach `Timeout`.
- **No retry:** a server that closes after reading the request produces `Protocol`, with one
  connection and one request even though two answers were valid. Connecting falls back from
  a refusing `[::1]` to `127.0.0.1` before sending.
- **Cancellation:** dropping the request after the server has read it closes the server's
  connection.
- **DNS slots:** eight dropped requests keep all eight slots, and a ninth times out in the
  queue. Releasing one lookup frees exactly one slot, which a new request then uses. The
  production pool is the shared process-wide semaphore.
- **Proxies ignored:** a child process with `HTTP(S)_PROXY`/`ALL_PROXY` set, in both cases,
  completes one exchange and the proxy listener receives no connection. No in-process
  environment mutation is used.
- **Redaction:** `Debug` and every error `Display`/`Debug` exclude the synthetic host, path and
  range markers.

The test-only hooks exist only in `cfg(test)` builds: the resolver, a private slot pool with
shorter deadlines, and permission for 127.0.0.1 and ::1. Production code builds the
transport only through `ProviderTransport::new`.

## Not covered

- Real providers, public DNS, real CA chains and native roots on deployment images. Native
  root loading is not exercised.
- Revocation checking (CRL/OCSP), which rustls does not perform by default.
- Confidential clients and egress proxies.
- Discovery and JWKS rotation. Later discovery may only confirm configured endpoints: it is
  not permission to fetch an arbitrary metadata URL. The provider-outage key freshness policy
  remains an owner decision.
- Configuration loading and validation.
- Routes, cookies, native handoff, sessions, logout and revocation.
- Admission, provisioning, reconciliation and operator recovery.

No issue acceptance is closed, and no Mac result implies GPU or production qualification.
