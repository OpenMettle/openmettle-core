# Provider document observation (V1-04)

This harness records how a pinned stock OIDC provider serves its discovery and JWKS documents on the wire. It supports [#5](https://github.com/OpenMettle/openmettle-core/issues/5). It does not attempt a sign-in, change the security profile in [ADR 0011](../../docs/adr/0011-managed-provider-keys.md) or qualify any provider.

## What runs

The [workflow](../../.github/workflows/provider-observation.yml) runs on pull requests that change this directory, the workflow or `src/provider_http.rs`, and on manual dispatch. Other pull requests do not start it.

1. The job runs the offline tests in `test_observe.py`.
2. On the same runner, it pulls the official Keycloak 26.8.2 image by index digest and checks its version label. It starts Keycloak in production mode (`start`) with `--network none`. The provider can use only its own loopback interface. The fixture uses the stock `master` realm.
3. `observe.py` waits for discovery to return HTTP 200. It retains that first successful response and requests the key set once. Both paths are fixed on `127.0.0.1:8080` inside the provider container.
   - `/realms/master/.well-known/openid-configuration`
   - `/realms/master/protocol/openid-connect/certs`

   Each request carries `Host`, the production `Accept` value from `src/provider_http.rs`, and `Connection: close` so the shell relay exits after one response. A test checks the `Accept` value against the Rust source. Python's `http.client` parses the response. The observer compares the returned `jwks_uri` with the configured address and follows no redirects.

Three options differ from a bare `start`. `--http-enabled=true` with `--hostname=http://127.0.0.1:8080` gives a deterministic loopback HTTP origin. `--cache=local` is needed because the default clustered cache cannot bind without a network. `--db=dev-file` states the production default explicitly. None of these options sets response headers on the observed endpoints.

## What is reported

The job log and summary contain the same JSON report. It contains only integers, booleans, constants and recognized tokens. The offline tests check that arbitrary provider values stay out of the report. The fixture disables Docker container logging.

For each document the report covers:

- the status code;
- the `Content-Type` media type and charset;
- whether `Date` is present and matches the IMF-fixdate format;
- whether `Age` is present, and its value if numeric;
- `Cache-Control` directives;
- whether `Content-Encoding` or `Location` is present.

For discovery it also covers whether the issuer and endpoints match the fixed realm, the advertised token endpoint authentication and PKCE methods, `authorization_response_iss_parameter_supported`, and whether `code`, `query`, `authorization_code`, RS256 and `public` are advertised. For the JWKS it reports key counts by type, algorithm and use, and whether any private member is present.

## Assertions

The job fails on any of these fixture errors:

- discovery is not served before the deadline;
- either document is not a 200 JSON object within 64 KiB, or it repeats a member;
- the issuer or `jwks_uri` does not match the fixed realm;
- the JWKS has no key array or contains private key members.

The job also fails if either source prediction from the [#5 research](https://github.com/OpenMettle/openmettle-core/issues/5#issuecomment-6985077381) is not observed:

- discovery `token_endpoint_auth_methods_supported` must be an array without `none`;
- discovery `Cache-Control` must include `no-store`.

Each of these properties conflicts with a rule in `src/provider_keys/documents.rs`: `metadata` requires `none`, and `freshness` refuses `no-store`. A passing job therefore reports `observed-incompatibility`. It does not mean that sign-in works, that Keycloak is supported, or that these are the only conflicts.

The report also records content types, `Date`/`Age`, JWKS cache directives, PKCE and the `iss` parameter flag for comparison with a hosted run.

## Limits

- **Loopback HTTP only.** These are direct observations of the provider's HTTP headers. They are not end-to-end evidence of OpenMettle's HTTPS provider transport, TLS, DNS policy or `ProviderKeys` behaviour. No reverse proxy, CDN or TLS terminator is present. A real deployment can add or rewrite these headers.
- **One release, one realm.** The observation covers the pinned image and the stock `master` realm with no client configured. Upstream source builds discovery without client context, but a configured public client is not exercised.
- **Pin durability.** Keycloak rebuilds and re-pushes the mutable `26.8.2` tag; it moved on 9 and 12 November 2026. The pinned index digest was the active tag on 18 November 2026. If the registry later removes the untagged manifest, the pull fails and the job fails. Re-resolve and re-record the pin; do not switch to a tag.
- **Provenance strength.** The image's SLSA provenance is an unsigned BuildKit attestation stored in the same index. It records the source repository and commit but is not a verified signature.

## Local commands

```sh
python3 -m unittest discover -s tests/provider_observation -v
```

The observation itself needs Docker and runs on the hosted runner.
