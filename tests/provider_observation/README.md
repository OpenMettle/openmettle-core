# Provider document observation (V1-04)

This harness records how a pinned stock OIDC provider serves its discovery and JWKS documents on the wire. It supports [#5](https://github.com/OpenMettle/openmettle-core/issues/5). It does not attempt a sign-in, change the security profile in [ADR 0011](../../docs/adr/0011-managed-provider-keys.md) or qualify any provider.

## What runs

The [workflow](../../.github/workflows/provider-observation.yml) runs on pull requests that change this directory, the workflow or `src/provider_http.rs`, and on manual dispatch. Other pull requests do not start it.

1. `harness` runs the offline tests in `test_observe.py`. No provider runs in this job.
2. `observe` pulls the official Keycloak 26.8.2 image by index digest and checks its version label. It starts the image in production mode (`start`) with `--network none`, so the provider has no network except its own loopback. No admin account, client, realm import, identity broker or proxy is configured. The stock `master` realm is observed.
3. `observe.py` sends one request to each fixed path through the image's own shell (`bash` `/dev/tcp`) on `127.0.0.1:8080`:
   - `/realms/master/.well-known/openid-configuration`
   - `/realms/master/protocol/openid-connect/certs`

   Each request carries only `Host` and the production `Accept` header from `src/provider_http.rs`. A test fails if those headers diverge. Python's `http.client` parses the response. Redirects are never followed. The returned `jwks_uri` is compared with the fixed path but never requested.

Three options differ from a bare `start`. `--http-enabled=true` with `--hostname=http://127.0.0.1:8080` gives a deterministic loopback HTTP origin. `--cache=local` is needed because the default clustered cache cannot bind without a network. `--db=dev-file` states the production default explicitly. None of these options sets response headers on the observed endpoints.

## What is reported

The job summary contains a JSON report built only from integers, booleans, constants and allowlisted tokens. Raw documents, key material, key IDs, issuer strings and unrecognized header values are never written. A test injects canary values into every observed field and checks that none of them appears in the report. Provider logs are not published.

For each document the report covers:

- the status code;
- the `Content-Type` media type and charset;
- whether `Date` is present and is an IMF-fixdate;
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

Content types, `Date`/`Age`, JWKS cache directives, PKCE and the `iss` parameter flag are recorded but not asserted. Upstream source alone does not settle their rendered values. Add assertions only after an owner has reviewed a hosted observation.

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
