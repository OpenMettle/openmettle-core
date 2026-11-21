# Application API contract

`contracts/openapi/openmettle-v1.json` defines the `/v1/*` application API. Operations marked
`"x-openmettle-implementation": "implemented"` are served by `openmettle-api` when
`OPENMETTLE_API_AUTH_CONFIG` is configured, covering `/v1/capabilities`, `/v1/projects`,
`/v1/conversations`, `/v1/branches`, `/v1/models`, `/v1/presets`, `/v1/runs`, and
`/v1/artifacts` families. Without `OPENMETTLE_API_AUTH_CONFIG`, `openmettle-api` serves
`/healthz` and `/readyz` only and answers `404` on `/v1/*` paths. Read
[ADR 0007](../docs/adr/0007-application-api-contract.md) for wire rules, versioning and limits.

| Path | Purpose |
| --- | --- |
| `openapi/openmettle-v1.json` | Canonical OpenAPI 3.2.1 document (hand-maintained) |
| `fixtures/{valid,compat,invalid}/` | Generated consumer fixtures; do not edit |
| `vendor/oas-3.2/` | Official OpenAPI 3.2 schema files, unmodified, Apache-2.0 |
| `telemetry/v1.json` | Canonical telemetry contract v1: redaction policy, log/trace allowlists and bounded metrics (ADR 0028) |
| `telemetry/alerts-v1.yaml` | Deterministic Prometheus alert rules over telemetry contract v1 signals (ADR 0028) |
| `telemetry/alerts-v1-test.yaml` | Deterministic `promtool test rules` suite covering positive and negative cases for v1 alerts (ADR 0028) |

After changing the document, regenerate fixtures and run the checks:

```sh
python3 scripts/contract_fixtures.py
python3 scripts/contract_fixtures.py --check
python3 -m unittest discover -s scripts/tests
cargo test --locked --offline --test contract
```

Fixture classes:

- `valid`: canonical examples and declared boundary values.
- `compat`: responses a v1 consumer must accept, such as unknown fields, unrecognized
  vocabulary and newer minors.
- `invalid`: each records the instance path and JSON Schema keyword that must fail.

Each fixture records its schema pointer, source example and mutation. Fixtures are synthetic.
They do not prove that a runtime produces or redacts responses correctly.

Consumers pin a core commit. Client generators may be added only after these conformance
checks exist (REPOSITORIES.md).
