# Vendored OpenAPI 3.2 schemas

Unmodified copies of official OpenAPI Initiative schema files, retrieved on 17 November 2026.
They validate `contracts/openapi/openmettle-v1.json` offline. `tests/contract.rs` pins each digest.

| File | Source | SHA-256 |
| --- | --- | --- |
| `schema-base-2026-11-12.json` | https://spec.openapis.org/oas/3.2/schema-base/2026-11-12 | `8e432f0f148597960daa3aafa0c0030d8aae7538d32c217854a1e3aada595216` |
| `schema-2026-11-12.json` | https://spec.openapis.org/oas/3.2/schema/2026-11-12 | `f1f7ee38d431a7bb1082e4df2288dbe1d4d3f49081b497af249c07b77737fb43` |
| `dialect-2026-02-26.json` | https://spec.openapis.org/oas/3.2/dialect/2026-02-26 | `9375b7042aa0b01848403f0a9ebf12a3425e01a9e24337ce12624f10fea73833` |
| `meta-2026-02-26.json` | https://spec.openapis.org/oas/3.2/meta/2026-02-26 | `f444d02ef7d36f30293983fad8118c823a3c70a49a8e5aa6f1afe21215e35417` |
| `LICENSE` | https://github.com/OAI/OpenAPI-Specification/blob/main/LICENSE | `4948367c65e1ce06690e2cadc6e86fce1a6a6db55ef874ce4b78c0f472ce5f13` |

These were the latest OpenAPI 3.2 schema iterations listed at https://spec.openapis.org/oas/
on the retrieval date; the latest 3.2 specification is v3.2.1. The OpenAPI Specification
repository is licensed under Apache-2.0 and has no NOTICE file. The JSON Schema 2020-12
metaschema is not vendored; the pinned `jsonschema` crate bundles it. To update, retrieve new
iterations, update this table, the digests in `tests/contract.rs` and ADR 0007, then rerun the
contract tests.
