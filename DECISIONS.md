# Decision records

## Index (0001–0046)

| ADR | Title | Date |
| --- | --- | --- |
| [0001](#0001--repository-bootstrap-16-november-2026) | Repository bootstrap | 16 November 2026 |
| [0002](docs/adr/0002-cpu-runtime.md) | CPU process and database health runtime | 16 November 2026 |
| [0003](docs/adr/0003-schema-migrations.md) | Schema ownership, migrations and bounded database roles | 17 November 2026 |
| [0004](docs/adr/0004-run-persistence.md) | Run, event and operation persistence | 17 November 2026 |
| [0005](docs/adr/0005-artifact-storage-accounting.md) | Artifact revisions, storage reservations and byte accounting | 17 November 2026 |
| [0006](docs/adr/0006-grant-persistence.md) | Grant persistence and immutable provenance | 17 November 2026 |
| [0007](docs/adr/0007-application-api-contract.md) | Application API contract and consumer fixtures | 17 November 2026 |
| [0008](docs/adr/0008-oidc-id-token-verification.md) | Offline OIDC ID-token verification core | 17 November 2026 |
| [0009](docs/adr/0009-protected-login-transactions.md) | Protected browser login transactions | 17 November 2026 |
| [0010](docs/adr/0010-provider-http-transport.md) | Provider token transport | 17 November 2026 |
| [0011](docs/adr/0011-managed-provider-keys.md) | Configured discovery and managed signing keys | 17 November 2026 |
| [0012](docs/adr/0012-login-provider-authority.md) | Durable login provider authority | 17 November 2026 |
| [0013](docs/adr/0013-local-identity-sessions.md) | Local identity approval and opaque sessions | 17 November 2026 |
| [0014](docs/adr/0014-login-admission.md) | Outstanding login admission | 17 November 2026 |
| [0015](docs/adr/0015-offline-auth-config-check.md) | Offline browser-auth configuration check | 17 November 2026 |
| [0016](docs/adr/0016-pooled-browser-auth-service.md) | Pooled browser-auth service and connection discard | 17 November 2026 |
| [0017](docs/adr/0017-browser-login-handoff.md) | Same-origin browser login handoff | 17 November 2026 |
| [0018](docs/adr/0018-bounded-login-router.md) | Bounded browser login router | 18 November 2026 |
| [0019](docs/adr/0019-session-check-and-logout-routes.md) | Session check and local logout routes | 18 November 2026 |
| [0020](docs/adr/0020-browser-routing-profile.md) | Versioned browser-routing profile | 18 November 2026 |
| [0021](docs/adr/0021-project-membership.md) | Login-time project membership for approved identities | 18 November 2026 |
| [0022](docs/adr/0022-home-invitation-codes.md) | Home invitation codes | 18 November 2026 |
| [0023](docs/adr/0023-native-sign-in.md) | Native sign-in with one-use code delivery | 19 November 2026 |
| [0024](docs/adr/0024-process-telemetry-and-redaction.md) | Process telemetry and default-deny redaction | 19 November 2026 |
| [0025](docs/adr/0025-browser-auth-runtime-mounting.md) | Browser sign-in runtime mounting, off by default | 19 November 2026 |
| [0026](docs/adr/0026-otlp-trace-export.md) | OTLP/HTTP protobuf trace export, off by default | 19 November 2026 |
| [0027](docs/adr/0027-authorization-and-private-projects.md) | Central authorization policy and private-by-default projects | 19–20 November 2026 |
| [0028](docs/adr/0028-telemetry-contract-and-metrics.md) | Telemetry contract v1 and bounded operational metrics | 20 November 2026 |
| [0029](docs/adr/0029-native-sign-in-mounting-and-session-context.md) | Native sign-in profile, runtime mounting and session authorization context | 20 November 2026 |
| [0030](docs/adr/0030-session-issuance-database-boundary.md) | Session issuance database boundary | 20 November 2026 |
| [0031](docs/adr/0031-filesystem-artifact-storage-and-streaming-multipart.md) | Filesystem artifact storage and streaming multipart uploads (superseded in part by ADR 0040) | 20 November 2026 |
| [0032](docs/adr/0032-durable-run-admission-and-fair-work-queue.md) | Durable run admission and fair PostgreSQL work queue | 20 November 2026 |
| [0033](docs/adr/0033-worker-leases-deadlines-and-restart-recovery.md) | Worker leases, deadlines, fencing and restart recovery | 20 November 2026 |
| [0034](docs/adr/0034-ordered-events-and-replayable-sse.md) | Ordered run events, cursor MACs and replayable `/v1` SSE | 20 November 2026 |
| [0035](docs/adr/0035-approvals-permitted-yolo-and-effect-ledger.md) | Approvals, permitted YOLO and the effect ledger | 21 November 2026 |
| [0036](docs/adr/0036-conversation-branches-presets-and-effective-model-config.md) | Conversation branches, presets and effective model configuration | 21 November 2026 |
| [0037](docs/adr/0037-gateway-provisioning-and-usage-reconciliation.md) | Application-owned gateway provisioning and usage reconciliation | 21 November 2026 |
| [0038](docs/adr/0038-sglang-and-external-provider-conformance-adapter.md) | SGLang and external-provider conformance adapter (superseded in part by ADR 0044) | 21 November 2026 |
| [0039](docs/adr/0039-scoped-mcp-adapter-and-bounded-tool-results.md) | Scoped MCP adapter, reviewed tool contracts and bounded spill artifacts | 21 November 2026 |
| [0040](docs/adr/0040-transactional-quotas-and-reservation-reconciliation.md) | Transactional quotas and reservation reconciliation | 21 November 2026; file-copy rebind amendment 24 November 2026; lost-payload declaration amendment 26 November 2026 |
| [0041](docs/adr/0041-retention-purge-and-deletion-journal.md) | Retention, purge and deletion journal | 22 November 2026; PR2a split and audit/journal privilege amendments 23 November 2026; PR2b/PR3 restore gate, lifecycle commitments and lost-payload journal amendment 26 November 2026 |
| [0042](docs/adr/0042-shared-capacity-api-and-resource-grants.md) | Shared capacity API and serialized resource grants | 22 November 2026 |
| [0043](docs/adr/0043-packaged-worker-inference-configuration.md) | Packaged worker inference configuration | 23 November 2026 |
| [0044](docs/adr/0044-own-inference-proxy-and-binding-free-dispatch.md) | OpenMettle's own inference proxy and binding-free dispatch (supersedes ADRs 0037 and 0038 in part) | 23 November 2026 |
| [0045](docs/adr/0045-credential-vault-and-external-connection-lifecycle.md) | Credential vault and external connection lifecycle | 26 November 2026 |
| [0046](docs/adr/0046-maintenance-window-coordinated-backup-capture.md) | Maintenance-window coordinated backup capture | 26 November 2026 |

## 0001 — Repository bootstrap (16 November 2026)

Status: accepted implementation organization; does not revise architecture v1.

Use core, app and deploy repositories as described in REPOSITORIES.md. Store the accepted baseline with its service contracts in core. Keep repositories private during initial development. Start with the existing MIT starter and preserve separate dependency/provenance review before distribution.

The bootstrap pins Rust 1.100.0 and Flutter 3.50.0 for development checks. These are tooling pins, not a decision on the runtime dependency graph. Axum, Tokio, SQLx, rmcp and production images still require the implementation dependency ADR and lockfiles. *(Superseded for the Rust runtime dependency graph and lockfiles by [ADR 0002](docs/adr/0002-cpu-runtime.md).)*

## Template for the next decision

Record: number/title, status/date, triggering problem, decision, alternatives, consequences, affected contracts, evidence, ticket and superseded decision (if any). A proposed decision does not silently replace the accepted baseline.
