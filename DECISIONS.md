# Decision records

## 0001 — Repository bootstrap (16 November 2026)

Status: accepted implementation organization; does not revise architecture v1.

Use core, app and deploy repositories as described in REPOSITORIES.md. Store the accepted baseline with its service contracts in core. Keep repositories private during initial development. Start with the existing MIT starter and preserve separate dependency/provenance review before distribution.

The bootstrap pins Rust 1.100.0 and Flutter 3.50.0 for development checks. These are tooling pins, not a decision on the runtime dependency graph. Axum, Tokio, SQLx, rmcp and production images still require the implementation dependency ADR and lockfiles.

## Template for the next decision

Record: number/title, status/date, triggering problem, decision, alternatives, consequences, affected contracts, evidence, ticket and superseded decision (if any). A proposed decision does not silently replace the accepted baseline.
