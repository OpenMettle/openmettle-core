# OpenMettle core

Rust API and workers for OpenMettle. **Bootstrap only:** the two binaries intentionally exit with configuration status 78; neither starts a server or processes work. No authentication, persistence, GPU orchestration or production endpoint is implemented yet.

## Start here

- [Accepted architecture v1](ARCHITECTURE-v1.md), including service diagrams and all 43 delivery tickets.
- [Repository boundaries](REPOSITORIES.md), [decisions](DECISIONS.md) and [provenance](UPSTREAM.md).
- [Live delivery tracker](https://github.com/orgs/OpenMettle/projects/1/views/1?filterQuery=%5BV1-00%5D&pane=issue&itemId=307308630).

## Development

Install Rust through the [official rustup installer](https://rustup.rs/). The repository pins Rust 1.100.0 with rustfmt and Clippy; Cargo installs the selected components through rustup when required. Python 3.10+ runs the repository check.

```sh
python3 scripts/check_repository.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
```

API and worker remain in one workspace and can be built independently with `cargo build --bin openmettle-api` and `cargo build --bin openmettle-worker`. Add shared crates as real boundaries emerge. The initial workspace uses only the Rust standard library.

## First implementation

V1-01 introduces actual runtime configuration, shutdown, health and packaging. V1-02 owns schema/migrations; V1-03 owns the application/event/capacity contracts. Add the version-pinned runtime dependencies in a reviewed ADR, then commit the resolved lockfile. Keep provider APIs distinct from the application API. V1-42 tracks distribution provenance.

The app repository consumes core APIs. The deploy repository owns generic Helm packages. Private site values and curated fork implementations stay outside this tree.

## Baseline maintenance

The baseline is the complete accepted document exported from the [planning Page](https://chatgpt.com/space/page_fef707d85d8c8191a14f162d6281307d). SOURCE-REFERENCES.md retains neutral aliases, source pins and paths for personal repository citations; the Page retains original URLs. The native workbook reference points back to that archive. These portability/privacy changes do not amend the accepted architecture. Record subsequent decisions in DECISIONS.md and link implementation tickets.
