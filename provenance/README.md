# Provenance and distribution readiness

This directory holds the V1-42 provenance register. Its tooling reports dependencies and notice obligations, and refuses distribution while any fact is missing. **This is a partial V1-42 increment.** It covers the core repository and records stack components only as far as the existing evidence allows. It is not legal advice and does not clear any component for distribution.

## Files

| Path | Purpose |
| --- | --- |
| `provenance/register.json` | Maintained source: Rust package reviews, stack components, review-group dispositions and the distribution boundary |
| `scripts/provenance.py` | Generates the inventory and runs the distribution-readiness gate (Python 3.11+ standard library) |
| `scripts/tests/test_provenance.py` | Positive and negative gate tests that use the synthetic fixture in `scripts/tests/fixtures/provenance/` |
| `.github/workflows/provenance.yml` | CI inventory artifact; the readiness gate runs on manual dispatch |

The generated inventory is a CI artifact and is not committed. A committed snapshot of the bootstrap dependency graph would go stale as soon as V1-01 adds runtime crates.

## Commands

```sh
python3 -m unittest discover -s scripts/tests -v
cargo metadata --locked --format-version 1 > /tmp/cargo-metadata.json
python3 scripts/provenance.py inventory --cargo-metadata /tmp/cargo-metadata.json --output-dir /tmp/provenance
python3 scripts/provenance.py check-distribution --cargo-metadata /tmp/cargo-metadata.json
```

`--cargo-metadata` is optional for local runs without the pinned toolchain. When it is omitted, the gate reports declared crate licences as unverified. Exit codes:

| Command | 0 | 1 | 2 |
| --- | --- | --- | --- |
| `inventory` | Inventory written, even if blockers remain | — | Register, lockfile or metadata is invalid or inconsistent |
| `check-distribution` | No recorded blockers; owner release approval is still required | One or more blockers | As above |

## Inventory and clearance are separate

- **Inventory success** means the register is valid, every `Cargo.lock` package is listed, and the output is reproducible. It says nothing about whether distribution is permitted.
- **Distribution readiness** fails until all of the following hold:
  - the distribution boundary is defined;
  - every required review group (core, graphiti, database, sandbox, serving, media, application-fork) has a reviewed disposition;
  - every `Cargo.lock` package has a review at the exact name, version, source and checksum, and its licence matches the declared crate metadata;
  - every `included` component has a version, pin, origin, licence with evidence, recorded notices and a dated review, and no shipped component remains a `candidate`.

`Cargo.lock` is read on every run. A new or upgraded crate has no exact-version review, so it blocks readiness. This includes the V1-01 runtime dependencies once they land. A review for a version no longer in the lockfile produces a stale-review warning.

`cargo metadata --locked` stops Cargo from changing the lockfile. It does not prove that build artifacts are reproducible, and it does not review container images, OS packages or bundled assets.

## Register rules

- Record a licence expression only when there is source evidence for it, and cite that evidence. Otherwise use `null`. A licence recorded by the baseline is evidence; it is not a completed review.
- `review.status: reviewed` needs a named reviewer, a date and evidence. Agents should leave entries `pending`; the owner or a designated reviewer records completed reviews.
- Mark a component `excluded` only with an `exclusion_reason`. Use `blocked` for components whose licence is incompatible with the intended distribution.
- Use the neutral source aliases from `SOURCE-REFERENCES.md`. Do not add personal repository coordinates, site domains, LAN addresses or storage paths.
- A language translation of existing code is not automatically an independent implementation. Do not record translated Open WebUI code as first-party.

## Current state (16 November 2026)

- The distribution boundary is **undefined**. No accepted decision states whether a distribution contains only the core binaries or also container images, Helm-referenced images, curated forks or model artifacts. This needs an owner decision.
- Every review group and component review is pending. Without crate metadata, the gate reports 99 blockers against the bootstrap lockfile (one workspace package). Against the V1-01 runtime lockfile in PR #35 (179 packages), it reports 277 blockers, 178 of them crates with no exact-version review.
- The register records the PR #35 build, runtime and test images by digest. Once V1-01 merges, rerun the gate against the merged `Cargo.lock`, Dockerfile and crate metadata. The runtime images do not yet include licence or notice files for the bundled crates or Debian packages.
- These pins are taken from read-only source evidence: Graphiti 0.31.2 and the neo4j driver 6.4.1 (wheel hashes), the Neo4j Community 5.26.32 and PostgreSQL 18.6 image digests, the Text Embeddings Inference image digest and a locally built SGLang image digest (all at the `workstation-stack` revision cited in `SOURCE-REFERENCES.md`), plus the reviewed revisions of the forks and evidence repositories.
- These are missing: versions and pins for Agent Sandbox, sandboxd and gVisor; the Graphiti memory image; the SGLang release revision; the media services; and all model weights. Licences are also missing for several pinned components.
- The `serving-fork` licence file names a personal copyright holder. The obligation to preserve authorship conflicts with removing personal references, so it must be resolved through the existing publication tickets before distribution.

## Related publication and scanner work

Do not duplicate this work here. These retained project items track it:

- [Prepare the repos for OpenMettle publication](https://github.com/orgs/OpenMettle/projects/1?pane=issue&itemId=305626649)
- [Personal-reference policy and scanner in CI](https://github.com/orgs/OpenMettle/projects/1?pane=issue&itemId=305657120)
- [Stack: move site-specific values into a private site config](https://github.com/orgs/OpenMettle/projects/1?pane=issue&itemId=305657189)
- [Serving: rebrand and remove work-machine paths from evidence](https://github.com/orgs/OpenMettle/projects/1?pane=issue&itemId=305657370)
- [Open WebUI fork: move to the org with clean authorship](https://github.com/orgs/OpenMettle/projects/1?pane=issue&itemId=305657645)
- [Publish clean repos in the org (history and authorship)](https://github.com/orgs/OpenMettle/projects/1?pane=issue&itemId=305657719)

Sealed evidence and existing history stay unchanged. Nothing in this directory authorizes publishing, releasing or rewriting history.
