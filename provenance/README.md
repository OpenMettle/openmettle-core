# Provenance and distribution readiness

This directory holds the V1-42 provenance register. Its tooling reports dependencies and notice obligations, and refuses distribution while any fact is missing. **This is a partial V1-42 increment.** It covers the core repository and records stack components only as far as the existing evidence allows. It is licence bookkeeping, not legal advice, and it does not clear any component for distribution.

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
  - the distribution boundary has a nonblank description and a dated, attributed decision review with evidence;
  - every required review group (core, graphiti, database, sandbox, serving, media, application-fork) is either `reviewed` or `excluded`. Both need a nonblank summary and a dated, attributed decision review with evidence. An `excluded` group is outside the recorded boundary and also needs an `exclusion_reason`; it cannot contain an `included` or `candidate` component;
  - every `Cargo.lock` package has a review at the exact name, version, source and checksum, and its licence matches the declared crate metadata;
  - every `included` component has a version, pin, origin, licence with evidence, recorded notices and a dated review, and no shipped component remains a `candidate`. An `excluded` or `not-distributed` component needs only its `exclusion_reason`; its missing facts do not block.

Recorded notices require nonempty notice references and obligations. A `none-required` disposition requires an explicit justification and the component or crate review must still be complete before inclusion can pass. Evidence entries must be nonblank strings and review dates must be real calendar dates.

Automatic discovery covers Cargo packages only. The component register is manually curated; the gate cannot detect an omitted image, asset or model. A release reviewer must reconcile the actual distribution against the register. A passing gate checks recorded evidence, not the truth or completeness of external evidence. Absolute Cargo licence-file paths are reduced to filenames in artifacts; the source package still owns the full notice.

`Cargo.lock` is read on every run. A new or upgraded crate has no exact-version review, so it blocks readiness. This includes the V1-01 runtime dependencies once they land. A review for a version no longer in the lockfile produces a stale-review warning.

`cargo metadata --locked` stops Cargo from changing the lockfile. It does not prove that build artifacts are reproducible, and it does not review container images, OS packages or bundled assets.

## Register rules

- Record a licence expression only when there is source evidence for it, and cite that evidence. Otherwise use `null`. A licence recorded by the baseline is evidence; it is not a completed review.
- `review.status: reviewed` needs a named reviewer, a date and evidence. Agents should leave entries `pending`; the owner or a designated reviewer records completed reviews.
- Mark a component `excluded` (kept out of the distribution by decision) or `not-distributed` (tooling that is never shipped) only with an `exclusion_reason`. Use `blocked` for components whose licence is incompatible with the intended distribution.
- Give every component a `redistribution` assessment with a `basis`. It looks ahead to a wider boundary and is not a distribution decision:
  - `redistributable`: the register records a licence expression with evidence, and that licence permits redistribution under its conditions;
  - `user-fetched`: recorded licence evidence restricts redistribution, so a user would fetch the component. It cannot be shipped;
  - `undetermined`: everything else, including any component without recorded licence evidence.
- Use the neutral source aliases from `SOURCE-REFERENCES.md`. Do not add personal repository coordinates, site domains, LAN addresses or storage paths.
- A language translation of existing code is not automatically an independent implementation. Do not record translated Open WebUI code as first-party.

## Current state (19 November 2026)

- **Distribution boundary.** The owner defined it on 19 November 2026 ([decision](https://github.com/OpenMettle/openmettle-core/issues/32#issuecomment-7005620131)) and refined it the same day ([licence policy and reviews](https://github.com/OpenMettle/openmettle-core/issues/32#issuecomment-7006023083), [public forks](https://github.com/OpenMettle/openmettle-core/issues/32#issuecomment-7006271314)):
  - distributed: the source code in the public OpenMettle repositories that are not forks, and the Helm chart in openmettle-deploy;
  - not distributed yet: built container images (including the core api, worker and migrate images), re-hosted third-party images, curated forks and model weights. The public forks OpenMettle/sglang and OpenMettle/open-webui stay outside as public forks under their upstream licences. Third-party images are referenced only at their publishers' locations.

  The long-term direction is to distribute everything needed to run OpenMettle, eventually as an Arch Linux distribution with everything preinstalled except components whose licences do not allow redistribution. Each widening is a separate owner decision; publishing the core images (V1-36) is the likely next one. The register transcribes the boundary and the group dispositions from those comments. They are scope decisions, not licence reviews.
- **Outside the boundary.** The graphiti, database, sandbox, serving, media and application-fork groups are `excluded`. Every component in them is `excluded` or `not-distributed` with a reason, as are the Debian runtime base image and the CI and test tooling in the core group. Their licence reviews remain pending and are needed before the boundary widens to include them.
- **Inside the boundary.** The core source (the `openmettle-core` workspace package), the retained repository-template starter and the vendored OpenAPI 3.2 schemas are `included`. Their notices are recorded. `LICENSE`, including its copyright line, is byte-identical to the template's LICENSE at the pinned revision. The vendored schemas keep their Apache-2.0 LICENSE and origin README. The owner reviewed all three and the core group disposition on 19 November 2026; an agent transcribed those reviews from the decision comment. They are reviews against policy, not legal clearance.
- **Public forks.** OpenMettle/sglang (a public GitHub fork of sgl-project/sglang, default branch `openmettle/rdna4`, root LICENSE Apache-2.0) and OpenMettle/open-webui stay outside the boundary as public forks under their upstream licences. The SGLang fork comes inside, with a full audit, when serving packaging (V1-20) ships it: a selected and pinned release revision, and an audit of its bundled third-party code (`3rdparty/` and the router, gateway and Rust sub-projects). The Open WebUI fork is reference material for the product OpenMettle replaces; it stays public, its licence adds a branding clause, and nothing from it is copied or translated into OpenMettle.
- **Redistribution assessment.** Each component records one. Only components with recorded licence evidence are `redistributable` or `user-fetched`. Neo4j Community is recorded as GPLv3, so it is `redistributable` only with its corresponding source. Evidence for the Agent Sandbox controller, gVisor and HelixDB is unpinned and must be rechecked at the selected release.
- **Rust packages.** No Cargo.lock package other than the workspace package has an exact-version review. Against the current lockfile (333 packages), the gate reports 332 blockers: one for each package without a review record.
- **Observed read-only on 19 November 2026.** Both forks above are publicly visible GitHub forks that keep their upstream licences; neither is part of the OpenMettle distribution. Later that day the owner made every OpenMettle repository public, including openmettle-deploy, so the chart source is now published as the boundary intends. Track these through the publication tickets below.
- **Carried forward.** The register keeps the read-only pins recorded on 16 November 2026: Graphiti 0.31.2 and the neo4j driver 6.4.1 (wheel hashes), the Neo4j Community 5.26.32 and PostgreSQL 18.6 image digests, the Text Embeddings Inference image digest and a locally built SGLang image digest (all at the `workstation-stack` revision cited in `SOURCE-REFERENCES.md`), plus the reviewed revisions of the forks and evidence repositories. It still lacks versions and pins for Agent Sandbox, sandboxd, gVisor, the Graphiti memory image, the SGLang release revision, the media services and all model weights. The runtime images do not yet include licence or notice files for the bundled crates or Debian packages; that matters once the images are published.
- The `serving-fork` licence file names a personal copyright holder. Preserve required copyright and authorship notices. Removing private site configuration does not authorize deleting attribution; track packaging and notice preservation through the existing publication tickets.

## Related publication and scanner work

Do not duplicate this work here. These retained project items track it:

- [Prepare the repos for OpenMettle publication](https://github.com/orgs/OpenMettle/projects/1?pane=issue&itemId=305626649)
- [Personal-reference policy and scanner in CI](https://github.com/orgs/OpenMettle/projects/1?pane=issue&itemId=305657120)
- [Stack: move site-specific values into a private site config](https://github.com/orgs/OpenMettle/projects/1?pane=issue&itemId=305657189)
- [Serving: rebrand and remove work-machine paths from evidence](https://github.com/orgs/OpenMettle/projects/1?pane=issue&itemId=305657370)
- [Open WebUI fork: move to the org with clean authorship](https://github.com/orgs/OpenMettle/projects/1?pane=issue&itemId=305657645)
- [Publish clean repos in the org (history and authorship)](https://github.com/orgs/OpenMettle/projects/1?pane=issue&itemId=305657719)

Sealed evidence and existing history stay unchanged. Nothing in this directory authorizes publishing, releasing or rewriting history.
