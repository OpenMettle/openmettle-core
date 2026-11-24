# Provenance and distribution readiness

This directory holds the V1-42 provenance register. Its tooling reports dependencies and notice obligations, and refuses distribution while any fact is missing. **This is a partial V1-42 increment.** It covers the core repository and records stack components only as far as the existing evidence allows. It is licence bookkeeping, not legal advice, and it does not clear any component for distribution.

## Files

| Path | Purpose |
| --- | --- |
| `provenance/register.json` | Maintained source: the distribution boundary, review-group dispositions, the Cargo licence policy, maintained Rust package reviews and stack components |
| `provenance/cargo-reviews.json` | Generated, committed review records: one per Cargo.lock package without a maintained review, checked against the Cargo licence policy. Do not edit by hand |
| `scripts/provenance.py` | Generates the policy records and the inventory, and runs the distribution-readiness gate (Python 3.11+ standard library) |
| `scripts/tests/test_provenance.py` | Positive and negative gate tests that use the synthetic fixture in `scripts/tests/fixtures/provenance/` |
| `.github/workflows/provenance.yml` | CI inventory artifact; the readiness gate runs on manual dispatch |

The generated inventory is a CI artifact and is not committed. A committed snapshot of the bootstrap dependency graph would go stale as soon as V1-01 adds runtime crates.

## Commands

```sh
python3 -m unittest discover -s scripts/tests -v
cargo metadata --locked --format-version 1 > /tmp/cargo-metadata.json
python3 scripts/provenance.py review-cargo --cargo-metadata /tmp/cargo-metadata.json
python3 scripts/provenance.py inventory --cargo-metadata /tmp/cargo-metadata.json --output-dir /tmp/provenance
python3 scripts/provenance.py check-distribution --cargo-metadata /tmp/cargo-metadata.json
```

`review-cargo` rewrites `provenance/cargo-reviews.json`; review its diff before committing. `review-cargo --check` writes nothing and reports whether the committed records are current.

**Every pull request that changes `Cargo.lock` must regenerate the records with `review-cargo` and commit them.** Stale records fail CI through the unit tests: `test_committed_policy_records_cover_the_lockfile_and_match_the_policy` fails when the records do not cover `Cargo.lock` exactly or disagree with the allow-list. The CI step that runs `review-cargo --check` afterwards also compares the records with real `cargo metadata` output; a difference there (a declared licence that changed without a lockfile change) is reported as a warning, not a failure, and blocks distribution readiness.

 `--cargo-metadata` is required for `review-cargo` and optional for the other commands for local runs without the pinned toolchain. When it is omitted, the gate reports declared crate licences as unverified. Exit codes:

| Command | 0 | 1 | 2 |
| --- | --- | --- | --- |
| `inventory` | Inventory written, even if blockers remain | — | Register, records, lockfile or metadata is invalid or inconsistent |
| `check-distribution` | No recorded blockers; owner release approval is still required | One or more blockers | As above |
| `review-cargo` | Records written, or `--check` found them current | `--check` found stale records | As above |

## Inventory and clearance are separate

- **Inventory success** means the register is valid, every `Cargo.lock` package is listed, and the output is reproducible. It says nothing about whether distribution is permitted.
- **Distribution readiness** fails until all of the following hold:
  - the distribution boundary has a nonblank description, an `artefacts` list and a dated, attributed decision review with evidence;
  - every required review group (core, graphiti, database, sandbox, serving, media, application-fork) is either `reviewed` or `excluded`. Both need a nonblank summary and a dated, attributed decision review with evidence. An `excluded` group is outside the recorded boundary and also needs an `exclusion_reason`; it cannot contain an `included`, `candidate` or `reviewed-elsewhere` component;
  - every `Cargo.lock` package has a maintained review or a generated policy record at the exact name, version, source and checksum, and its licence matches the declared crate metadata. A policy record also needs an `allowed` outcome under the current allow-list and an owner-approved Cargo licence policy. A path (workspace) package needs a maintained review: `review-cargo` generates no record for it, and the gate refuses one. A maintained review's licence must also be on the allow-list. If the boundary's `artefacts` include `container-image` or `binary`, the policy's `none-required` notices no longer hold and the gate blocks until notice obligations are recorded;
  - every `included` component has a version, pin, origin, licence with evidence, recorded notices and a dated review, and no shipped component remains a `candidate`. An `included` component's licence must be on the allow-list. An `excluded` or `not-distributed` component needs only its `exclusion_reason`; its missing facts do not block. A `reviewed-elsewhere` component is inside the boundary but reviewed in another repository, so this gate does not evaluate it (see the register rules).

Recorded notices require nonempty notice references and obligations. A `none-required` disposition requires an explicit justification and the component or crate review must still be complete before inclusion can pass. Evidence entries must be nonblank strings and review dates must be real calendar dates.

Automatic discovery covers Cargo packages only. The component register is manually curated; the gate cannot detect an omitted image, asset or model. A release reviewer must reconcile the actual distribution against the register. A passing gate checks recorded evidence, not the truth or completeness of external evidence. Absolute Cargo licence-file paths are reduced to filenames in artifacts; the source package still owns the full notice.

`Cargo.lock` is read on every run. A new or upgraded crate has no exact-version review or record, so it blocks readiness until the records are regenerated and committed. A review or record for a version no longer in the lockfile produces a stale warning.

## Cargo licence policy (owner-approved)

`cargo_licence_policy` in `register.json` is an explicit allow-list of SPDX licence identifiers. **It is a licence-bookkeeping policy, not legal clearance.** An agent proposed it, and the owner approved it on 19 November 2026 with CC0-1.0 dropped and MIT-0 added ([decision](https://github.com/OpenMettle/openmettle-core/issues/32#issuecomment-7006023083)). An agent transcribed the approval into the policy's review. If the review returns to `pending`, every package reviewed against the policy blocks readiness. The approved list is:

`0BSD`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `MIT`, `MIT-0`, `Unicode-3.0`, `Zlib`

`review-cargo` reads each package's declared `license` field from `cargo metadata` and records its outcome:

- an `OR` expression passes if any branch is allowed; an `AND` expression passes only if every part is allowed. `AND` binds tighter than `OR`, and parentheses group as in SPDX;
- a `WITH` term passes only if the whole term, such as `Apache-2.0 WITH LLVM-exception`, is on the list. None are listed, so such a term needs another allowed `OR` branch;
- Cargo's deprecated `/` separator is read as `OR`, by the same owner decision. This normalisation applies to the Cargo `license` field only, before SPDX evaluation. An expression containing `/` is rewritten only when it is a plain list of single licence identifiers: `MIT/Apache-2.0` is evaluated as `MIT OR Apache-2.0`, and the record keeps the declared form in `declared_licence` and the evaluated form in `slash_as_or`. SPDX identifiers cannot contain `/`, so a valid SPDX expression is never rewritten. A `/` mixed with `AND`, `OR` or `WITH` (in any case) or with parentheses is refused as ambiguous, as is an empty or multi-word item between separators. An operator counts only as a whole token between whitespace or `/`, so `MIT/GPL-2.0-or-later` is read as `MIT OR GPL-2.0-or-later` and then evaluated; `GPL-2.0-or-later/LGPL-2.1-or-later` is read the same way and blocks because neither licence is allowed;
- these stay blockers, and the record names the reason: no declared licence (including packages that only name a licence file), an invalid SPDX expression (including lower-case operators and a refused `/` form) and a licence outside the list. The tool does not reinterpret them.

The gate re-checks every committed record, including its `slash_as_or` reading, against `Cargo.lock`, the declared metadata and the current allow-list. A hand-edited, stale or policy-changed record blocks. Packages with a maintained review in `cargo_reviews` (the first-party workspace package) get no generated record. The allow-list also applies to maintained reviews and `included` components. There is no per-package exception mechanism, because the owner has granted no exception; adding one would need a named, evidenced and owner-reviewed exception.

The policy's `scope` records that Cargo packages are build inputs under the 19 November 2026 boundary: Cargo fetches them at build time and no binary or image containing them is distributed. Their notices are therefore `none-required` for now. The boundary's machine-readable `artefacts` list (`source`, `helm-chart`) carries that condition: adding `container-image` or `binary` makes the gate block until the policy records the crates' notice obligations. They become shipped content once the core images are published (V1-36). That widening needs its own owner decision, and each crate's licence and notice files must then ship with the images.

`cargo metadata --locked` stops Cargo from changing the lockfile. It does not prove that build artifacts are reproducible, and it does not review container images, OS packages or bundled assets.

## Register rules

- Record a licence expression only when there is source evidence for it, and cite that evidence. Otherwise use `null`. A licence recorded by the baseline is evidence; it is not a completed review.
- `review.status: reviewed` needs a named reviewer, a date and evidence. Only the owner or a designated reviewer completes a review. An agent may record `reviewed` only to transcribe a review or decision that the owner or designated reviewer has published: the entry names that reviewer and the decision date, cites the decision URL as evidence, and its notes say that an agent transcribed it. Otherwise agents leave entries `pending`.
- Every component records one `distribution` value:
  - `included` or `candidate`: shipped from this repository inside the boundary, and gated here;
  - `excluded`: a runtime, source or model component that an owner decision keeps outside the current boundary. It needs an `exclusion_reason`;
  - `not-distributed`: never part of an OpenMettle distribution by its nature: build, CI and test tooling, and unadopted experiments. It needs an `exclusion_reason`;
  - `reviewed-elsewhere`: inside the boundary, but shipped and licence-reviewed by another OpenMettle repository. It needs `reviewed_in` naming that repository, belongs to a group with a completed owner disposition, and has no `exclusion_reason`. The core gate does not evaluate it.
- Use review status `blocked` for components whose licence is incompatible with the intended distribution.
- Give every component a `redistribution` assessment with a `basis`. It looks ahead to a wider boundary and is not a distribution decision:
  - `redistributable`: the register records a licence expression with evidence, and that licence permits redistribution under its conditions;
  - `user-fetched`: recorded licence evidence restricts redistribution, so a user would fetch the component. It cannot be shipped;
  - `undetermined`: everything else, including any component without recorded licence evidence.
- Models are not distributed by the project. The operator chooses the model a deployment serves and accepts its licence, so the register names no model and takes no position on model licence terms ([owner decision, 24 Nov 2026](https://github.com/OpenMettle/openmettle-core/issues/32#issuecomment-7132587306)). A fixture recorded from a model deployment states who recorded it, on whose deployment, and that the prompts were synthetic; it does not name the model.
- Use the neutral source aliases from `SOURCE-REFERENCES.md`. Do not add personal repository coordinates, site domains, LAN addresses or storage paths.
- A language translation of existing code is not automatically an independent implementation. Do not record translated Open WebUI code as first-party.

## Current state (19 November 2026, updated 24 November 2026)

- **Distribution boundary.** The owner defined it on 19 November 2026 ([decision](https://github.com/OpenMettle/openmettle-core/issues/32#issuecomment-7005620131)) and refined it the same day ([licence policy and reviews](https://github.com/OpenMettle/openmettle-core/issues/32#issuecomment-7006023083), [public forks](https://github.com/OpenMettle/openmettle-core/issues/32#issuecomment-7006271314), [openmettle-serving](https://github.com/OpenMettle/openmettle-core/issues/32#issuecomment-7008299248)):
  - distributed: the source code in the public OpenMettle repositories that are not forks, and the Helm chart in openmettle-deploy;
  - explicit exception: OpenMettle/openmettle-serving, a public non-fork repository of experimental ROCm/SGLang serving and benchmarking work, stays outside until serving packaging (V1-20) audits the serving stack, the same treatment as the SGLang fork;
  - not distributed yet: built container images (including the core api, worker and migrate images), re-hosted third-party images, curated forks and model weights. The public forks OpenMettle/sglang and OpenMettle/open-webui stay outside as public forks under their upstream licences. Third-party images are referenced only at their publishers' locations.

  The long-term direction is to distribute everything needed to run OpenMettle, eventually as an Arch Linux distribution with everything preinstalled except components whose licences do not allow redistribution. Each widening is a separate owner decision; publishing the core images (V1-36) is the likely next one. The register transcribes the boundary and the group dispositions from those comments. They are scope decisions, not licence reviews.

  **This register's gate covers openmettle-core's own source only.** Every other in-boundary repository, including the chart in openmettle-deploy and openmettle-acp, is reviewed in its own repository.
- **Outside the boundary.** The graphiti, database, sandbox, serving, media and application-fork groups are `excluded`. The serving group includes the serving-fork evidence repository, which is OpenMettle/openmettle-serving (its recorded pin was observed in that repository on 19 November 2026), so it is the boundary's explicit exception. Every component in them is `excluded` or `not-distributed` with a reason, as are the Debian runtime base image and the CI and test tooling in the core group. Their licence reviews remain pending and are needed before the boundary widens to include them.
- **Inside the boundary, reviewed here.** The core source (the `openmettle-core` workspace package, recorded as a Cargo review), the retained repository-template starter and the vendored OpenAPI 3.2 schemas are in-boundary and reviewed; the two components are `included`. Their notices are recorded. `LICENSE`, including its copyright line, is byte-identical to the template's LICENSE at the pinned revision. The vendored schemas keep their Apache-2.0 LICENSE and origin README. The owner reviewed all three and the core group disposition on 19 November 2026; an agent transcribed those reviews from the decision comment. They are reviews against policy, not legal clearance. The recorded SGLang responses in `tests/fixtures/sglang-recorded/` are also `included` (MIT): the owner recorded them on their own deployment with synthetic prompts and contributed them as test data under the project's licence. An agent transcribed the owner's 24 November 2026 decision; the SGLang fork commit that served them is not verified.
- **Inside the boundary, reviewed elsewhere.** `openmettle-acp` is `reviewed-elsewhere` in the `other-repositories` group: it is inside the boundary and its licence review lives in OpenMettle/openmettle-acp. This register records no licence review for it, and the gate does not evaluate it.
- **Public forks.** OpenMettle/sglang (a public GitHub fork of sgl-project/sglang, default branch `openmettle/rdna4`, root LICENSE Apache-2.0) and OpenMettle/open-webui stay outside the boundary as public forks under their upstream licences. The SGLang fork comes inside, with a full audit, when serving packaging (V1-20) ships it: a selected and pinned release revision, and an audit of its bundled third-party code (`3rdparty/` and the router, gateway and Rust sub-projects). The Open WebUI fork is reference material for the product OpenMettle replaces; it stays public, its licence adds a branding clause, and nothing from it is copied or translated into OpenMettle.
- **Redistribution assessment.** Each component records one. Only components with recorded licence evidence are `redistributable` or `user-fetched`. Neo4j Community is recorded as GPLv3, but its corresponding-source compliance review is not recorded, so it is `undetermined`. The Agent Sandbox controller, gVisor and HelixDB are `undetermined` too: no version is recorded, and the unpinned licence evidence is not a guarantee for future releases.
- **Rust packages.** All 352 non-workspace packages in `Cargo.lock` have generated policy records in `provenance/cargo-reviews.json`, and all 352 are `allowed` under the approved allow-list (checked in CI by `test_committed_policy_records_cover_the_lockfile_and_match_the_policy` and `review-cargo --check`). 14 of them declare Cargo's deprecated `/` form (`MIT/Apache-2.0` or `Apache-2.0/MIT`) and are recorded with their `OR` reading. `borrow-or-share` 0.2.4 declares `MIT-0`, which is on the list. The workspace package keeps its maintained owner review (MIT), which is also on the list.
- **Gate result.** Against the current lockfile (353 packages total: 1 workspace package plus 352 non-workspace entries in `provenance/cargo-reviews.json`) and fresh `cargo metadata`, the gate reports 0 blockers, for openmettle-core only, with boundary artefacts `source` and `helm-chart`. Without `cargo metadata` it reports 1 blocker: the declared crate licences are unverified. A pass is not a release approval: the owner still approves each release, and other in-boundary repositories are reviewed in their own repositories.
- **Observed read-only on 19 November 2026.** Both forks above are publicly visible GitHub forks that keep their upstream licences; neither is part of the OpenMettle distribution. Later that day the owner made every OpenMettle repository public, including openmettle-deploy, so the chart source is now published as the boundary intends. Track these through the publication tickets below.
- **Recorded on 24 November 2026.** Items that entered the repository after the register's last change on 19 November: the pinned Prometheus v3.5.0 and Grafana Alloy v1.10.0 test images used by the telemetry qualification (`not-distributed`, CI and test tooling; digests re-confirmed read-only from the registry, licence reviews pending). The recorded SGLang responses in `tests/fixtures/sglang-recorded/` (V1-08, #146) are committed in the public source tree, so they fall inside the boundary; they are `included` as owner-contributed test data under the owner decision above. The Keycloak 26.8.2 image in both Keycloak workflows is the digest already recorded. The crates added to `Cargo.lock` since then are covered by regenerated policy records. Host tools that tests call from the runner without a pin (for example GNU `tar`, `restic` in the artifact rebind tests, `openssl`, Docker and Chrome) are not recorded: the register records pinned or fetched tools only.
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
