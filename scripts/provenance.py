#!/usr/bin/env python3
"""Provenance inventory and fail-closed distribution-readiness gate (V1-42).

The inventory shows what is known; it does not clear anything for distribution.
`check-distribution` exits non-zero while any blocker remains. It reads Cargo.lock
on every run, so new Rust dependencies stay blocked until they have exact-version reviews.
Requires Python 3.11+ (tomllib). It uses only the standard library and makes no network calls.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = 1
REQUIRED_GROUPS = ("core", "graphiti", "database", "sandbox", "serving", "media", "application-fork")
KINDS = {"code", "asset", "model", "curated-fork", "container-image", "library", "service", "tooling"}
DISTRIBUTION = {"included", "candidate", "excluded", "not-distributed"}
SHIPPED = {"included", "candidate"}
REVIEW_STATUS = {"pending", "reviewed", "blocked"}
NOTICE_STATUS = {"pending", "recorded", "none-required"}
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


class InputError(Exception):
    """The register, lockfile or metadata cannot be trusted; treat as fail-closed."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_lock(path: Path) -> list[dict]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise InputError(f"{path.name}: cannot read lockfile: {exc}") from exc
    packages = data.get("package")
    if not isinstance(packages, list) or not packages:
        raise InputError(f"{path.name}: no [[package]] entries")
    result = []
    for pkg in packages:
        if not isinstance(pkg.get("name"), str) or not isinstance(pkg.get("version"), str):
            raise InputError(f"{path.name}: package entry without name/version")
        result.append({"name": pkg["name"], "version": pkg["version"],
                       "source": pkg.get("source"), "checksum": pkg.get("checksum")})
    return sorted(result, key=_pkg_key)


def _pkg_key(pkg: dict) -> tuple:
    return (pkg["name"], pkg["version"], pkg.get("source") or "")


def load_metadata(path: Path | None, lock: list[dict]) -> dict | None:
    """Return declared licence metadata keyed by package. It must describe the same package set as Cargo.lock."""
    if path is None:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        packages = data["packages"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise InputError(f"cargo metadata: unreadable: {exc}") from exc
    declared = {}
    for pkg in packages:
        source = pkg.get("source")
        key = (pkg["name"], pkg["version"], source or "")
        declared[key] = {"license": pkg.get("license"), "license_file": pkg.get("license_file"),
                         "repository": pkg.get("repository")}
    lock_keys = {_pkg_key(p) for p in lock}
    # Path (workspace) packages have no source in Cargo.lock; cargo metadata gives them none either.
    if set(declared) != lock_keys:
        missing = sorted(lock_keys - set(declared))
        extra = sorted(set(declared) - lock_keys)
        raise InputError(f"cargo metadata does not match Cargo.lock (missing {missing}, extra {extra})")
    return declared


def _need(obj: dict, field: str, where: str, errors: list[str], types) -> None:
    if field not in obj:
        errors.append(f"{where}: missing '{field}'")
    elif not isinstance(obj[field], types):
        errors.append(f"{where}: '{field}' has the wrong type")


def _validate_review(review, where, errors):
    if not isinstance(review, dict):
        errors.append(f"{where}: 'review' must be an object")
        return
    if review.get("status") not in REVIEW_STATUS:
        errors.append(f"{where}: review.status must be one of {sorted(REVIEW_STATUS)}")
    _need(review, "evidence", f"{where}.review", errors, list)
    _need(review, "notes", f"{where}.review", errors, str)
    if review.get("status") == "reviewed":
        if not review.get("reviewer"):
            errors.append(f"{where}: a reviewed entry needs a reviewer")
        if not isinstance(review.get("date"), str) or not DATE.fullmatch(review["date"]):
            errors.append(f"{where}: a reviewed entry needs a YYYY-MM-DD date")
        if not review.get("evidence"):
            errors.append(f"{where}: a reviewed entry needs evidence")


def _validate_licence_notices(entry, where, errors):
    licence, notices = entry.get("licence"), entry.get("notices")
    if not isinstance(licence, dict) or "expression" not in licence or not isinstance(licence.get("evidence"), list):
        errors.append(f"{where}: 'licence' needs 'expression' (string or null) and 'evidence' (list)")
    elif licence["expression"] is not None and not isinstance(licence["expression"], str):
        errors.append(f"{where}: licence.expression must be a string or null")
    if not isinstance(notices, dict) or notices.get("status") not in NOTICE_STATUS:
        errors.append(f"{where}: notices.status must be one of {sorted(NOTICE_STATUS)}")
    else:
        _need(notices, "files", f"{where}.notices", errors, list)
        _need(notices, "obligations", f"{where}.notices", errors, list)


def validate_register(register) -> list[str]:
    errors: list[str] = []
    if not isinstance(register, dict):
        return ["register: must be a JSON object"]
    if register.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"register: schema_version must be {SCHEMA_VERSION}")
    boundary = register.get("distribution_boundary")
    if not isinstance(boundary, dict) or boundary.get("status") not in {"defined", "undefined"}:
        errors.append("register: distribution_boundary.status must be 'defined' or 'undefined'")
    groups = register.get("review_groups")
    if not isinstance(groups, dict):
        errors.append("register: review_groups must be an object")
        groups = {}
    for name in REQUIRED_GROUPS:
        if name not in groups:
            errors.append(f"review_groups: required group '{name}' is missing")
    for name, group in groups.items():
        if not isinstance(group, dict) or group.get("status") not in {"pending", "reviewed"}:
            errors.append(f"review_groups.{name}: status must be 'pending' or 'reviewed'")
    seen = set()
    cargo_reviews = register.get("cargo_reviews")
    if not isinstance(cargo_reviews, list):
        errors.append("register: cargo_reviews must be a list")
        cargo_reviews = []
    for i, entry in enumerate(cargo_reviews):
        where = f"cargo_reviews[{i}]"
        if not isinstance(entry, dict):
            errors.append(f"{where}: must be an object")
            continue
        _need(entry, "name", where, errors, str)
        _need(entry, "version", where, errors, str)
        for field in ("source", "checksum"):
            if field not in entry or not (entry[field] is None or isinstance(entry[field], str)):
                errors.append(f"{where}: '{field}' must be present (string or null)")
        key = (entry.get("name"), entry.get("version"), entry.get("source") or "")
        if key in seen:
            errors.append(f"{where}: duplicate review for {key[0]} {key[1]}")
        seen.add(key)
        _validate_licence_notices(entry, where, errors)
        _validate_review(entry.get("review"), where, errors)
    components = register.get("components")
    if not isinstance(components, list):
        errors.append("register: components must be a list")
        components = []
    ids = set()
    for i, comp in enumerate(components):
        where = f"components[{i}]"
        if not isinstance(comp, dict):
            errors.append(f"{where}: must be an object")
            continue
        cid = comp.get("id")
        if not isinstance(cid, str) or not cid:
            errors.append(f"{where}: missing 'id'")
        elif cid in ids:
            errors.append(f"{where}: duplicate id '{cid}'")
        else:
            ids.add(cid)
            where = f"components.{cid}"
        _need(comp, "name", where, errors, str)
        if comp.get("kind") not in KINDS:
            errors.append(f"{where}: kind must be one of {sorted(KINDS)}")
        if comp.get("review_group") not in groups:
            errors.append(f"{where}: review_group '{comp.get('review_group')}' is not declared")
        if comp.get("distribution") not in DISTRIBUTION:
            errors.append(f"{where}: distribution must be one of {sorted(DISTRIBUTION)}")
        for field in ("version", "pin", "origin"):
            if field not in comp or not (comp[field] is None or isinstance(comp[field], str)):
                errors.append(f"{where}: '{field}' must be present (string or null)")
        _need(comp, "source_evidence", where, errors, list)
        _need(comp, "tracking", where, errors, list)
        _validate_licence_notices(comp, where, errors)
        _validate_review(comp.get("review"), where, errors)
        if comp.get("distribution") == "excluded" and not comp.get("exclusion_reason"):
            errors.append(f"{where}: excluded components need an exclusion_reason")
    return errors


def _readiness_blockers(entry, label, blockers):
    if not entry["licence"]["expression"]:
        blockers.append(f"{label}: licence not recorded")
    elif not entry["licence"]["evidence"]:
        blockers.append(f"{label}: licence has no source evidence")
    if entry["notices"]["status"] == "pending":
        blockers.append(f"{label}: notice obligations pending")
    status = entry["review"]["status"]
    if status == "blocked":
        blockers.append(f"{label}: review blocked ({entry['review']['notes']})")
    elif status != "reviewed":
        blockers.append(f"{label}: review {status}")


def evaluate(register: dict, lock: list[dict], metadata: dict | None) -> dict:
    """Build the inventory and readiness blockers. The register must already be valid."""
    blockers: list[str] = []
    warnings: list[str] = []
    if register["distribution_boundary"]["status"] != "defined":
        blockers.append("distribution boundary: undefined (owner decision required)")
    for name in REQUIRED_GROUPS:
        if register["review_groups"][name]["status"] != "reviewed":
            blockers.append(f"review group {name}: disposition pending")
    if metadata is None:
        blockers.append("cargo metadata: not supplied, so declared crate licences are unverified")

    reviews = {(r["name"], r["version"], r["source"] or ""): r for r in register["cargo_reviews"]}
    cargo = []
    for pkg in lock:
        key = _pkg_key(pkg)
        label = f"cargo {pkg['name']} {pkg['version']}"
        review = reviews.pop(key, None)
        declared = metadata.get(key) if metadata else None
        row = {**pkg, "declared_licence": declared["license"] if declared else None,
               "declared_licence_file": declared["license_file"] if declared else None,
               "repository": declared["repository"] if declared else None,
               "reviewed_licence": review["licence"]["expression"] if review else None,
               "review_status": review["review"]["status"] if review else "missing",
               "notices": review["notices"] if review else None}
        cargo.append(row)
        if review is None:
            blockers.append(f"{label}: no exact-version review record")
            continue
        if review["checksum"] != pkg["checksum"]:
            blockers.append(f"{label}: reviewed checksum does not match Cargo.lock")
        _readiness_blockers(review, label, blockers)
        if declared and declared["license"] != review["licence"]["expression"]:
            blockers.append(f"{label}: declared licence {declared['license']!r} differs from reviewed "
                            f"{review['licence']['expression']!r}")
        if declared and declared["license"] is None and declared["license_file"] is None:
            blockers.append(f"{label}: crate declares no licence")
    for key in sorted(reviews):
        warnings.append(f"cargo review for {key[0]} {key[1]} matches no Cargo.lock package (stale)")

    components = []
    for comp in sorted(register["components"], key=lambda c: c["id"]):
        components.append({k: comp[k] for k in ("id", "name", "kind", "review_group", "distribution",
                                                "version", "pin", "origin", "licence", "notices")}
                          | {"review_status": comp["review"]["status"],
                             "exclusion_reason": comp.get("exclusion_reason")})
        if comp["distribution"] not in SHIPPED:
            continue
        label = f"component {comp['id']}"
        if comp["distribution"] == "candidate":
            blockers.append(f"{label}: distribution decision pending (candidate)")
        for field in ("version", "pin", "origin"):
            if not comp[field]:
                blockers.append(f"{label}: {field} not recorded")
        _readiness_blockers(comp, label, blockers)

    return {
        "schema_version": SCHEMA_VERSION,
        "notice": "Inventory only. A successful inventory run is not distribution clearance or legal advice.",
        "distribution_ready": not blockers,
        "distribution_boundary": register["distribution_boundary"],
        "review_groups": {k: register["review_groups"][k] for k in sorted(register["review_groups"])},
        "cargo_packages": cargo,
        "components": components,
        "blockers": blockers,
        "warnings": warnings,
    }


def _row(*cells) -> str:
    return "| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in cells) + " |"


def render_notices(report: dict, inputs: dict) -> str:
    lines = ["# Notice and source obligations", "",
             "Generated by `scripts/provenance.py`. This is an inventory, not distribution clearance or legal advice.", "",
             f"- Distribution ready: **{'yes' if report['distribution_ready'] else 'no'}** "
             f"({len(report['blockers'])} blockers)",
             f"- Distribution boundary: {report['distribution_boundary']['status']}"]
    lines += [f"- Input `{name}` sha256: `{digest}`" for name, digest in sorted(inputs.items())]
    lines += ["", "## Rust packages (from Cargo.lock)", "",
              "| Package | Version | Source | Declared licence | Reviewed licence | Review | Notice files | Obligations |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for p in report["cargo_packages"]:
        notices = p["notices"] or {"files": [], "obligations": []}
        lines.append(_row(p["name"], p["version"], p["source"] or "workspace", p["declared_licence"] or "unknown",
                          p["reviewed_licence"] or "unknown", p["review_status"],
                          ", ".join(notices["files"]) or "—", " ".join(notices["obligations"]) or "—"))
    lines += ["", "## Components", "",
              "| Component | Group | Distribution | Version | Pin | Licence | Notices | Obligations | Review |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for c in report["components"]:
        lines.append(_row(c["id"], c["review_group"], c["distribution"], c["version"] or "unknown",
                          c["pin"] or "unknown", c["licence"]["expression"] or "unknown", c["notices"]["status"],
                          " ".join(c["notices"]["obligations"]) or "—", c["review_status"]))
    lines += ["", "## Blockers", ""] + [f"- {b}" for b in report["blockers"] or ["None."]]
    if report["warnings"]:
        lines += ["", "## Warnings", ""] + [f"- {w}" for w in report["warnings"]]
    return "\n".join(lines) + "\n"


def run(args) -> tuple[dict, dict]:
    root = Path(args.root).resolve()
    register_path = Path(args.register) if args.register else root / "provenance" / "register.json"
    lock_path = root / "Cargo.lock"
    try:
        register = json.loads(register_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InputError(f"register: unreadable: {exc}") from exc
    errors = validate_register(register)
    if errors:
        raise InputError("register invalid:\n  " + "\n  ".join(errors))
    lock = load_lock(lock_path)
    metadata_path = Path(args.cargo_metadata) if args.cargo_metadata else None
    metadata = load_metadata(metadata_path, lock)
    inputs = {"Cargo.lock": _sha256(lock_path), "register.json": _sha256(register_path)}
    report = evaluate(register, lock, metadata)
    report["inputs"] = dict(sorted(inputs.items()))
    report["cargo_metadata_supplied"] = metadata is not None
    return report, inputs


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("inventory", "check-distribution"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--root", default=str(ROOT), help="repository root containing Cargo.lock")
        cmd.add_argument("--register", help="register path (default: <root>/provenance/register.json)")
        cmd.add_argument("--cargo-metadata", help="output of `cargo metadata --locked --format-version 1`")
        if name == "inventory":
            cmd.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    try:
        report, inputs = run(args)
    except InputError as exc:
        print(f"provenance: {exc}", file=sys.stderr)
        return 2
    if args.command == "inventory":
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "dependency-inventory.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (out / "notice-obligations.md").write_text(render_notices(report, inputs), encoding="utf-8")
        print(f"Inventory written to {out} ({len(report['cargo_packages'])} Rust packages, "
              f"{len(report['components'])} components). Distribution ready: "
              f"{'yes' if report['distribution_ready'] else 'NO'} ({len(report['blockers'])} blockers). "
              "Inventory success is not distribution clearance.")
        return 0
    for warning in report["warnings"]:
        print(f"warning: {warning}", file=sys.stderr)
    if report["blockers"]:
        print(f"Distribution NOT ready: {len(report['blockers'])} blockers", file=sys.stderr)
        for blocker in report["blockers"]:
            print(f"  - {blocker}", file=sys.stderr)
        return 1
    print("Distribution readiness: no blockers in the recorded inventory. Owner release approval is still required.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
