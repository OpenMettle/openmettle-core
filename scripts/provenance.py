#!/usr/bin/env python3
"""Provenance inventory and fail-closed distribution-readiness gate (V1-42).

The inventory shows what is known; it does not clear anything for distribution.
`check-distribution` exits non-zero while any blocker remains. It reads Cargo.lock
on every run, so new Rust dependencies stay blocked until they have exact-version reviews.
`review-cargo` generates those records (provenance/cargo-reviews.json) by checking each package's
declared licence against the register's allow-list policy; the gate re-checks every record.
Requires Python 3.11+ (tomllib). It uses only the standard library and makes no network calls.
"""
from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path, PureWindowsPath

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = 1
REQUIRED_GROUPS = ("core", "graphiti", "database", "sandbox", "serving", "media", "application-fork")
KINDS = {"code", "asset", "model", "curated-fork", "container-image", "library", "service", "tooling"}
# "reviewed-elsewhere": inside the boundary, but shipped and licence-reviewed by another OpenMettle
# repository. This register covers openmettle-core's own source, so the core gate does not evaluate it.
DISTRIBUTION = {"included", "candidate", "excluded", "not-distributed", "reviewed-elsewhere"}
SHIPPED = {"included", "candidate"}
IN_BOUNDARY = SHIPPED | {"reviewed-elsewhere"}
GROUP_STATUS = {"pending", "reviewed", "excluded"}
# Forward-looking assessment for a wider future boundary. It is not a distribution decision.
REDISTRIBUTION = {"redistributable", "user-fetched", "undetermined"}
REVIEW_STATUS = {"pending", "reviewed", "blocked"}
NOTICE_STATUS = {"pending", "recorded", "none-required"}
# What the boundary distributes. Shipping an image or binary makes bundled crates shipped content.
ARTEFACTS = {"source", "helm-chart", "container-image", "binary"}
BUILT_ARTEFACTS = {"container-image", "binary"}
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
        if not isinstance(pkg, dict) or not _text(pkg.get("name")) or not _text(pkg.get("version")):
            raise InputError(f"{path.name}: package entry without name/version")
        for field in ("source", "checksum"):
            if pkg.get(field) is not None and not _text(pkg[field]):
                raise InputError(f"{path.name}: invalid package {field}")
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
    if not isinstance(packages, list):
        raise InputError("cargo metadata: packages must be a list")
    for pkg in packages:
        if not isinstance(pkg, dict) or not _text(pkg.get("name")) or not _text(pkg.get("version")):
            raise InputError("cargo metadata: invalid package name/version")
        for field in ("source", "license", "license_file", "repository"):
            if pkg.get(field) is not None and not _text(pkg[field]):
                raise InputError(f"cargo metadata: invalid package {field}")
        source = pkg.get("source")
        key = (pkg["name"], pkg["version"], source or "")
        if key in declared:
            raise InputError("cargo metadata: duplicate package")
        licence_file = pkg.get("license_file")
        if licence_file:
            # Cargo metadata can contain paths in the local registry or checkout.
            # Retain the notice filename, never the machine-specific prefix.
            if PureWindowsPath(licence_file).is_absolute():
                licence_file = PureWindowsPath(licence_file).name
            elif Path(licence_file).is_absolute() or ".." in Path(licence_file).parts:
                licence_file = Path(licence_file).name
        declared[key] = {"license": pkg.get("license"), "license_file": licence_file,
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
    elif types is str and not obj[field].strip():
        errors.append(f"{where}: '{field}' must not be blank")
    elif types is list and any(not isinstance(v, str) or not v.strip() for v in obj[field]):
        errors.append(f"{where}: '{field}' must contain nonblank strings")


def _text(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validate_review(review, where, errors):
    if not isinstance(review, dict):
        errors.append(f"{where}: 'review' must be an object")
        return
    if not isinstance(review.get("status"), str) or review["status"] not in REVIEW_STATUS:
        errors.append(f"{where}: review.status must be one of {sorted(REVIEW_STATUS)}")
    _need(review, "evidence", f"{where}.review", errors, list)
    _need(review, "notes", f"{where}.review", errors, str)
    if review.get("status") == "reviewed":
        if not _text(review.get("reviewer")):
            errors.append(f"{where}: a reviewed entry needs a reviewer")
        if not isinstance(review.get("date"), str) or not DATE.fullmatch(review["date"]):
            errors.append(f"{where}: a reviewed entry needs a YYYY-MM-DD date")
        else:
            try:
                date.fromisoformat(review["date"])
            except ValueError:
                errors.append(f"{where}: review date is not a valid calendar date")
        if not review.get("evidence"):
            errors.append(f"{where}: a reviewed entry needs evidence")


def _validate_licence_notices(entry, where, errors):
    licence, notices = entry.get("licence"), entry.get("notices")
    if not isinstance(licence, dict) or "expression" not in licence or not isinstance(licence.get("evidence"), list):
        errors.append(f"{where}: 'licence' needs 'expression' (string or null) and 'evidence' (list)")
    else:
        if licence["expression"] is not None and not _text(licence["expression"]):
            errors.append(f"{where}: licence.expression must be a nonblank string or null")
        _need(licence, "evidence", f"{where}.licence", errors, list)
    _validate_notices(notices, where, errors)


def _validate_notices(notices, where, errors):
    if (not isinstance(notices, dict) or not isinstance(notices.get("status"), str)
            or notices["status"] not in NOTICE_STATUS):
        errors.append(f"{where}: notices.status must be one of {sorted(NOTICE_STATUS)}")
    else:
        _need(notices, "files", f"{where}.notices", errors, list)
        _need(notices, "obligations", f"{where}.notices", errors, list)
        if notices["status"] == "recorded" and (not notices.get("files") or not notices.get("obligations")):
            errors.append(f"{where}: recorded notices need nonempty files and obligations")
        if notices["status"] == "none-required" and not _text(notices.get("justification")):
            errors.append(f"{where}: none-required notices need a justification")


class LicenceSyntaxError(ValueError):
    """A declared licence is not a valid SPDX expression."""


_LICENCE_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9.+:-]+)")
_LICENCE_TERM = re.compile(r"(?:DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+|[A-Za-z0-9.-]+\+?")
_OPERATORS = ("AND", "OR", "WITH")


def parse_licence(expression: str):
    """Parse an SPDX licence expression into ("or"|"and", [nodes]) and ("term", "<id>[ WITH <exception>]").

    Precedence follows SPDX: WITH binds tightest, then AND, then OR. Operators must be upper case.
    Anything else, including Cargo's deprecated "/" separator, is a syntax error (fail closed).
    licence_outcome rewrites a legacy Cargo "/" list with normalise_cargo_slash before calling this.
    """
    tokens, pos = [], 0
    while pos < len(expression):
        match = _LICENCE_TOKEN.match(expression, pos)
        if not match:
            if not expression[pos:].strip():
                break
            bad = expression[pos:].lstrip()[0]
            hint = " (Cargo's deprecated '/' separator)" if bad == "/" else ""
            raise LicenceSyntaxError(f"unexpected {bad!r}{hint}")
        tokens.append(match.group(1))
        pos = match.end()
    if not tokens:
        raise LicenceSyntaxError("empty expression")

    def term(i):
        if i >= len(tokens):
            raise LicenceSyntaxError("expression ends early")
        if tokens[i] == "(":
            node, i = either(i + 1)
            if i >= len(tokens) or tokens[i] != ")":
                raise LicenceSyntaxError("unbalanced parenthesis")
            return node, i + 1
        if tokens[i] in _OPERATORS or not _LICENCE_TERM.fullmatch(tokens[i]):
            raise LicenceSyntaxError(f"expected a licence identifier, found {tokens[i]!r}")
        name, i = tokens[i], i + 1
        if i < len(tokens) and tokens[i] == "WITH":
            if (i + 1 >= len(tokens) or tokens[i + 1] in _OPERATORS
                    or not re.fullmatch(r"[A-Za-z0-9.-]+", tokens[i + 1])):
                raise LicenceSyntaxError("WITH needs an exception identifier")
            name, i = f"{name} WITH {tokens[i + 1]}", i + 2
        return ("term", name), i

    def chain(i, operator, operand):
        node, i = operand(i)
        nodes = [node]
        while i < len(tokens) and tokens[i] == operator:
            node, i = operand(i + 1)
            nodes.append(node)
        return (operator.lower(), nodes) if len(nodes) > 1 else nodes[0], i

    def both(i):
        return chain(i, "AND", term)

    def either(i):
        return chain(i, "OR", both)

    node, i = either(0)
    if i != len(tokens):
        raise LicenceSyntaxError(f"unexpected {tokens[i]!r}")
    return node


def _allowed(node, allowed: set[str]) -> bool:
    kind, value = node
    if kind == "term":
        return value in allowed
    results = [_allowed(child, allowed) for child in value]
    return any(results) if kind == "or" else all(results)


def _terms(node) -> set[str]:
    kind, value = node
    return {value} if kind == "term" else set().union(*(_terms(child) for child in value))


_TOKEN_SPLIT = re.compile(r"[\s/]+")


def normalise_cargo_slash(expression: str) -> str | None:
    """Read Cargo's deprecated '/' licence separator as OR (owner decision, 19 Nov 2026).

    Applies to the Cargo `license` field only, before SPDX evaluation. SPDX identifiers and
    expressions cannot contain '/', so a valid SPDX expression never reaches the rewrite.
    Returns None when the expression has no '/'. Otherwise the expression must be a plain list
    of single licence identifiers, such as 'MIT/Apache-2.0', which becomes 'MIT OR Apache-2.0'.
    A '/' mixed with SPDX operators (in any case) or parentheses is refused as ambiguous: the
    tool does not guess how '/' groups against AND, OR or WITH. An operator is a whole token
    between whitespace or '/', so '-or-later' inside 'GPL-2.0-or-later' is not one.
    """
    if "/" not in expression:
        return None
    if (any(token.upper() in _OPERATORS for token in _TOKEN_SPLIT.split(expression))
            or "(" in expression or ")" in expression):
        raise LicenceSyntaxError("Cargo's deprecated '/' separator is mixed with SPDX operators or "
                                 "parentheses; refused as ambiguous")
    parts = [part.strip() for part in expression.split("/")]
    if any(not _LICENCE_TERM.fullmatch(part) for part in parts):
        raise LicenceSyntaxError("Cargo's deprecated '/' separator must separate single licence identifiers")
    return " OR ".join(parts)


def licence_outcome(expression: str | None, licence_file: str | None,
                    allowed: set[str]) -> tuple[str, str | None, str | None]:
    """Check a Cargo package's declared licence against the allow-list.

    An OR passes if any branch passes; an AND needs all parts. Returns (outcome, reason, slash_as_or),
    where slash_as_or is the SPDX expression evaluated in place of a legacy '/' form, or None.
    """
    if expression is None:
        detail = f"; it names only the licence file {licence_file!r}" if licence_file else ""
        return "blocked", f"declares no SPDX licence expression{detail}", None
    try:
        slash_as_or = normalise_cargo_slash(expression)
        node = parse_licence(slash_as_or or expression)
    except LicenceSyntaxError as exc:
        return "blocked", f"licence {expression!r} is not a valid SPDX expression: {exc}", None
    if _allowed(node, allowed):
        return "allowed", None, slash_as_or
    outside = ", ".join(sorted(_terms(node) - allowed))
    return "blocked", f"licence {expression!r} is outside the allow-list ({outside} not allowed)", slash_as_or


def _validate_policy(policy, errors):
    where = "cargo_licence_policy"
    if not isinstance(policy, dict):
        errors.append(f"register: {where} must be an object")
        return
    _need(policy, "scope", where, errors, str)
    _need(policy, "allowed_licences", where, errors, list)
    allowed = policy.get("allowed_licences")
    if isinstance(allowed, list) and all(_text(v) for v in allowed):
        if not allowed:
            errors.append(f"{where}: allowed_licences must not be empty")
        if len(set(allowed)) != len(allowed):
            errors.append(f"{where}: allowed_licences contains duplicates")
        for value in allowed:
            try:
                node = parse_licence(value)
            except LicenceSyntaxError as exc:
                errors.append(f"{where}: {value!r} is not a valid SPDX term: {exc}")
                continue
            if node[0] != "term":
                errors.append(f"{where}: {value!r} must be one licence identifier, not an expression")
    _validate_notices(policy.get("notices"), where, errors)
    _validate_review(policy.get("review"), where, errors)


def validate_register(register) -> list[str]:
    errors: list[str] = []
    if not isinstance(register, dict):
        return ["register: must be a JSON object"]
    if register.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"register: schema_version must be {SCHEMA_VERSION}")
    boundary = register.get("distribution_boundary")
    if not isinstance(boundary, dict) or boundary.get("status") not in ("defined", "undefined"):
        errors.append("register: distribution_boundary.status must be 'defined' or 'undefined'")
    elif boundary["status"] == "defined":
        _need(boundary, "description", "distribution_boundary", errors, str)
        _validate_review(boundary.get("review"), "distribution_boundary", errors)
        if not isinstance(boundary.get("review"), dict) or boundary["review"].get("status") != "reviewed":
            errors.append("distribution_boundary: defined boundary needs a completed decision review")
        artefacts = boundary.get("artefacts")
        if (not isinstance(artefacts, list) or not artefacts
                or any(not isinstance(a, str) or a not in ARTEFACTS for a in artefacts)
                or len(set(artefacts)) != len(artefacts)):
            errors.append(f"distribution_boundary: defined boundary needs 'artefacts', a nonempty list of "
                          f"distinct values from {sorted(ARTEFACTS)}")
    groups = register.get("review_groups")
    if not isinstance(groups, dict):
        errors.append("register: review_groups must be an object")
        groups = {}
    for name in REQUIRED_GROUPS:
        if name not in groups:
            errors.append(f"review_groups: required group '{name}' is missing")
    for name, group in groups.items():
        if not isinstance(group, dict) or group.get("status") not in GROUP_STATUS:
            errors.append(f"review_groups.{name}: status must be one of {sorted(GROUP_STATUS)}")
        elif group["status"] in ("reviewed", "excluded"):
            _need(group, "summary", f"review_groups.{name}", errors, str)
            if group["status"] == "excluded":
                # An excluded group is outside the recorded boundary; the reason and the decision
                # review replace a licence review, so both must be present.
                _need(group, "exclusion_reason", f"review_groups.{name}", errors, str)
            _validate_review(group.get("review"), f"review_groups.{name}", errors)
            if not isinstance(group.get("review"), dict) or group["review"].get("status") != "reviewed":
                errors.append(f"review_groups.{name}: {group['status']} disposition needs a completed decision review")
    _validate_policy(register.get("cargo_licence_policy"), errors)
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
            if field not in entry or not (entry[field] is None or _text(entry[field])):
                errors.append(f"{where}: '{field}' must be present (string or null)")
        if not all(_text(entry.get(k)) for k in ("name", "version")) or not (
                entry.get("source") is None or _text(entry.get("source"))):
            continue
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
        if not _text(cid):
            errors.append(f"{where}: missing 'id'")
        elif cid in ids:
            errors.append(f"{where}: duplicate id '{cid}'")
        else:
            ids.add(cid)
            where = f"components.{cid}"
        _need(comp, "name", where, errors, str)
        if not isinstance(comp.get("kind"), str) or comp["kind"] not in KINDS:
            errors.append(f"{where}: kind must be one of {sorted(KINDS)}")
        if not isinstance(comp.get("review_group"), str) or comp["review_group"] not in groups:
            errors.append(f"{where}: review_group '{comp.get('review_group')}' is not declared")
        if not isinstance(comp.get("distribution"), str) or comp["distribution"] not in DISTRIBUTION:
            errors.append(f"{where}: distribution must be one of {sorted(DISTRIBUTION)}")
        for field in ("version", "pin", "origin"):
            if field not in comp or not (comp[field] is None or _text(comp[field])):
                errors.append(f"{where}: '{field}' must be present (string or null)")
        _need(comp, "source_evidence", where, errors, list)
        _need(comp, "tracking", where, errors, list)
        _validate_licence_notices(comp, where, errors)
        _validate_review(comp.get("review"), where, errors)
        _validate_redistribution(comp, where, errors)
        if comp.get("distribution") in ("excluded", "not-distributed") and not _text(comp.get("exclusion_reason")):
            errors.append(f"{where}: {comp['distribution']} components need an exclusion_reason")
        group = groups.get(comp.get("review_group")) if isinstance(comp.get("review_group"), str) else None
        if (isinstance(group, dict) and group.get("status") == "excluded"
                and comp.get("distribution") in IN_BOUNDARY):
            errors.append(f"{where}: an in-boundary component cannot belong to excluded group '{comp['review_group']}'")
        if comp.get("distribution") == "reviewed-elsewhere":
            # The owner's group disposition is the only record here; the licence review lives in reviewed_in.
            if not _text(comp.get("reviewed_in")):
                errors.append(f"{where}: reviewed-elsewhere components need 'reviewed_in' naming the reviewing repository")
            if comp.get("exclusion_reason") is not None:
                errors.append(f"{where}: an in-boundary component cannot have an exclusion_reason")
            if isinstance(group, dict) and group.get("status") != "reviewed":
                errors.append(f"{where}: reviewed-elsewhere components need a group with a completed owner disposition")
    return errors


def _validate_redistribution(comp, where, errors):
    """The assessment may only go beyond 'undetermined' when the register holds licence evidence."""
    assessment = comp.get("redistribution")
    if (not isinstance(assessment, dict) or not isinstance(assessment.get("assessment"), str)
            or assessment["assessment"] not in REDISTRIBUTION):
        errors.append(f"{where}: redistribution.assessment must be one of {sorted(REDISTRIBUTION)}")
        return
    _need(assessment, "basis", f"{where}.redistribution", errors, str)
    licence = comp.get("licence") if isinstance(comp.get("licence"), dict) else {}
    evidence = licence.get("evidence") if isinstance(licence.get("evidence"), list) else []
    if assessment["assessment"] == "redistributable" and not (_text(licence.get("expression")) and evidence):
        errors.append(f"{where}: 'redistributable' needs a recorded licence expression with evidence")
    if assessment["assessment"] == "user-fetched" and not evidence:
        errors.append(f"{where}: 'user-fetched' needs licence evidence that restricts redistribution")
    if assessment["assessment"] == "user-fetched" and comp.get("distribution") in SHIPPED:
        errors.append(f"{where}: a component recorded as user-fetched cannot be shipped")


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


def _allow_list_blocker(entry, label, allowed, blockers):
    """Maintained reviews and shipped components meet the same owner-approved allow-list as policy records.

    There is no per-package exception: the owner has granted none.
    """
    if entry["licence"]["expression"]:
        outcome, reason, _ = licence_outcome(entry["licence"]["expression"], None, allowed)
        if outcome != "allowed":
            blockers.append(f"{label}: {reason}")


def evaluate(register: dict, lock: list[dict], metadata: dict | None, records: list[dict] = ()) -> dict:
    """Build the inventory and readiness blockers. The register must already be valid."""
    blockers: list[str] = []
    warnings: list[str] = []
    if register["distribution_boundary"]["status"] != "defined":
        blockers.append("distribution boundary: undefined (owner decision required)")
    for name in REQUIRED_GROUPS:
        # Excluded groups are outside the recorded boundary; validation already required their reason.
        if register["review_groups"][name]["status"] not in ("reviewed", "excluded"):
            blockers.append(f"review group {name}: disposition pending")
    if metadata is None:
        blockers.append("cargo metadata: not supplied, so declared crate licences are unverified")

    reviews = {(r["name"], r["version"], r["source"] or ""): r for r in register["cargo_reviews"]}
    records = {_pkg_key(r): r for r in records}
    policy = register["cargo_licence_policy"]
    allowed = set(policy["allowed_licences"])
    policy_packages = 0
    cargo = []
    for pkg in lock:
        key = _pkg_key(pkg)
        label = f"cargo {pkg['name']} {pkg['version']}"
        review = reviews.pop(key, None)
        record = records.pop(key, None)
        declared = metadata.get(key) if metadata else None
        row = {**pkg, "declared_licence": declared["license"] if declared else None,
               "declared_licence_file": declared["license_file"] if declared else None,
               "repository": declared["repository"] if declared else None,
               "reviewed_licence": review["licence"]["expression"] if review else None,
               "review_status": review["review"]["status"] if review else "missing",
               "notices": review["notices"] if review else None, "slash_as_or": None}
        cargo.append(row)
        if review is None and pkg["source"] is None:
            # Path (workspace) packages are our own source: they need a maintained, owner-reviewed entry.
            what = "a generated policy record is refused" if record is not None else "none is recorded"
            blockers.append(f"{label}: path package needs a maintained review in cargo_reviews ({what})")
            continue
        if review is None and record is not None:
            # Generated record: re-check it against Cargo.lock, the declared metadata and the
            # current policy, so a stale or hand-edited record cannot pass.
            policy_packages += 1
            outcome, reason, slash_as_or = licence_outcome(record["declared_licence"],
                                                           record["declared_licence_file"], allowed)
            row |= {"reviewed_licence": record["declared_licence"], "review_status": f"policy-{outcome}",
                    "notices": policy["notices"], "slash_as_or": slash_as_or}
            if record["checksum"] != pkg["checksum"]:
                blockers.append(f"{label}: recorded checksum does not match Cargo.lock")
            if declared and (declared["license"], declared["license_file"]) != (
                    record["declared_licence"], record["declared_licence_file"]):
                blockers.append(f"{label}: declared licence {declared['license']!r} differs from recorded "
                                f"{record['declared_licence']!r} (regenerate the records)")
            if (record["outcome"], record["reason"]) != (outcome, reason):
                blockers.append(f"{label}: recorded outcome {record['outcome']!r} differs from the current "
                                f"policy result {outcome!r} (regenerate the records)")
            if record.get("slash_as_or") != slash_as_or:
                blockers.append(f"{label}: recorded slash_as_or {record.get('slash_as_or')!r} differs from the "
                                f"current reading {slash_as_or!r} (regenerate the records)")
            if outcome != "allowed":
                blockers.append(f"{label}: {reason}")
            continue
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
        _allow_list_blocker(review, label, allowed, blockers)
    for key in sorted(reviews):
        warnings.append(f"cargo review for {key[0]} {key[1]} matches no Cargo.lock package (stale)")
    for key in sorted(records):
        warnings.append(f"cargo policy record for {key[0]} {key[1]} matches no Cargo.lock package (stale)")
    if policy_packages:
        # Records are only as good as the policy: it needs the owner's completed review.
        if policy["review"]["status"] != "reviewed":
            blockers.append(f"cargo licence policy: owner approval {policy['review']['status']} "
                            f"({policy_packages} packages are reviewed against it)")
        if policy["notices"]["status"] == "pending":
            blockers.append("cargo licence policy: notice obligations pending")
        built = sorted(BUILT_ARTEFACTS & set(register["distribution_boundary"].get("artefacts") or []))
        if policy["notices"]["status"] == "none-required" and built:
            # 'none-required' rests on crates being build inputs only; shipping images or binaries ends that.
            blockers.append(f"cargo licence policy: notices are 'none-required' but the boundary distributes "
                            f"{', '.join(built)}; record the crates' notice obligations")

    components = []
    for comp in sorted(register["components"], key=lambda c: c["id"]):
        components.append({k: comp[k] for k in ("id", "name", "kind", "review_group", "distribution",
                                                "version", "pin", "origin", "licence", "notices")}
                          | {"review_status": comp["review"]["status"],
                             "exclusion_reason": comp.get("exclusion_reason"),
                             "reviewed_in": comp.get("reviewed_in"),
                             "redistribution": comp["redistribution"]})
        if comp["distribution"] not in SHIPPED:
            continue
        label = f"component {comp['id']}"
        if comp["distribution"] == "candidate":
            blockers.append(f"{label}: distribution decision pending (candidate)")
        for field in ("version", "pin", "origin"):
            if not comp[field]:
                blockers.append(f"{label}: {field} not recorded")
        _readiness_blockers(comp, label, blockers)
        _allow_list_blocker(comp, label, allowed, blockers)

    return {
        "schema_version": SCHEMA_VERSION,
        "notice": "Inventory only. A successful inventory run is not distribution clearance or legal advice.",
        "distribution_ready": not blockers,
        "distribution_boundary": register["distribution_boundary"],
        "review_groups": {k: register["review_groups"][k] for k in sorted(register["review_groups"])},
        "cargo_licence_policy": policy,
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
             f"- Distribution boundary: {report['distribution_boundary']['status']}"
             + (f" — {report['distribution_boundary']['description']}"
                if report["distribution_boundary"]["status"] == "defined" else "")]
    if report["distribution_boundary"]["status"] == "defined":
        lines.append(f"- Boundary artefacts: {', '.join(report['distribution_boundary']['artefacts'])}. "
                     "This report covers openmettle-core only.")
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
              "| Component | Group | Distribution | Version | Pin | Licence | Notices | Obligations | Review "
              "| Later redistribution |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for c in report["components"]:
        distribution = c["distribution"] + (f" ({c['reviewed_in']})" if c["reviewed_in"] else "")
        lines.append(_row(c["id"], c["review_group"], distribution, c["version"] or "unknown",
                          c["pin"] or "unknown", c["licence"]["expression"] or "unknown", c["notices"]["status"],
                          " ".join(c["notices"]["obligations"]) or "—", c["review_status"],
                          c["redistribution"]["assessment"]))
    lines += ["", "## Blockers", ""] + [f"- {b}" for b in report["blockers"] or ["None."]]
    if report["warnings"]:
        lines += ["", "## Warnings", ""] + [f"- {w}" for w in report["warnings"]]
    return "\n".join(lines) + "\n"


RECORDS_FILE = "cargo-reviews.json"
RECORD_OUTCOMES = {"allowed", "blocked"}
RECORD_KEYS = ("name", "version", "source", "checksum", "declared_licence", "declared_licence_file",
               "outcome", "reason", "slash_as_or")
RECORDS_HEADER = {
    "generated_by": "python3 scripts/provenance.py review-cargo --cargo-metadata <cargo metadata JSON>",
    "notice": ("Generated; do not edit. Each record pins a Cargo.lock package to its declared licence and the "
               "outcome against cargo_licence_policy in register.json. slash_as_or is set when the declared "
               "licence uses Cargo's deprecated '/' separator: it is the SPDX expression evaluated instead, with '/' "
               "read as OR. Reviewed against policy; not legal clearance."),
}


def load_records(path: Path) -> list[dict]:
    """Load generated policy records. A missing file means no records, so every package blocks."""
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        packages = data["packages"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise InputError(f"{path.name}: unreadable: {exc}") from exc
    if not isinstance(packages, list):
        raise InputError(f"{path.name}: packages must be a list")
    seen = set()
    for i, rec in enumerate(packages):
        where = f"{path.name} packages[{i}]"
        if not isinstance(rec, dict):
            raise InputError(f"{where}: must be an object")
        missing = [field for field in RECORD_KEYS if field not in rec]
        if missing:
            raise InputError(f"{where}: missing {', '.join(repr(f) for f in missing)}; regenerate with review-cargo")
        if not _text(rec["name"]) or not _text(rec["version"]):
            raise InputError(f"{where}: needs a name and version")
        for field in ("source", "checksum", "declared_licence", "declared_licence_file", "reason", "slash_as_or"):
            if rec.get(field) is not None and not _text(rec[field]):
                raise InputError(f"{where}: '{field}' must be a nonblank string or null")
        if (not isinstance(rec.get("outcome"), str) or rec["outcome"] not in RECORD_OUTCOMES
                or (rec["outcome"] == "blocked") != _text(rec.get("reason"))):
            raise InputError(f"{where}: outcome must be 'allowed' (no reason) or 'blocked' (with a reason)")
        key = _pkg_key(rec)
        if key in seen:
            raise InputError(f"{where}: duplicate record for {key[0]} {key[1]}")
        seen.add(key)
    return packages


def generate_records(register: dict, lock: list[dict], metadata: dict) -> list[dict]:
    """One record per registry or git package without a maintained review, in lockfile order.

    Path (workspace) packages never get a generated record: they need a maintained review.
    """
    maintained = {(r["name"], r["version"], r["source"] or "") for r in register["cargo_reviews"]}
    allowed = set(register["cargo_licence_policy"]["allowed_licences"])
    records = []
    for pkg in lock:
        key = _pkg_key(pkg)
        if key in maintained or pkg["source"] is None:
            continue
        declared = metadata[key]
        outcome, reason, slash_as_or = licence_outcome(declared["license"], declared["license_file"], allowed)
        records.append({"name": pkg["name"], "version": pkg["version"], "source": pkg["source"],
                        "checksum": pkg["checksum"], "declared_licence": declared["license"],
                        "declared_licence_file": declared["license_file"], "outcome": outcome, "reason": reason,
                        "slash_as_or": slash_as_or})
    return records


def render_records(records: list[dict]) -> str:
    """Stable JSON with one record per line, so a lockfile change shows as a readable diff."""
    lines = ["{"] + [f"  {json.dumps(k)}: {json.dumps(v, ensure_ascii=False)}," for k, v in RECORDS_HEADER.items()]
    lines.append('  "packages": [')
    lines += [f"    {json.dumps(r, sort_keys=True, ensure_ascii=False)}{',' if i < len(records) - 1 else ''}"
              for i, r in enumerate(records)]
    return "\n".join(lines + ["  ]", "}"]) + "\n"


def _load_inputs(args):
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
    # Generated records sit beside the maintained register, never inside it.
    return register, register_path, lock, lock_path, metadata, register_path.parent / RECORDS_FILE


def run(args) -> tuple[dict, dict]:
    register, register_path, lock, lock_path, metadata, records_path = _load_inputs(args)
    records = load_records(records_path)
    overlap = {_pkg_key(r) for r in records} & {(r["name"], r["version"], r["source"] or "")
                                                 for r in register["cargo_reviews"]}
    if overlap:
        names = ", ".join(f"{k[0]} {k[1]}" for k in sorted(overlap))
        raise InputError(f"{RECORDS_FILE}: packages with a maintained review must not also have a record: {names}")
    inputs = {"Cargo.lock": _sha256(lock_path), "register.json": _sha256(register_path)}
    if records_path.exists():
        inputs[RECORDS_FILE] = _sha256(records_path)
    report = evaluate(register, lock, metadata, records)
    report["inputs"] = dict(sorted(inputs.items()))
    report["cargo_metadata_supplied"] = metadata is not None
    return report, inputs


def review_cargo(args) -> int:
    register, _, lock, _, metadata, records_path = _load_inputs(args)
    text = render_records(generate_records(register, lock, metadata))
    current = records_path.read_text(encoding="utf-8") if records_path.exists() else None
    if args.check:
        if current != text:
            print(f"{records_path.name} is out of date; run review-cargo and review the diff", file=sys.stderr)
            return 1
        print(f"{records_path.name} matches Cargo.lock, the declared metadata and the policy.")
        return 0
    records_path.write_text(text, encoding="utf-8")
    print(f"Wrote {records_path.name}. Records are reviewed against policy, not cleared.")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("inventory", "check-distribution", "review-cargo"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--root", default=str(ROOT), help="repository root containing Cargo.lock")
        cmd.add_argument("--register", help="register path (default: <root>/provenance/register.json); "
                         f"generated records live beside it in {RECORDS_FILE}")
        cmd.add_argument("--cargo-metadata", required=name == "review-cargo",
                         help="output of `cargo metadata --locked --format-version 1`")
        if name == "inventory":
            cmd.add_argument("--output-dir", required=True)
        if name == "review-cargo":
            cmd.add_argument("--check", action="store_true",
                             help=f"exit 1 if {RECORDS_FILE} differs from a fresh generation; write nothing")
    args = parser.parse_args(argv)
    try:
        if args.command == "review-cargo":
            return review_cargo(args)
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
    artefacts = ", ".join(report["distribution_boundary"].get("artefacts") or [])
    print(f"Distribution readiness: no blockers in the recorded inventory for openmettle-core only "
          f"(boundary artefacts: {artefacts}). Other in-boundary repositories are reviewed in their own "
          "repositories. Owner release approval is still required.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
