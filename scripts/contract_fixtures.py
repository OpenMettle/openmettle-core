#!/usr/bin/env python3
"""Generate API contract fixtures from the canonical OpenAPI document (ADR 0007).

Standard library only. Fixtures are derived from Example Objects in
components.examples that carry x-openmettle-fixture, plus deterministic
mutations: declared mutations and, for object-valued response examples, an
unknown root field (compatible) and the removal of each root-required property
(invalid). Validation happens in tests/contract.rs with a real JSON Schema
2020-12 validator; this script never decides validity itself.

    python3 scripts/contract_fixtures.py           # rewrite contracts/fixtures
    python3 scripts/contract_fixtures.py --check   # fail if fixtures are stale
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "contracts" / "openapi" / "openmettle-v1.json"
OUTPUT = ROOT / "contracts" / "fixtures"
CLASSES = ("valid", "compat", "invalid")
DIRECTIONS = ("response", "request", "value")
UNKNOWN_FIELD = "x_contract_future_field"
GENERATED_BY = "scripts/contract_fixtures.py"


class FixtureError(Exception):
    pass


def _tokens(pointer: str) -> list[str]:
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise FixtureError(f"invalid JSON pointer {pointer!r}")
    return [t.replace("~1", "/").replace("~0", "~") for t in pointer[1:].split("/")]


def resolve(document, pointer: str):
    """Resolve a local '#/...' reference or a bare JSON pointer."""
    if pointer.startswith("#"):
        pointer = pointer[1:]
    node = document
    for token in _tokens(pointer):
        if isinstance(node, list):
            if not token.isdigit() or int(token) >= len(node):
                raise FixtureError(f"pointer {pointer!r} does not resolve")
            node = node[int(token)]
        elif isinstance(node, dict) and token in node:
            node = node[token]
        else:
            raise FixtureError(f"pointer {pointer!r} does not resolve")
    return node


def _schema(document, pointer: str) -> dict:
    """Follow local $ref chains at the root of a schema."""
    seen = set()
    node = resolve(document, pointer)
    while isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if not ref.startswith("#/") or ref in seen:
            raise FixtureError(f"unsupported or cyclic $ref {ref!r}")
        seen.add(ref)
        node = resolve(document, ref)
    if not isinstance(node, dict):
        raise FixtureError(f"{pointer} is not a schema object")
    return node


def _apply(value, pointer: str, op: str, new=None):
    tokens = _tokens(pointer)
    if not tokens:
        if op != "set":
            raise FixtureError("only set may target the document root")
        return copy.deepcopy(new)
    result = copy.deepcopy(value)
    parent = resolve(result, "/" + "/".join(t.replace("~", "~0").replace("/", "~1") for t in tokens[:-1]) if len(tokens) > 1 else "")
    last = tokens[-1]
    if isinstance(parent, dict):
        if op == "remove":
            if last not in parent:
                raise FixtureError(f"cannot remove missing {pointer}")
            del parent[last]
        else:
            parent[last] = copy.deepcopy(new)
    elif isinstance(parent, list) and last.isdigit() and int(last) < len(parent):
        if op == "remove":
            del parent[int(last)]
        else:
            parent[int(last)] = copy.deepcopy(new)
    else:
        raise FixtureError(f"pointer {pointer} does not resolve")
    return result


def _encode_content(value) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def mutate(instance, mutation: dict):
    op = mutation.get("op")
    if op not in ("set", "remove"):
        raise FixtureError(f"unsupported mutation op {op!r}")
    if "repeat" in mutation:
        unit, count = mutation["repeat"]
        if not isinstance(unit, str) or not isinstance(count, int) or count < 0:
            raise FixtureError("repeat must be [string, nonnegative count]")
        new = unit * count
    else:
        new = mutation.get("value")
    if op == "set" and "repeat" not in mutation and "value" not in mutation:
        raise FixtureError("set requires value or repeat")
    path = mutation.get("path")
    if not isinstance(path, str):
        raise FixtureError("mutation path must be a string")
    if "#" in path:
        outer, inner = path.split("#", 1)
        encoded = resolve(instance, outer)
        if not isinstance(encoded, str):
            raise FixtureError(f"{outer} does not hold encoded JSON")
        content = _apply(json.loads(encoded), inner, op, new)
        return _apply(instance, outer, "set", _encode_content(content))
    return _apply(instance, path, op, new)


def _expectation(mutation: dict, cls: str):
    expect = mutation.get("expect")
    if cls == "invalid":
        if not isinstance(expect, dict) or not expect:
            raise FixtureError(f"invalid mutation {mutation.get('name')!r} needs expect")
        if not expect.get("decode") and ("instancePath" not in expect or "keyword" not in expect):
            raise FixtureError(f"mutation {mutation.get('name')!r} needs instancePath and keyword")
        return {"valid": False, **expect}
    if expect is not None:
        raise FixtureError(f"{cls} mutation {mutation.get('name')!r} must not declare expect")
    return {"valid": True}


def _fixture(name, cls, schema, source, direction, mutation, expect, instance):
    return {
        "generated_by": GENERATED_BY,
        "fixture": name,
        "class": cls,
        "schema": schema,
        "direction": direction,
        "source": source,
        "mutation": mutation,
        "expect": expect,
        "instance": instance,
    }


def generate(document) -> dict[str, dict]:
    """Return {relative path: fixture} for every fixture."""
    out: dict[str, dict] = {}

    def add(fixture):
        path = f"{fixture['class']}/{fixture['fixture']}.json"
        if path in out:
            raise FixtureError(f"duplicate fixture {path}")
        out[path] = fixture

    examples = document.get("components", {}).get("examples", {})
    for example_name in sorted(examples):
        example = examples[example_name]
        meta = example.get("x-openmettle-fixture")
        if meta is None:
            continue
        if "dataValue" not in example:
            raise FixtureError(f"{example_name}: fixture examples need dataValue")
        schema, direction = meta.get("schema"), meta.get("direction")
        if not isinstance(schema, str) or not schema.startswith("#/"):
            raise FixtureError(f"{example_name}: schema must be a local pointer")
        if direction not in DIRECTIONS:
            raise FixtureError(f"{example_name}: direction must be one of {DIRECTIONS}")
        root = _schema(document, schema)
        source = f"#/components/examples/{example_name}"
        base = example["dataValue"]
        add(_fixture(example_name, "valid", schema, source, direction, None, {"valid": True}, base))

        if direction != "value" and isinstance(base, dict):
            extended = copy.deepcopy(base)
            if UNKNOWN_FIELD in extended:
                raise FixtureError(f"{example_name} already uses {UNKNOWN_FIELD}")
            extended[UNKNOWN_FIELD] = {"added_in": "1.999"}
            if direction == "response":
                cls, expect = "compat", {"valid": True}
            else:
                cls, expect = "invalid", {"valid": False, "instancePath": "", "keyword": "additionalProperties"}
            mutation = {"name": "auto-unknown-root-field", "op": "set", "path": f"/{UNKNOWN_FIELD}"}
            add(_fixture(f"{example_name}--auto-unknown-root-field", cls, schema, source, direction,
                         mutation, expect, extended))
            for required in root.get("required", []):
                if required not in base:
                    raise FixtureError(f"{example_name}: example lacks required {required}")
                mutation = {"name": f"auto-missing-{required}", "op": "remove", "path": f"/{required}"}
                add(_fixture(f"{example_name}--auto-missing-{required}", "invalid", schema, source,
                             direction, mutation,
                             {"valid": False, "instancePath": "", "keyword": "required"},
                             mutate(base, mutation)))

        for mutation in meta.get("mutations", []):
            name, cls = mutation.get("name"), mutation.get("class")
            if not isinstance(name, str) or not name or not all(c.isalnum() or c == "-" for c in name):
                raise FixtureError(f"{example_name}: mutation names use letters, digits and '-'")
            if cls not in CLASSES:
                raise FixtureError(f"{example_name}/{name}: class must be one of {CLASSES}")
            expect = _expectation(mutation, cls)
            recorded = {k: mutation[k] for k in ("name", "op", "path", "value", "repeat") if k in mutation}
            add(_fixture(f"{example_name}--{name}", cls, schema, source, direction, recorded, expect,
                         mutate(base, mutation)))
    return out


def render(fixture) -> str:
    return json.dumps(fixture, ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="report stale fixtures without writing")
    parser.add_argument("--document", type=Path, default=DOCUMENT)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.document.read_text(encoding="utf-8"))
        expected = {path: render(f) for path, f in generate(document).items()}
    except (OSError, ValueError, FixtureError) as error:
        print(f"contract fixtures: {error}", file=sys.stderr)
        return 2
    existing = {
        p.relative_to(args.output).as_posix(): p
        for p in sorted(args.output.rglob("*.json")) if p.is_file()
    } if args.output.exists() else {}
    if args.check:
        problems = [f"missing {p}" for p in sorted(set(expected) - set(existing))]
        problems += [f"stale {p}" for p in sorted(set(existing) - set(expected))]
        problems += [f"changed {p}" for p in sorted(set(expected) & set(existing))
                     if existing[p].read_text(encoding="utf-8") != expected[p]]
        if problems:
            print("contract fixtures are out of date; run scripts/contract_fixtures.py",
                  *problems, sep="\n  ", file=sys.stderr)
            return 1
        print(f"Contract fixtures are current ({len(expected)} files).")
        return 0
    for path in sorted(set(existing) - set(expected)):
        existing[path].unlink()
    for path, text in sorted(expected.items()):
        target = args.output / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists() or target.read_text(encoding="utf-8") != text:
            target.write_text(text, encoding="utf-8")
    print(f"Wrote {len(expected)} contract fixtures to {args.output.relative_to(ROOT) if args.output.is_relative_to(ROOT) else args.output}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
