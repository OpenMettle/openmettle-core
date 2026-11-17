"""Tests for scripts/contract_fixtures.py: deterministic generation, drift detection and mutations.

Schema validity is checked by tests/contract.rs with a real JSON Schema validator; these
tests cover the generator only. Run with: python3 -m unittest discover -s scripts/tests
"""
from __future__ import annotations

import contextlib
import io
import json
import random
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
REPO = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

import contract_fixtures as cf  # noqa: E402

DOCUMENT = json.loads(cf.DOCUMENT.read_text(encoding="utf-8"))
I64_MAX = 2**63 - 1


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cf.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def minimal(direction="response", mutations=(), required=("a",), data=None):
    return {
        "components": {
            "schemas": {
                "Target": {"$ref": "#/components/schemas/Object"},
                "Object": {"type": "object", "required": list(required),
                           "properties": {"a": {"type": "string", "maxLength": 3}}},
            },
            "examples": {
                "Example": {
                    "dataValue": {"a": "x"} if data is None else data,
                    "x-openmettle-fixture": {"schema": "#/components/schemas/Target",
                                             "direction": direction, "mutations": list(mutations)},
                }
            },
        }
    }


class GenerationTests(unittest.TestCase):
    def test_committed_fixtures_are_current(self):
        code, out, err = run_cli("--check")
        self.assertEqual(code, 0, err)
        self.assertIn("current", out)

    def test_generation_is_deterministic(self):
        first = {p: cf.render(f) for p, f in cf.generate(DOCUMENT).items()}
        second = {p: cf.render(f) for p, f in cf.generate(json.loads(json.dumps(DOCUMENT))).items()}
        self.assertEqual(first, second)
        self.assertTrue(all(text.endswith("\n") and "\r" not in text for text in first.values()))

    def test_check_reports_changed_missing_and_stale_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "fixtures"
            shutil.copytree(cf.OUTPUT, output)
            changed = output / "valid" / "CounterZero.json"
            changed.write_text(changed.read_text().replace('"0"', '"00"'), encoding="utf-8")
            (output / "valid" / "UuidCanonical.json").unlink()
            (output / "invalid" / "Leftover.json").write_text("{}\n", encoding="utf-8")
            code, _, err = run_cli("--check", "--output", str(output))
            self.assertEqual(code, 1)
            for needle in ("changed valid/CounterZero.json", "missing valid/UuidCanonical.json",
                           "stale invalid/Leftover.json"):
                self.assertIn(needle, err)
            self.assertEqual(run_cli("--output", str(output))[0], 0)
            self.assertEqual(run_cli("--check", "--output", str(output))[0], 0)
            self.assertFalse((output / "invalid" / "Leftover.json").exists())

    def test_invalid_document_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "doc.json"
            bad.write_text(json.dumps(minimal(mutations=[{"name": "x", "class": "invalid",
                                                          "op": "remove", "path": "/a"}])))
            self.assertEqual(run_cli("--check", "--document", str(bad), "--output", tmp)[0], 2)


class MutationTests(unittest.TestCase):
    def test_set_remove_root_and_repeat(self):
        base = {"a": {"b": [1, 2]}, "c": "x"}
        self.assertEqual(cf.mutate(base, {"op": "set", "path": "/a/b/1", "value": 3}),
                         {"a": {"b": [1, 3]}, "c": "x"})
        self.assertEqual(cf.mutate(base, {"op": "remove", "path": "/c"}), {"a": {"b": [1, 2]}})
        self.assertEqual(cf.mutate(base, {"op": "set", "path": "", "value": "v"}), "v")
        self.assertEqual(cf.mutate(base, {"op": "set", "path": "/c", "repeat": ["ab", 3]})["c"],
                         "ababab")
        self.assertEqual(base, {"a": {"b": [1, 2]}, "c": "x"}, "source must not change")

    def test_pointer_escapes(self):
        base = {"a/b": {"~": 1}}
        self.assertEqual(cf.mutate(base, {"op": "set", "path": "/a~1b/~0", "value": 2}),
                         {"a/b": {"~": 2}})

    def test_encoded_content_paths(self):
        base = {"data": json.dumps({"z": 1, "a": {"b": 2}})}
        mutated = cf.mutate(base, {"op": "set", "path": "/data#/a/b", "value": "3"})
        self.assertEqual(mutated["data"], '{"a":{"b":"3"},"z":1}')
        removed = cf.mutate(base, {"op": "remove", "path": "/data#/z"})
        self.assertEqual(json.loads(removed["data"]), {"a": {"b": 2}})

    def test_rejects_unsupported_or_unresolvable_mutations(self):
        for mutation in ({"op": "move", "path": "/a", "value": 1},
                         {"op": "remove", "path": "/missing"},
                         {"op": "remove", "path": ""},
                         {"op": "set", "path": "/a"},
                         {"op": "set", "path": "a", "value": 1},
                         {"op": "set", "path": "/a#/x", "value": 1}):
            with self.subTest(mutation=mutation), self.assertRaises(cf.FixtureError):
                cf.mutate({"a": 1}, mutation)


class DeclarationTests(unittest.TestCase):
    def test_auto_mutations_for_responses(self):
        out = cf.generate(minimal())
        self.assertEqual(out["compat/Example--auto-unknown-root-field.json"]["instance"],
                         {"a": "x", cf.UNKNOWN_FIELD: {"added_in": "1.999"}})
        missing = out["invalid/Example--auto-missing-a.json"]
        self.assertEqual(missing["instance"], {})
        self.assertEqual(missing["expect"], {"valid": False, "instancePath": "", "keyword": "required"})

    def test_requests_reject_unknown_fields(self):
        out = cf.generate(minimal(direction="request"))
        fixture = out["invalid/Example--auto-unknown-root-field.json"]
        self.assertEqual(fixture["expect"]["keyword"], "additionalProperties")

    def test_values_have_only_declared_mutations(self):
        out = cf.generate(minimal(direction="value", data="v"))
        self.assertEqual(sorted(out), ["valid/Example.json"])

    def test_expectations_are_mandatory_for_invalid_and_forbidden_otherwise(self):
        cases = [
            {"name": "a", "class": "invalid", "op": "remove", "path": "/a"},
            {"name": "a", "class": "invalid", "op": "remove", "path": "/a", "expect": {"keyword": "x"}},
            {"name": "a", "class": "compat", "op": "set", "path": "/a", "value": "y",
             "expect": {"instancePath": "", "keyword": "x"}},
            {"name": "a b", "class": "valid", "op": "set", "path": "/a", "value": "y"},
            {"name": "a", "class": "maybe", "op": "set", "path": "/a", "value": "y"},
        ]
        for mutation in cases:
            with self.subTest(mutation=mutation), self.assertRaises(cf.FixtureError):
                cf.generate(minimal(mutations=[mutation]))

    def test_schema_pointers_are_local_and_acyclic(self):
        document = minimal()
        document["components"]["examples"]["Example"]["x-openmettle-fixture"]["schema"] = \
            "https://example.invalid/schema.json"
        with self.assertRaises(cf.FixtureError):
            cf.generate(document)
        document = minimal()
        document["components"]["schemas"]["Object"] = {"$ref": "#/components/schemas/Target"}
        with self.assertRaises(cf.FixtureError):
            cf.generate(document)

    def test_example_must_contain_root_required_properties(self):
        with self.assertRaises(cf.FixtureError):
            cf.generate(minimal(required=("a", "b")))


class CanonicalDocumentTests(unittest.TestCase):
    """Cross-check the hand-maintained signed 64-bit patterns with an independent regex engine."""

    def pattern(self, name):
        return re.compile(DOCUMENT["components"]["schemas"][name]["pattern"])

    def test_decimal_patterns_match_exact_signed_64_bounds(self):
        nonnegative, positive = self.pattern("NonNegativeDecimal"), self.pattern("PositiveSequence")
        rng = random.Random(7)
        samples = [0, 1, 9, 10, 2**53, 2**53 + 1, I64_MAX - 1, I64_MAX, I64_MAX + 1,
                   10**18 - 1, 10**18, 10**19, 2**64 - 1]
        samples += [rng.randrange(0, 2**64) for _ in range(20000)]
        samples += [rng.randrange(0, 10**digits) for digits in range(1, 21) for _ in range(50)]
        for value in samples:
            text = str(value)
            self.assertEqual(bool(nonnegative.fullmatch(text)), value <= I64_MAX, text)
            self.assertEqual(bool(positive.fullmatch(text)), 1 <= value <= I64_MAX, text)
        for text in ("", "00", "01", "-1", "+1", "1.0", "1e3", " 1", "1 ", "١"):
            self.assertIsNone(nonnegative.fullmatch(text), text)
            self.assertIsNone(positive.fullmatch(text), text)

    def test_every_fixture_example_declares_metadata(self):
        examples = DOCUMENT["components"]["examples"]
        self.assertTrue(examples)
        for name, example in examples.items():
            self.assertIn("x-openmettle-fixture", example, name)


if __name__ == "__main__":
    unittest.main()
