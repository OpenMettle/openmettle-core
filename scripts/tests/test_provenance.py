"""Tests for scripts/provenance.py: inventory determinism and fail-closed distribution readiness.

Run with: python3 -m unittest discover -s scripts/tests
"""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
REPO = SCRIPTS.parent
FIXTURE = SCRIPTS / "tests" / "fixtures" / "provenance" / "cleared"
sys.path.insert(0, str(SCRIPTS))

import provenance  # noqa: E402


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = provenance.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class FixtureCase(unittest.TestCase):
    """Each test gets a writable copy of the fully reviewed fixture and mutates one fact."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "repo"
        shutil.copytree(FIXTURE, self.root)
        self.register_path = self.root / "register.json"
        self.metadata_path = self.root / "cargo-metadata.json"

    def tearDown(self):
        self._tmp.cleanup()

    def register(self):
        return json.loads(self.register_path.read_text())

    def save(self, register):
        self.register_path.write_text(json.dumps(register, indent=2) + "\n")

    def gate(self, metadata=True):
        args = ["check-distribution", "--root", str(self.root), "--register", str(self.register_path)]
        if metadata:
            args += ["--cargo-metadata", str(self.metadata_path)]
        return run_cli(*args)

    def assert_blocked(self, fragment, metadata=True):
        code, _, err = self.gate(metadata)
        self.assertEqual(code, 1, err)
        self.assertIn(fragment, err)

    def assert_invalid(self, fragment):
        code, _, err = self.gate()
        self.assertEqual(code, 2, err)
        self.assertIn(fragment, err)


class PositiveTests(FixtureCase):
    def test_fully_reviewed_fixture_passes(self):
        code, out, err = self.gate()
        self.assertEqual(code, 0, err)
        self.assertIn("Owner release approval is still required", out)

    def test_excluded_blocked_component_does_not_block(self):
        code, _, err = self.gate()
        self.assertEqual(code, 0, err)
        self.assertNotIn("fixture-excluded", err)

    def test_excluded_group_needs_only_its_exclusion_record(self):
        reg = self.register()
        reg["components"] = [c for c in reg["components"] if c["review_group"] != "media"]
        reg["review_groups"]["media"] |= {"status": "excluded", "exclusion_reason": "Synthetic boundary exclusion."}
        self.save(reg)
        code, _, err = self.gate()
        self.assertEqual(code, 0, err)

    def test_excluded_component_with_missing_facts_does_not_block(self):
        reg = self.register()
        excluded = reg["components"][1]
        self.assertEqual(excluded["distribution"], "excluded")
        self.assertIsNone(excluded["licence"]["expression"])
        self.assertIsNone(excluded["pin"])
        code, _, err = self.gate()
        self.assertEqual(code, 0, err)

    def test_redistribution_assessment_is_inventoried(self):
        out_dir = self.root / "out"
        code, _, err = run_cli("inventory", "--root", str(self.root), "--register", str(self.register_path),
                               "--cargo-metadata", str(self.metadata_path), "--output-dir", str(out_dir))
        self.assertEqual(code, 0, err)
        report = json.loads((out_dir / "dependency-inventory.json").read_text())
        self.assertEqual({c["id"]: c["redistribution"]["assessment"] for c in report["components"]},
                         {"fixture-excluded": "undetermined", "fixture-image": "redistributable"})
        self.assertIn("| redistributable |", (out_dir / "notice-obligations.md").read_text())

    def test_inventory_is_deterministic_and_complete(self):
        outputs = []
        for name in ("a", "b"):
            out_dir = self.root / name
            code, _, err = run_cli("inventory", "--root", str(self.root), "--register", str(self.register_path),
                                   "--cargo-metadata", str(self.metadata_path), "--output-dir", str(out_dir))
            self.assertEqual(code, 0, err)
            outputs.append({p.name: p.read_bytes() for p in sorted(out_dir.iterdir())})
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(set(outputs[0]), {"dependency-inventory.json", "notice-obligations.md"})
        report = json.loads(outputs[0]["dependency-inventory.json"])
        self.assertTrue(report["distribution_ready"])
        self.assertEqual([p["name"] for p in report["cargo_packages"]], ["fixture-app", "fixture-dep"])
        self.assertEqual(report["cargo_packages"][1]["declared_licence"], "Apache-2.0")
        self.assertNotIn(str(self.root), outputs[0]["dependency-inventory.json"].decode())
        self.assertIn(b"Retain the licence text.", outputs[0]["notice-obligations.md"])


class NegativeTests(FixtureCase):
    def test_recorded_notices_require_references_and_obligations(self):
        for section in ("cargo_reviews", "components"):
            for field in ("files", "obligations"):
                with self.subTest(section=section, field=field):
                    reg = json.loads((FIXTURE / "register.json").read_text())
                    reg[section][0]["notices"][field] = []
                    self.save(reg)
                    self.assert_invalid("recorded notices need nonempty")

    def test_none_required_needs_justification(self):
        reg = self.register()
        reg["components"][0]["notices"] = {"status": "none-required", "files": [], "obligations": []}
        self.save(reg)
        self.assert_invalid("none-required notices need a justification")

    def test_status_only_decisions_are_invalid(self):
        reg = self.register()
        reg["distribution_boundary"] = {"status": "defined"}
        self.save(reg)
        self.assert_invalid("distribution_boundary")
        reg = json.loads((FIXTURE / "register.json").read_text())
        reg["review_groups"] = {g: {"status": "reviewed"} for g in provenance.REQUIRED_GROUPS}
        self.save(reg)
        self.assert_invalid("completed decision review")

    def test_decisions_need_substance_and_completed_review(self):
        for target, text_field in (("distribution_boundary", "description"), ("core", "summary")):
            for field, value in ((text_field, " "), ("review", {"status": "pending", "evidence": [], "notes": "Pending"})):
                with self.subTest(target=target, field=field):
                    reg = json.loads((FIXTURE / "register.json").read_text())
                    decision = reg[target] if target == "distribution_boundary" else reg["review_groups"][target]
                    decision[field] = value
                    self.save(reg)
                    self.assertEqual(self.gate()[0], 2)

    def test_whitespace_component_facts_are_invalid(self):
        for field in ("version", "pin", "origin"):
            with self.subTest(field=field):
                reg = json.loads((FIXTURE / "register.json").read_text())
                reg["components"][0][field] = " \t"
                self.save(reg)
                self.assert_invalid(field)

    def test_malformed_review_facts_are_invalid(self):
        for field, value in (("reviewer", 123), ("reviewer", " "), ("evidence", [None]),
                             ("evidence", [" "]), ("date", "2026-99-99"), ("date", "2026-02-30")):
            with self.subTest(field=field, value=value):
                reg = json.loads((FIXTURE / "register.json").read_text())
                reg["components"][0]["review"][field] = value
                self.save(reg)
                self.assertEqual(self.gate()[0], 2)

    def test_malformed_list_members_are_invalid(self):
        for section, field in (("licence", "evidence"), ("notices", "files"), ("notices", "obligations")):
            reg = json.loads((FIXTURE / "register.json").read_text())
            reg["components"][0][section][field] = [None]
            self.save(reg)
            self.assert_invalid("nonblank strings")

    def test_unhashable_fields_produce_input_error(self):
        for section, field in (("cargo_reviews", "name"), ("cargo_reviews", "source"),
                               ("components", "kind"), ("components", "review_group"),
                               ("components", "distribution")):
            reg = json.loads((FIXTURE / "register.json").read_text())
            reg[section][0][field] = []
            self.save(reg)
            self.assertEqual(self.gate()[0], 2)

    def test_malformed_metadata_produces_input_error(self):
        for data in ({"packages": {}}, {"packages": [None]}, {"packages": [{"name": []}]}):
            self.metadata_path.write_text(json.dumps(data))
            self.assert_invalid("cargo metadata")

    def test_machine_specific_licence_paths_are_not_exported(self):
        for path in ("/private/synthetic-user/source/LICENSE", "C:\\Users\\synthetic-user\\LICENSE"):
            meta = json.loads((FIXTURE / "cargo-metadata.json").read_text())
            meta["packages"][1]["license_file"] = path
            self.metadata_path.write_text(json.dumps(meta))
            out_dir = self.root / "inventory"
            code, _, err = run_cli("inventory", "--root", str(self.root), "--register", str(self.register_path),
                                   "--cargo-metadata", str(self.metadata_path), "--output-dir", str(out_dir))
            self.assertEqual(code, 0, err)
            report = (out_dir / "dependency-inventory.json").read_text()
            self.assertNotIn("synthetic-user", report)
            self.assertEqual(json.loads(report)["cargo_packages"][1]["declared_licence_file"], "LICENSE")

    def test_new_lock_dependency_without_review_blocks(self):
        lock = self.root / "Cargo.lock"
        lock.write_text(lock.read_text() + '\n[[package]]\nname = "fixture-new"\nversion = "0.9.0"\n'
                        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                        'checksum = "' + "0" * 63 + '3"\n')
        self.assert_blocked("cargo fixture-new 0.9.0: no exact-version review record", metadata=False)

    def test_version_bump_invalidates_review(self):
        lock = self.root / "Cargo.lock"
        lock.write_text(lock.read_text().replace('version = "1.2.3"', 'version = "1.2.4"'))
        code, _, err = self.gate(metadata=False)
        self.assertEqual(code, 1)
        self.assertIn("cargo fixture-dep 1.2.4: no exact-version review record", err)
        self.assertIn("cargo review for fixture-dep 1.2.3 matches no Cargo.lock package", err)

    def test_checksum_mismatch_blocks(self):
        lock = self.root / "Cargo.lock"
        lock.write_text(lock.read_text().replace("0" * 63 + "1", "f" * 64))
        self.assert_blocked("reviewed checksum does not match Cargo.lock", metadata=False)

    def test_missing_cargo_metadata_blocks(self):
        self.assert_blocked("cargo metadata: not supplied", metadata=False)

    def test_declared_licence_mismatch_blocks(self):
        meta = json.loads(self.metadata_path.read_text())
        meta["packages"][1]["license"] = "GPL-3.0-only"
        self.metadata_path.write_text(json.dumps(meta))
        self.assert_blocked("declared licence 'GPL-3.0-only' differs from reviewed 'Apache-2.0'")

    def test_stale_metadata_is_rejected(self):
        meta = json.loads(self.metadata_path.read_text())
        meta["packages"].pop()
        self.metadata_path.write_text(json.dumps(meta))
        self.assert_invalid("cargo metadata does not match Cargo.lock")

    def test_undefined_boundary_blocks(self):
        reg = self.register()
        reg["distribution_boundary"]["status"] = "undefined"
        self.save(reg)
        self.assert_blocked("distribution boundary: undefined")

    def test_pending_group_disposition_blocks(self):
        for group in provenance.REQUIRED_GROUPS:
            with self.subTest(group=group):
                reg = json.loads((FIXTURE / "register.json").read_text())
                reg["review_groups"][group]["status"] = "pending"
                self.save(reg)
                self.assert_blocked(f"review group {group}: disposition pending")

    def test_missing_required_group_is_invalid(self):
        reg = self.register()
        del reg["review_groups"]["media"]
        self.save(reg)
        self.assert_invalid("required group 'media' is missing")

    def test_unreviewed_component_blocks(self):
        reg = self.register()
        reg["components"][0]["review"] = {"status": "pending", "reviewer": None, "date": None,
                                          "evidence": [], "notes": "Not reviewed."}
        self.save(reg)
        self.assert_blocked("component fixture-image: review pending")

    def test_blocked_shipped_component_blocks(self):
        reg = self.register()
        reg["components"][1]["distribution"] = "included"
        self.save(reg)
        self.assert_blocked("component fixture-excluded: review blocked")

    def test_candidate_component_blocks(self):
        reg = self.register()
        reg["components"][0]["distribution"] = "candidate"
        self.save(reg)
        self.assert_blocked("component fixture-image: distribution decision pending")

    def test_missing_component_facts_block(self):
        for field, message in (("pin", "pin not recorded"), ("version", "version not recorded"),
                               ("origin", "origin not recorded")):
            with self.subTest(field=field):
                reg = json.loads((FIXTURE / "register.json").read_text())
                reg["components"][0][field] = None
                self.save(reg)
                self.assert_blocked(f"component fixture-image: {message}")

    def test_unknown_licence_blocks(self):
        reg = self.register()
        reg["cargo_reviews"][1]["licence"]["expression"] = None
        self.save(reg)
        self.assert_blocked("cargo fixture-dep 1.2.3: licence not recorded")

    def test_licence_without_evidence_blocks(self):
        reg = self.register()
        reg["components"][0]["licence"]["evidence"] = []
        reg["components"][0]["redistribution"]["assessment"] = "undetermined"
        self.save(reg)
        self.assert_blocked("component fixture-image: licence has no source evidence")

    def test_pending_notices_block(self):
        reg = self.register()
        reg["components"][0]["notices"]["status"] = "pending"
        self.save(reg)
        self.assert_blocked("component fixture-image: notice obligations pending")

    def test_reviewed_without_reviewer_is_invalid(self):
        reg = self.register()
        reg["components"][0]["review"]["reviewer"] = None
        self.save(reg)
        self.assert_invalid("a reviewed entry needs a reviewer")

    def test_excluded_without_reason_is_invalid(self):
        for distribution in ("excluded", "not-distributed"):
            for reason in (None, " "):
                with self.subTest(distribution=distribution, reason=reason):
                    reg = json.loads((FIXTURE / "register.json").read_text())
                    reg["components"][1]["distribution"] = distribution
                    reg["components"][1]["exclusion_reason"] = reason
                    self.save(reg)
                    self.assert_invalid(f"{distribution} components need an exclusion_reason")

    def test_excluded_group_needs_reason_and_decision_review(self):
        cases = (("exclusion_reason", None, "exclusion_reason"),
                 ("exclusion_reason", " ", "exclusion_reason"),
                 ("review", None, "excluded disposition needs a completed decision review"),
                 ("review", {"status": "pending", "evidence": [], "notes": "Pending."},
                  "excluded disposition needs a completed decision review"))
        for field, value, fragment in cases:
            with self.subTest(field=field, value=value):
                reg = json.loads((FIXTURE / "register.json").read_text())
                reg["review_groups"]["media"] |= {"status": "excluded", "exclusion_reason": "Synthetic."}
                reg["review_groups"]["media"][field] = value
                self.save(reg)
                self.assert_invalid(fragment)

    def test_shipped_component_in_excluded_group_is_invalid(self):
        for distribution in ("included", "candidate"):
            with self.subTest(distribution=distribution):
                reg = json.loads((FIXTURE / "register.json").read_text())
                reg["review_groups"]["database"] |= {"status": "excluded", "exclusion_reason": "Synthetic."}
                reg["components"][0]["distribution"] = distribution
                self.save(reg)
                self.assert_invalid("cannot belong to excluded group 'database'")

    def test_in_boundary_component_with_missing_facts_still_blocks(self):
        reg = self.register()
        reg["review_groups"]["sandbox"] |= {"status": "excluded", "exclusion_reason": "Synthetic."}
        reg["components"][0]["notices"]["status"] = "pending"
        reg["components"][0]["licence"] = {"expression": None, "evidence": []}
        reg["components"][0]["redistribution"]["assessment"] = "undetermined"
        self.save(reg)
        code, _, err = self.gate()
        self.assertEqual(code, 1, err)
        self.assertIn("component fixture-image: licence not recorded", err)
        self.assertIn("component fixture-image: notice obligations pending", err)
        self.assertNotIn("fixture-excluded", err)

    def test_redistribution_assessment_is_required_and_evidence_bound(self):
        cases = ((0, None, "redistribution.assessment must be one of"),
                 (0, {"assessment": "allowed", "basis": "x"}, "redistribution.assessment must be one of"),
                 (0, {"assessment": "undetermined", "basis": " "}, "'basis' must not be blank"),
                 (1, {"assessment": "redistributable", "basis": "No licence recorded."},
                  "'redistributable' needs a recorded licence expression with evidence"),
                 (1, {"assessment": "user-fetched", "basis": "No evidence."},
                  "'user-fetched' needs licence evidence"),
                 (0, {"assessment": "user-fetched", "basis": "Synthetic restriction."},
                  "user-fetched cannot be shipped"))
        for index, value, fragment in cases:
            with self.subTest(value=value):
                reg = json.loads((FIXTURE / "register.json").read_text())
                reg["components"][index]["redistribution"] = value
                self.save(reg)
                self.assert_invalid(fragment)

    def test_redistributable_needs_evidence_not_just_an_expression(self):
        reg = self.register()
        reg["components"][1]["licence"] = {"expression": "MIT", "evidence": []}
        reg["components"][1]["redistribution"] = {"assessment": "redistributable", "basis": "Unsourced."}
        self.save(reg)
        self.assert_invalid("'redistributable' needs a recorded licence expression with evidence")

    def test_unreadable_lock_is_invalid(self):
        (self.root / "Cargo.lock").write_text("not = [valid")
        self.assert_invalid("cannot read lockfile")

    def test_inventory_succeeds_while_distribution_is_blocked(self):
        reg = self.register()
        reg["distribution_boundary"]["status"] = "undefined"
        self.save(reg)
        out_dir = self.root / "out"
        code, out, err = run_cli("inventory", "--root", str(self.root), "--register", str(self.register_path),
                                 "--cargo-metadata", str(self.metadata_path), "--output-dir", str(out_dir))
        self.assertEqual(code, 0, err)
        self.assertIn("not distribution clearance", out)
        report = json.loads((out_dir / "dependency-inventory.json").read_text())
        self.assertFalse(report["distribution_ready"])
        self.assertIn("**no**", (out_dir / "notice-obligations.md").read_text())


class RepositoryRegisterTests(unittest.TestCase):
    """The checked-in register must stay valid, and it must not claim readiness without evidence."""

    def test_register_is_valid(self):
        register = json.loads((REPO / "provenance" / "register.json").read_text())
        self.assertEqual(provenance.validate_register(register), [])

    def test_repository_gate_fails_while_any_review_is_pending(self):
        register = json.loads((REPO / "provenance" / "register.json").read_text())
        pending = ([g for g in register["review_groups"].values() if g["status"] == "pending"]
                   + [r for r in register["cargo_reviews"] if r["review"]["status"] == "pending"]
                   + [c for c in register["components"]
                      if c["distribution"] in provenance.SHIPPED and c["review"]["status"] == "pending"])
        if not pending:
            self.skipTest("no pending review is recorded")
        code, _, err = run_cli("check-distribution", "--root", str(REPO))
        self.assertEqual(code, 1, err)

    def test_repository_register_records_the_19_nov_boundary(self):
        register = json.loads((REPO / "provenance" / "register.json").read_text())
        boundary = register["distribution_boundary"]
        self.assertEqual(boundary["status"], "defined")
        self.assertEqual(boundary["review"]["date"], "2026-11-19")
        self.assertIn("https://github.com/OpenMettle/openmettle-core/issues/32#issuecomment-7005620131",
                      boundary["review"]["evidence"])
        self.assertIn("https://github.com/OpenMettle/openmettle-core/issues/32#issuecomment-7006023083",
                      boundary["review"]["evidence"])
        # The second decision brings the SGLang fork source inside and keeps the Open WebUI fork outside.
        components = {comp["id"]: comp for comp in register["components"]}
        self.assertEqual(components["sglang-curated-fork"]["distribution"], "included")
        self.assertEqual(components["open-webui-fork"]["distribution"], "excluded")
        self.assertNotEqual(register["review_groups"]["serving"]["status"], "excluded")
        # Nothing may stay an undecided candidate, and every component carries a forward assessment.
        for comp in register["components"]:
            with self.subTest(component=comp["id"]):
                self.assertNotEqual(comp["distribution"], "candidate")
                self.assertIn(comp["redistribution"]["assessment"], provenance.REDISTRIBUTION)

    def test_every_lock_package_appears_in_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, err = run_cli("inventory", "--root", str(REPO), "--output-dir", tmp)
            self.assertEqual(code, 0, err)
            report = json.loads((Path(tmp) / "dependency-inventory.json").read_text())
        lock = provenance.load_lock(REPO / "Cargo.lock")
        self.assertEqual([(p["name"], p["version"]) for p in report["cargo_packages"]],
                         [(p["name"], p["version"]) for p in lock])


if __name__ == "__main__":
    unittest.main()
