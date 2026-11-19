"""Tests for the Cargo.lock dependency ban in scripts/check_repository.py (ADR 0026).

Run with: python3 -m unittest discover -s scripts/tests
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import check_repository  # noqa: E402


class BannedCrates(unittest.TestCase):
    def test_committed_lockfile_has_no_banned_crate(self):
        lock = (SCRIPTS.parent / "Cargo.lock").read_text(encoding="utf-8")
        self.assertEqual(check_repository.banned_crates(lock), [])
        # The scan sees real packages, so an empty result is not a parsing failure.
        self.assertIn("opentelemetry-proto", check_repository.LOCK_NAME.findall(lock))

    def test_each_banned_crate_is_reported_by_exact_name(self):
        for name in sorted(check_repository.BANNED_CRATES):
            lock = f'[[package]]\nname = "{name}"\nversion = "1.0.0"\n'
            self.assertEqual(check_repository.banned_crates(lock), [name])

    def test_similar_names_and_dependency_entries_are_not_packages(self):
        lock = (
            '[[package]]\nname = "h2o"\nversion = "1.0.0"\n'
            'dependencies = [\n "h2",\n "tonic",\n]\n'
            '[[package]]\nname = "tonic-build-x"\nversion = "1.0.0"\n'
        )
        self.assertEqual(check_repository.banned_crates(lock), [])


if __name__ == "__main__":
    unittest.main()
