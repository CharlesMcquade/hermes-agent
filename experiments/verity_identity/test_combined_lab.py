"""Combined-lab checker and exact-restoration regressions; no jobs or consent."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from combined_lab import Lab, inventory
from verify_combined_permissions import check, EXPECTED


class PermissionEvidenceTests(unittest.TestCase):
    def result(self, bare=False):
        return {
            "bare": bare,
            "events": [
                {
                    "event": "permission",
                    "name": n,
                    "status": s if not bare else "denied",
                    "allowed": not bare,
                    "requested": False,
                }
                for n, s in EXPECTED.items()
            ],
        }

    def test_hosted_requires_every_expected_status(self):
        result = self.result()
        check(result)
        result["events"][0]["allowed"] = False
        with self.assertRaises(AssertionError):
            check(result)

    def test_missing_category_is_not_success(self):
        result = self.result()
        result["events"].pop()
        with self.assertRaises(AssertionError):
            check(result)

    def test_bare_must_not_inherit_existing_grants(self):
        result = self.result(True)
        check(result)
        result["events"][0]["allowed"] = True
        with self.assertRaises(AssertionError):
            check(result)

    def test_request_is_never_counted_as_check_only(self):
        result = self.result()
        result["events"][0]["requested"] = True
        with self.assertRaises(AssertionError):
            check(result)


class RestoreTests(unittest.TestCase):
    def exercise(self, fail):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            lab = Lab.__new__(Lab)
            lab.root = root / "run"
            lab.root.mkdir()
            lab.lab = root / "permission-lab"
            lab.lab.mkdir()
            lab.original = lab.lab / "Verity Signing Lab.app"
            lab.original.mkdir()
            (lab.original / "original-marker").write_text("original bytes")
            lab.candidate = lab.root / "candidate.app"
            lab.candidate.mkdir()
            (lab.candidate / "candidate-marker").write_text("candidate bytes")
            lab.meta = {
                "original_inventory": inventory(lab.original),
                "candidate_inventory": inventory(lab.candidate),
            }
            lab.saved_manifest = b'{"original":true}\n'
            lab.jobs = []
            lab.paths = []
            lab.pids = set()
            lab.groups = set()
            lab.no_jobs = lambda: None
            lab.check_signature = lambda app: None
            lab.collect = lambda: None
            lab.known_gone = lambda: True
            lab.clean = False
            lab.restored = False

            class Deliberate(Exception):
                pass

            def run():
                with lab.installed():
                    self.assertTrue((lab.original / "candidate-marker").exists())
                    self.assertFalse((lab.original / "original-marker").exists())
                    if fail:
                        raise Deliberate()

            with patch("combined_lab.launchctl") as launch:
                if fail:
                    with self.assertRaises(Deliberate):
                        run()
                else:
                    run()
                launch.assert_not_called()
            self.assertEqual(inventory(lab.original), lab.meta["original_inventory"])
            self.assertEqual(
                (lab.root / "production-release.json").read_bytes(), lab.saved_manifest
            )
            self.assertTrue(lab.restored and lab.clean)
            self.assertFalse((lab.root / "original-preserved.bundle").exists())
            self.assertEqual(json.loads(lab.saved_manifest), {"original": True})

    def test_exact_restore_on_success(self):
        self.exercise(False)

    def test_exact_restore_on_failed_gate(self):
        self.exercise(True)


if __name__ == "__main__":
    unittest.main()
