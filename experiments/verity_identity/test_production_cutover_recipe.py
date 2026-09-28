"""Offline evidence of the post-success exact-return blocker, not an activation tool."""
import base64
import copy
from pathlib import Path
import plistlib
import sys
import unittest
from unittest.mock import patch

CONTROL = Path(__file__).resolve().parents[2] / "scripts/production_control"
sys.path.insert(0, str(CONTROL))
import approved_restart_job as approved  # noqa: E402
import restart_production as control  # noqa: E402
import test_native_migration as fixtures  # noqa: E402


class CutoverRecipeTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.NativeMigrationTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.c, self.host = self.f.c, self.f.host
        # Noncanonical JSON and binary plists make byte-exactness observable.
        self.original = b"\n " + self.c.manifest_path.read_bytes() + b"\n"
        self.c.manifest_path.write_bytes(self.original)
        self.plists = self.f.saved()
        self.baseline = self.f.base / "retained-baseline"
        self.baseline.mkdir()
        (self.baseline / "manifest").write_bytes(self.original)
        for role, data in self.plists.items():
            (self.baseline / (role + ".plist")).write_bytes(data)
        app = Path(self.f.new["native_host"]["bundle"])
        self.artifacts = {p: p.read_bytes() for p in app.rglob("*") if p.is_file()}
        self.artifacts[self.f.base / "production_launcher.py"] = b"fixture launcher"
        # No accidental escape to a real host adapter, subprocess or network.
        for target in ("subprocess.run", "subprocess.Popen"):
            guard = patch(target, side_effect=AssertionError("native call forbidden"))
            guard.start()
            self.addCleanup(guard.stop)

    def assert_retained(self):
        self.assertEqual((self.baseline / "manifest").read_bytes(), self.original)
        for role, data in self.plists.items():
            self.assertEqual((self.baseline / (role + ".plist")).read_bytes(), data)
        for path, data in self.artifacts.items():
            self.assertEqual(path.read_bytes(), data)

    def inverse(self):
        candidate = copy.deepcopy(self.f.old)
        candidate["launchd_overrides"] = {}
        for role, raw in self.plists.items():
            old = plistlib.loads(raw)
            candidate["launchd_overrides"][role] = {
                key: old[key] for key in ("ProgramArguments", "WorkingDirectory")
            }
        return candidate

    def test_success_is_terminal_and_original_manifest_is_not_inverse(self):
        self.assertEqual(self.f.activate()["status"], "verified")
        current = self.c.manifest_path.read_bytes(), self.f.saved()
        journal = self.c.transaction_path.read_bytes()
        calls = list(self.host.calls)
        with control.control_lock(self.f.base):
            self.assertIsNone(self.c.recover_locked())
        with self.assertRaisesRegex(control.ControlError, "Unexpected launcher argv"):
            self.f.activate(self.f.old)
        self.assertEqual((self.c.manifest_path.read_bytes(), self.f.saved()), current)
        self.assertEqual(self.c.transaction_path.read_bytes(), journal)
        self.assertEqual(self.host.calls, calls)
        self.assert_retained()

    def test_inverse_verifies_but_cannot_restore_original_bytes_or_policy(self):
        self.assertEqual(self.f.activate()["status"], "verified")
        inverse = self.inverse()
        # The supported override vocabulary cannot set the missing legacy fields.
        for key, value in (("Program", "/usr/bin/python3"),
                           ("AbandonProcessGroup", True),
                           ("AssociatedBundleIdentifiers", [])):
            bad = copy.deepcopy(inverse)
            bad["launchd_overrides"]["agent"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(
                control.ControlError, "Unsupported launchd override field"
            ):
                self.f.activate(bad)
        self.assertEqual(self.f.activate(inverse)["status"], "verified")
        self.assertNotEqual(self.c.manifest_path.read_bytes(), self.original)
        for role, raw in self.f.saved().items():
            actual = plistlib.loads(raw)
            old = plistlib.loads(self.plists[role])
            self.assertEqual(actual["ProgramArguments"], old["ProgramArguments"])
            self.assertNotEqual(raw, self.plists[role])
            self.assertNotIn("Program", actual)
            self.assertIs(actual["AbandonProcessGroup"], False)
            self.assertEqual(actual["AssociatedBundleIdentifiers"],
                             [self.f.new["native_host"]["bundle_id"]])
        # A later transaction has replaced the journal's original legacy backup.
        self.assertIn(b"native_host", base64.b64decode(self.c.read_transaction()["manifest"]))
        self.assert_retained()

    def test_failed_inverse_preserves_native_fallback_and_separate_baseline(self):
        self.assertEqual(self.f.activate()["status"], "verified")
        native = self.c.manifest_path.read_bytes(), self.f.saved()
        self.host.fail_kicks = {self.host.kicks + 1}
        self.assertEqual(self.f.activate(self.inverse())["status"], "rolled_back")
        self.assertEqual((self.c.manifest_path.read_bytes(), self.f.saved()), native)
        self.c.snapshot(self.c.load(), self.c.definitions(self.c.load()))
        self.assert_retained()

    def test_incomplete_native_activation_restores_exact_original_once(self):
        class PowerLoss(BaseException):
            pass

        write = control.atomic_write

        def interrupted(path, data):
            write(path, data)
            if path == self.f.plists["agent"]:
                raise PowerLoss()

        with patch.object(control, "atomic_write", side_effect=interrupted):
            with self.assertRaises(PowerLoss):
                self.f.activate()
        self.assertEqual(self.c.read_transaction()["phase"], "prepared")
        with control.control_lock(self.f.base):
            self.assertEqual(self.c.recover_locked()["status"], "rolled_back")
        self.assertEqual(self.c.manifest_path.read_bytes(), self.original)
        self.assertEqual(self.f.saved(), self.plists)
        calls = list(self.host.calls)
        with control.control_lock(self.f.base):
            self.assertIsNone(self.c.recover_locked())
        self.assertEqual(self.host.calls, calls)
        self.assert_retained()

    def test_documented_job_is_unarmed_and_routes_exact_approved_arguments(self):
        doc = Path(__file__).with_name("PRODUCTION-CUTOVER.md").read_text(encoding="utf-8")
        recipe = doc.split("```python\n", 1)[1].split("```", 1)[0]
        namespace = {}
        exec(compile(recipe, "documented-unarmed-job", "exec"), namespace)
        base, version = self.f.base, self.f.base / "control-versions/v1"
        report = dict(final_base=str(base), final_control_version=str(version),
                      bootstrap_python="/usr/bin/python3")
        candidate = base / "stage/candidate-release.json"
        job = namespace["unarmed_job"](report, candidate, base / "private-job")
        job = plistlib.loads(plistlib.dumps(job))
        self.assertIs(job["Disabled"], True)
        self.assertIs(job["RunAtLoad"], False)
        self.assertIs(job["KeepAlive"], False)
        argv = job["ProgramArguments"]
        self.assertEqual(argv[:3], [report["bootstrap_python"], "-B",
                                   str(version / "approved_restart_job.py")])
        with patch.object(approved, "restart_main", return_value={"status": "verified"}) as main:
            with self.assertRaises(control.ControlError):
                approved.main(argv[3:], owner=lambda: 42)
            main.assert_not_called()
            approved.main(argv[3:], owner=lambda: 1)
            main.assert_called_once_with(["--base", str(base), "--restart", "--yes",
                                          "--activate", str(candidate), "--reload"])
        with self.assertRaises(ValueError):
            namespace["unarmed_job"](dict(report, final_control_version="relative"),
                                      candidate, base / "private-job")


if __name__ == "__main__":
    unittest.main()
