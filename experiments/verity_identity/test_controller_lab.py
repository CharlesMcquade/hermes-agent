"""Portable regressions for lab isolation and evidence; never launches jobs."""

import copy
import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch

import verify_service_host_live as gate


class LabGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.app = self.root / "Verity Controller Lab.app"
        self.exe = self.app / "Contents/MacOS/VerityServiceHost"
        self.exe.parent.mkdir(parents=True)
        self.exe.write_bytes(b"unit fixture, never executed")
        self.exe.chmod(0o700)
        self.manifest = {
            "native_host": {
                "bundle_id": "com.charles.verity.controllerlab",
                "bundle": str(self.app),
                "executable": str(self.exe),
            },
            "labels": {
                r: f"com.charles.verity.controllerlab.123.{r}"
                for r in ("agent", "webui")
            },
            "state_dir": str(self.root / "state"),
            "health_url": "http://127.0.0.1:23456/health",
            "services": {},
        }
        (self.root / "state").mkdir()
        for role in ("agent", "webui"):
            repo = self.root / role
            repo.mkdir()
            self.manifest["services"][role] = {
                "plist_path": str(self.root / (role + ".plist")),
                "repo": str(repo),
                "cwd": str(repo),
            }
            self.definition = {
                "Label": self.manifest["labels"][role],
                "ProgramArguments": [str(self.exe), role],
                "WorkingDirectory": str(self.root),
                "RunAtLoad": True,
                "KeepAlive": True,
                "AssociatedBundleIdentifiers": ["com.charles.verity.controllerlab"],
                "ThrottleInterval": 1,
                "AbandonProcessGroup": False,
                "StandardOutPath": str(self.root / (role + ".out")),
                "StandardErrorPath": str(self.root / (role + ".err")),
            }
            (self.root / (role + ".plist")).write_bytes(plistlib.dumps(self.definition))
        (self.root / "build-report.json").write_text(
            json.dumps({
                "root": str(self.root),
                "synthetic_services": True,
                "labels": self.manifest["labels"],
            })
        )
        self.save_manifest()

    def save_manifest(self):
        (self.root / "production-release.json").write_text(json.dumps(self.manifest))

    def test_valid_paths_and_actual_definitions(self):
        self.assertEqual(gate.lab(self.root)[0], self.root)

    def test_refuse_external_executable_before_any_execution(self):
        self.manifest["native_host"]["executable"] = "/bin/sleep"
        self.save_manifest()
        with (
            patch.object(gate, "launchctl") as launch,
            patch.object(gate.subprocess, "run") as run,
        ):
            with self.assertRaises(AssertionError):
                gate.verify(self.root)
            launch.assert_not_called()
            run.assert_not_called()

    def test_refuse_plist_drift_before_any_execution(self):
        path = self.root / "webui.plist"
        original = plistlib.loads(path.read_bytes())
        for key, value in [
            ("Label", "not.a.lab.job"),
            ("ProgramArguments", ["/bin/sleep", "30"]),
            ("Program", "/bin/sleep"),
            ("WorkingDirectory", "/"),
            ("EnvironmentVariables", {"PYTHONPATH": "/external"}),
            ("StandardOutPath", "/external/output"),
        ]:
            with self.subTest(key=key):
                path.write_bytes(plistlib.dumps(dict(original, **{key: value})))
                with self.assertRaises(AssertionError):
                    gate.lab(self.root)
        path.write_bytes(plistlib.dumps(original))

    def test_refuse_executable_or_plist_symlink(self):
        other = self.root / "other"
        other.write_bytes(self.exe.read_bytes())
        self.exe.unlink()
        self.exe.symlink_to(other)
        with self.assertRaises(AssertionError):
            gate.lab(self.root)

    def test_empty_process_accounting_is_not_cleanup_proof(self):
        with (
            patch.object(gate, "alive", return_value=False),
            patch.object(gate.subprocess, "run") as run,
        ):
            run.return_value.stdout = ""
            self.assertFalse(gate.all_recorded_gone(self.root))

    def test_early_unready_host_and_worker_are_checked(self):
        (self.root / "agent.out").write_text(
            json.dumps({
                "event": "service-host",
                "pid": 101,
                "child_pid": 102,
                "guard_pid": 103,
                "pgid": 101,
                "role": "agent",
            })
            + "\n"
        )
        (self.root / "state/processes.jsonl").write_text(
            json.dumps({
                "pid": 102,
                "ppid": 101,
                "worker": 104,
                "pgid": 101,
                "role": "agent",
            })
            + "\n"
        )
        with patch.object(gate, "alive", side_effect=lambda pid: pid == 104):
            self.assertFalse(gate.all_recorded_gone(self.root))
        with (
            patch.object(gate, "alive", return_value=False),
            patch.object(gate.subprocess, "run") as run,
        ):
            run.return_value.stdout = "105 101\n"
            self.assertFalse(gate.all_recorded_gone(self.root))
            run.return_value.stdout = ""
            self.assertTrue(gate.all_recorded_gone(self.root))

    def test_failed_start_cannot_claim_verified_cleanup(self):
        for started in ([], ["gui/501/com.charles.verity.controllerlab.123.agent"]):
            proof = {"status": "failed"}
            gate.set_cleanup_outcome(proof, [], started)
            self.assertFalse(proof["cleanup_verified"])
            self.assertEqual(
                proof["cleanup_status"], "inconclusive" if started else "not_started"
            )
        proof = {"status": "running"}
        gate.set_cleanup_outcome(proof, [], ["lab"])
        self.assertTrue(proof["cleanup_verified"])
        self.assertEqual(proof["cleanup_status"], "verified")

    def test_initial_pair_is_a_snapshot(self):
        pair = {"agent": {"pid": 101}, "webui": {"pid": 201}}
        expected = copy.deepcopy(pair)
        report = {"cases": []}
        gate.record_initial_pair(report, pair)
        pair["webui"] = {"pid": 301}
        pair["agent"]["pid"] = 401
        self.assertEqual(report["cases"][0]["pair"], expected)


if __name__ == "__main__":
    unittest.main()
