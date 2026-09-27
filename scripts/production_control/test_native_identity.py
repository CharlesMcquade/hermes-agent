"""Native-parent contracts; all mutable state is disposable."""

import copy
import hashlib
import json
import os
from pathlib import Path
import plistlib
import unittest
from typing import Any
from unittest.mock import patch

import test_restart_control as baseline
from restart_production import ControlError, save_json
from watchdog import tick


class NativeTests(unittest.TestCase):
    host: Any

    def setUp(self):
        fixture = baseline.ControlTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.base, self.clock = fixture.base, fixture.clock
        self.manifest, self.plists = fixture.manifest, fixture.plists
        self.c, self.host = fixture.c, fixture.host
        app = self.base / "Host.app"
        exe = app / "Contents/MacOS/VerityServiceHost"
        exe.parent.mkdir(parents=True)
        exe.write_bytes(b"fixture")
        exe.chmod(0o755)
        resources = app / "Contents/Resources"
        resources.mkdir()
        launcher = self.base / "production_launcher.py"
        launcher.write_bytes(b"fixture launcher")
        digest = hashlib.sha256(launcher.read_bytes()).hexdigest()
        self.settings = dict(
            base=str(self.base),
            bootstrap_python="/usr/bin/python3",
            launcher=str(launcher),
            launcher_sha256=digest,
            roles=["agent", "webui"],
        )
        save_json(resources / "service-settings.json", self.settings)
        (app / "Contents/Info.plist").write_bytes(
            plistlib.dumps({"CFBundleIdentifier": "com.charles.verity.controllerlab"})
        )
        from production_launcher import inventory

        self.manifest["native_host"] = dict(
            bundle=str(app),
            executable=str(exe),
            bundle_id="com.charles.verity.controllerlab",
            requirement='identifier "com.charles.verity.controllerlab" and certificate leaf = H"'
            + "a" * 40
            + '"',
            inventory=inventory(app),
            launcher_sha256=digest,
        )
        self.processes = {}
        for s, pid in [("agent", 100), ("webui", 200)]:
            argv = ["/usr/bin/python3", "-B", str(self.base / (s + ".py"))]
            self.manifest["services"][s]["argv"] = argv
            data = plistlib.loads(self.plists[s].read_bytes())
            data.update(
                ProgramArguments=[str(exe), s],
                AssociatedBundleIdentifiers=[self.manifest["native_host"]["bundle_id"]],
            )
            self.plists[s].write_bytes(plistlib.dumps(data))
            self.host.jobs[s]["argv"] = data["ProgramArguments"]
            self.processes[pid] = dict(
                pid=pid,
                ppid=1,
                uid=os.getuid(),
                executable=str(exe),
                argv=[str(exe), s],
                start_time=self.clock() - 1,
            )
            self.processes[pid + 1] = dict(
                pid=pid + 1,
                ppid=pid,
                uid=os.getuid(),
                executable=str(Path(argv[0]).resolve()),
                argv=argv,
                start_time=self.clock(),
            )
        self.host.process_identity = lambda pid: copy.deepcopy(self.processes[pid])
        self.host.verify_native_signature = lambda pid, requirement: True
        self.host.verify_native_bundle = lambda bundle, requirement: True
        self.host.listener = lambda url: {201}
        save_json(self.c.manifest_path, self.manifest)

    def proof(self, **kw):
        return self.c.snapshot(self.manifest, self.c.definitions(self.manifest), **kw)

    def test_native_pair_is_ready_and_watchdog_does_not_restart(self):
        proof = self.proof()
        self.assertEqual(proof["process_identity"]["webui"]["child"]["pid"], 201)
        self.assertEqual(tick(self.c, grace=0)["status"], "healthy")
        self.host.deep = False
        self.assertEqual(tick(self.c, grace=0)["status"], "degraded")
        self.assertEqual(self.host.calls, [])

    def test_false_listener_and_duplicate_listeners_rejected(self):
        for listeners in ({999}, {200}, {201, 999}, set()):
            with (
                self.subTest(listeners=listeners),
                patch.object(self.host, "listener", return_value=listeners),
            ):
                with self.assertRaises((ControlError, KeyError)):
                    self.proof()

    def test_identity_must_match_exact_role_runtime_parent_uid_and_birth(self):
        cases = [
            (200, "argv", [self.manifest["native_host"]["executable"], "agent"]),
            (200, "executable", "/wrong"),
            (200, "uid", os.getuid() + 1),
            (201, "argv", ["/usr/bin/python3", "unrelated"]),
            (201, "executable", "/wrong"),
            (201, "ppid", 300),
            (101, "ppid", 300),
            (201, "uid", os.getuid() + 1),
            (201, "start_time", self.clock() - 20),
            (200, "start_time", self.clock() + 10),
        ]
        for pid, field, value in cases:
            old = copy.deepcopy(self.processes)
            with self.subTest(pid=pid, field=field):
                self.processes[pid][field] = value
                with self.assertRaises(ControlError):
                    self.proof()
            self.processes = old
        with self.assertRaises(ControlError):
            self.proof(since=self.clock() + 1)

    def test_signature_and_mid_inspection_races_rejected(self):
        with patch.object(self.host, "verify_native_signature", return_value=False):
            with self.assertRaises(ControlError):
                self.proof()
        original = self.host.process_identity
        counts = {}

        def racing(pid):
            counts[pid] = counts.get(pid, 0) + 1
            result = original(pid)
            if counts[pid] > 1:
                result["start_time"] += 0.01
            return result

        with patch.object(self.host, "process_identity", side_effect=racing):
            with self.assertRaises(ControlError):
                self.proof()
        original_fetch = self.host.fetch

        def change_job(url):
            self.host.jobs["webui"]["pid"] = 999
            return original_fetch(url)

        with patch.object(self.host, "fetch", side_effect=change_job):
            with self.assertRaises(ControlError):
                self.proof()

    def test_disk_and_settings_preflight_fail_before_stop(self):
        self.c.preflight(self.manifest)
        for key, value in [
            ("requirement", 'identifier "com.charles.verity.controllerlab"'),
            ("launcher_sha256", "0" * 64),
            ("inventory", {}),
        ]:
            bad = copy.deepcopy(self.manifest)
            bad["native_host"][key] = value
            with self.subTest(key=key), self.assertRaises(ControlError):
                self.c.preflight(bad)
        with patch.object(self.host, "verify_native_bundle", return_value=False):
            with self.assertRaises(ControlError):
                self.c.restart(yes=True)
        self.assertEqual(self.host.calls, [])

    def test_signed_settings_drift_and_plist_association_rejected(self):
        from production_launcher import inventory

        app = Path(self.manifest["native_host"]["bundle"])
        settings_path = app / "Contents/Resources/service-settings.json"
        for key, value in [
            ("base", "/other"),
            ("launcher", "/other/launcher.py"),
            ("roles", ["webui"]),
            ("bootstrap_python", "relative"),
        ]:
            settings = dict(self.settings, **{key: value})
            save_json(settings_path, settings)
            self.manifest["native_host"]["inventory"] = inventory(app)
            with self.subTest(key=key), self.assertRaises(ControlError):
                self.c.preflight(self.manifest)
        save_json(settings_path, self.settings)
        self.manifest["native_host"]["inventory"] = inventory(app)
        definition = plistlib.loads(self.plists["webui"].read_bytes())
        definition["AssociatedBundleIdentifiers"] = ["wrong"]
        self.plists["webui"].write_bytes(plistlib.dumps(definition))
        with self.assertRaisesRegex(ControlError, "associated bundle"):
            self.c.definitions(self.manifest)

    def test_listener_changed_after_http_is_rejected(self):
        original = self.host.fetch

        def changed(url):
            self.host.listener = lambda url: {201, 999}
            return original(url)

        with patch.object(self.host, "fetch", side_effect=changed):
            with self.assertRaisesRegex(ControlError, "listener changed"):
                self.proof()

    def test_readiness_requires_both_child_births_stable(self):
        original = self.c.snapshot
        calls = []

        def unstable(*args):
            result = original(*args)
            calls.append(1)
            result["process_identity"]["webui"]["child"]["start_time"] += len(calls)
            return result

        with patch.object(self.c, "snapshot", side_effect=unstable):
            with self.assertRaisesRegex(ControlError, "timeout"):
                self.c.wait_ready(
                    self.manifest, self.c.definitions(self.manifest), None, None
                )


class NativeAdapterTests(unittest.TestCase):
    def test_codesign_inline_requirement_prefix(self):
        from restart_production import Host

        host = Host()
        requirement = 'identifier "lab"'
        with patch.object(host, "run") as run:
            run.return_value.returncode = 0
            self.assertTrue(host.verify_native_bundle("/lab.app", requirement))
            run.assert_called_once_with(
                "/usr/bin/codesign",
                "--verify",
                "--strict",
                "--deep",
                "-R",
                "=" + requirement,
                "/lab.app",
                check=False,
            )

    def test_kernel_identity_and_dynamic_signature_on_disposable_process(self):
        import subprocess
        import time
        from native_identity import process_identity, verify_signature

        started = time.time()
        process = subprocess.Popen(["/bin/sleep", "30"])
        try:
            record = process_identity(process.pid)
            self.assertEqual(record["pid"], process.pid)
            self.assertEqual(record["ppid"], os.getpid())
            self.assertEqual(record["uid"], os.getuid())
            self.assertEqual(record["executable"], "/bin/sleep")
            self.assertEqual(record["argv"], ["/bin/sleep", "30"])
            self.assertGreaterEqual(record["start_time"], started)
            self.assertEqual(process_identity(process.pid), record)
            self.assertTrue(
                verify_signature(
                    process.pid, 'identifier "com.apple.sleep" and anchor apple'
                )
            )
            self.assertFalse(verify_signature(process.pid, 'identifier "invalid"'))
        finally:
            process.terminate()
            process.wait(timeout=5)
