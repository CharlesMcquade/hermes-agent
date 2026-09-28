"""Offline staging contracts. Compiler/signature adapter is explicitly a fixture."""

import copy
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import stage_production_native as staging


class StageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="verity-stage-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.base = self.root / "maintenance"
        self.base.mkdir()
        self.home = self.root / "home"
        self.home.mkdir()
        (self.root / "bootstrap-tmp").mkdir()
        self.selected = self.base / "production-release.json"
        self.identity = self.root / "public-identity.json"
        self.identity.write_text(
            json.dumps({
                "sha1": "a" * 40,
                "keychain": "/fixture/not-opened.keychain",
                "purpose": "production",
                "state": "complete",
                "recovery_readback_verified": True,
                "recovery_signature_challenge_verified": True,
            })
        )
        self.bootstrap = sys.executable
        self.manifest = dict(
            schema_version=2,
            release_id="fixture",
            state_dir=str(self.root / "state"),
            labels={"agent": "fixture.agent", "webui": "fixture.webui"},
            health_url="http://127.0.0.1:1/health",
            services={},
        )
        for role in staging.ROLES:
            p = self.root / (role + ".plist")
            p.write_bytes(
                plistlib.dumps(
                    dict(
                        Label=self.manifest["labels"][role],
                        ProgramArguments=[
                            self.bootstrap,
                            str(self.base / "production_launcher.py"),
                            role,
                        ],
                        WorkingDirectory=str(self.root),
                        RunAtLoad=True,
                        KeepAlive=True,
                        StandardOutPath=str(self.root / (role + ".out")),
                        ThrottleInterval=5,
                    )
                )
            )
            self.manifest["services"][role] = dict(
                repo="/fixture/unread-source/" + role,
                cwd="/fixture/unread-cwd",
                argv=["/fixture/selected-python", role],
                inventory={"fixture.py": {"sha256": "a" * 64, "executable": False}},
                runtimes=[
                    {
                        "root": "/fixture/unread-runtime",
                        "inventory": {"opaque": "receipt"},
                    }
                ],
                env_files=["/fixture/never-read-secret"],
                env={"HERMES_HOME": "/fixture/selected-home"},
                requires=["agent"] if role == "webui" else [],
                commit="fixture-commit",
                plist_path=str(p),
            )
        self.save()
        (self.base / "candidate-release.json").write_text("unrelated pending candidate")
        for name in staging.wrappers(self.base, self.base / "control-versions/old"):
            (self.base / name).write_text("unchanged active wrapper " + name)
        self.before = staging.inventory(self.base)
        self.calls = []

    def save(self):
        self.selected.write_text(json.dumps(self.manifest))

    def runner(self, argv, *, env=None):
        self.calls.append(argv)
        if Path(argv[0]).name == "xcrun":
            binary = Path(argv[-1])
            binary.write_bytes(b"fixture compiler output, not native code")
            binary.chmod(0o700)
        else:
            self.assertEqual(argv[0], "/usr/bin/codesign")
            self.assertTrue(Path(argv[-1]).is_relative_to(self.root / "stage"))
            if "--verify" in argv:
                self.assertTrue(argv[argv.index("-R") + 1].startswith("=identifier "))

    def stage(self, **changes):
        args = dict(
            root=self.root / "stage",
            selected=self.selected,
            identity_path=self.identity,
            control_id="native-v1",
            bootstrap=self.bootstrap,
            bootstrap_tmpdir=self.root / "bootstrap-tmp",
            home=self.home,
            runner=self.runner,
        )
        args.update(changes)
        return staging.stage(**args)

    def test_preserves_selection_and_independent_roles(self):
        result = self.stage()
        stage = self.root / "stage"
        candidate = json.loads((stage / "candidate-release.json").read_text())
        self.assertEqual(candidate["services"], self.manifest["services"])
        self.assertEqual(candidate["labels"], self.manifest["labels"])
        self.assertEqual(staging.inventory(self.base), self.before)
        self.assertFalse((self.home / "Applications").exists())
        self.assertFalse(result["activation_ready"])
        self.assertEqual(stage.stat().st_mode & 0o777, 0o700)
        for role in staging.ROLES:
            definition = plistlib.loads(
                (stage / "launchagents" / (role + ".plist")).read_bytes()
            )
            self.assertEqual(
                definition["ProgramArguments"],
                [candidate["native_host"]["executable"], role],
            )
            self.assertEqual(
                definition["AssociatedBundleIdentifiers"], [staging.BUNDLE_ID]
            )
            self.assertFalse(definition["AbandonProcessGroup"])
            self.assertEqual(definition["ThrottleInterval"], 5)
            self.assertEqual(
                (stage / "rollback" / (role + ".plist")).read_bytes(),
                Path(self.manifest["services"][role]["plist_path"]).read_bytes(),
            )
        self.assertTrue(staging.verify_stage(stage, runner=self.runner))
        self.assertIn("native_identity.py", result["control_sha256"])

    def test_planned_permissions_are_sealed_before_signing(self):
        # Independent platform contract: macOS Location, not the iOS WhenInUse key.
        required = {
            "NSCameraUsageDescription", "NSMicrophoneUsageDescription",
            "NSContactsUsageDescription", "NSCalendarsFullAccessUsageDescription",
            "NSRemindersFullAccessUsageDescription", "NSPhotoLibraryUsageDescription",
            "NSSpeechRecognitionUsageDescription", "NSBluetoothAlwaysUsageDescription",
            "NSLocationUsageDescription", "NSAppleEventsUsageDescription",
            "NSLocalNetworkUsageDescription",
        }
        signed = []

        def inspect(argv, **kwargs):
            if "--sign" in argv:
                info = plistlib.loads((Path(argv[-1]) / "Contents/Info.plist").read_bytes())
                self.assertEqual({k for k in info if k.endswith("UsageDescription")}, required)
                for key in required:
                    self.assertIsInstance(info[key], str)
                    self.assertTrue(info[key].strip())
                self.assertNotIn("NSBonjourServices", info)
                signed.append(info)
            self.runner(argv, **kwargs)

        self.stage(runner=inspect)
        self.assertEqual(len(signed), 1)
        info_path = self.root / "stage/Verity.app/Contents/Info.plist"
        self.assertEqual(plistlib.loads(info_path.read_bytes()), signed[0])
        candidate = json.loads((self.root / "stage/candidate-release.json").read_text())
        self.assertEqual(candidate["native_host"]["inventory"], staging.inventory(info_path.parent.parent))
        self.assertTrue(staging.verify_stage(self.root / "stage", runner=self.runner))

    def test_even_sealed_wrong_or_omitted_metadata_cannot_publish_success(self):
        # Corrupt before inventory/signature receipt creation: integrity alone is
        # insufficient if the builder sealed the wrong metadata in the first place.
        self.stage()
        original = plistlib.loads((self.root / "stage/Verity.app/Contents/Info.plist").read_bytes())
        # Include a description even on the unfixed builder so missing metadata
        # acceptance is reproduced independently of the coverage test above.
        keys = set(original) | {"NSCameraUsageDescription"}
        mutations = [(key, action) for key in sorted(keys) for action in ("omit", "wrong")]
        mutations.extend((key, "empty") for key in keys if key.endswith("UsageDescription"))
        mutations.extend([("NSBonjourServices", "extra"), ("LSUIElement", "integer")])
        put = staging.put
        for index, (key, action) in enumerate(mutations):
            with self.subTest(key=key, action=action):
                target = self.root / "stage" / str(index)

                def corrupt(path, data):
                    if path.name == "Info.plist":
                        info = plistlib.loads(data)
                        if action == "omit":
                            info.pop(key, None)
                        else:
                            info[key] = {
                                "extra": ["_unplanned._tcp"],
                                "integer": 1,
                                "empty": "",
                                "wrong": "incorrect metadata",
                            }[action]
                        data = plistlib.dumps(info)
                    put(path, data)

                with patch.object(staging, "put", side_effect=corrupt):
                    with self.assertRaisesRegex(ValueError, "bundle metadata mismatch"):
                        self.stage(root=target)
                self.assertFalse((target / "stage-report.json").exists())
                self.assertFalse((target / "stage-report.next.json").exists())
        self.assertEqual(staging.inventory(self.base), self.before)

    def test_signed_bootstrap_environment_is_explicit_and_selection_preserved(self):
        self.stage()
        stage = self.root / "stage"
        settings = json.loads(
            (stage / "Verity.app/Contents/Resources/service-settings.json").read_text()
        )
        self.assertEqual(settings["bootstrap_environment"], {
            "HOME": str(self.home),
            "TMPDIR": str(self.root / "bootstrap-tmp"),
            "HERMES_HOME": self.manifest["services"]["agent"]["env"]["HERMES_HOME"],
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        self.assertFalse((self.base / "home").exists())
        self.assertFalse((self.base / "tmp").exists())
        self.assertTrue(staging.verify_stage(stage, runner=self.runner))
        candidate = json.loads((stage / "candidate-release.json").read_text())
        self.assertEqual(candidate["services"], self.manifest["services"])

    def test_ambiguous_bootstrap_state_rejected_before_writes(self):
        for value in ("/other-state", "relative", None):
            with self.subTest(value=value):
                self.manifest["services"]["webui"]["env"]["HERMES_HOME"] = value
                self.save()
                with self.assertRaises((ValueError, RuntimeError)):
                    self.stage()
                self.assertFalse((self.root / "stage").exists())
        self.assertEqual(self.calls, [])

    def test_tamper_rejected(self):
        for relative in (
            "Verity.app/Contents/Resources/service-settings.json",
            "maintenance/production_launcher.py",
            "maintenance/watchdog.py",
            "control-versions/native-v1/native_identity.py",
        ):
            with self.subTest(relative=relative):
                if not (self.root / "stage").exists():
                    self.stage()
                p = self.root / "stage" / relative
                before = p.read_bytes()
                p.write_bytes(before + b"changed")
                with self.assertRaises((ValueError, RuntimeError)):
                    staging.verify_stage(self.root / "stage", runner=self.runner)
                p.write_bytes(before)

    def test_complete_proposal_and_rollback_drift_rejected(self):
        self.stage()
        stage = self.root / "stage"
        for relative in (
            "rollback/agent.plist",
            "launchagents/webui.plist",
            "candidate-release.json",
        ):
            with self.subTest(relative=relative):
                path = stage / relative
                original = path.read_bytes()
                if relative == "rollback/agent.plist":
                    path.write_bytes(b"corrupt rollback")
                elif relative.endswith(".plist"):
                    data = plistlib.loads(original)
                    data["EnvironmentVariables"] = {"UNEXPECTED": "injected"}
                    path.write_bytes(plistlib.dumps(data))
                else:
                    data = json.loads(original)
                    data["health_url"] = "http://127.0.0.1:2/wrong"
                    path.write_text(json.dumps(data))
                try:
                    with self.assertRaises((ValueError, RuntimeError)):
                        staging.verify_stage(stage, runner=self.runner)
                finally:
                    path.write_bytes(original)

    def test_lab_identity_rejected(self):
        data = json.loads(self.identity.read_text())
        data["purpose"] = "lab-only"
        self.identity.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "dedicated production identity"):
            self.stage()
        self.assertFalse((self.root / "stage").exists())

    def test_signature_failure_has_no_success_receipt(self):
        def reject(argv, **kwargs):
            if "--verify" in argv:
                raise RuntimeError("signature rejected")
            self.runner(argv, **kwargs)

        with self.assertRaisesRegex(RuntimeError, "signature rejected"):
            self.stage(runner=reject)
        self.assertFalse((self.root / "stage/stage-report.json").exists())
        self.assertEqual(staging.inventory(self.base), self.before)

    def test_compiler_uses_only_stage_local_scratch_and_clean_environment(self):
        observed = []

        def compiler(argv, *, env=None):
            if Path(argv[0]).name == "xcrun":
                assert env is not None, "compiler must not inherit caller environment"
                self.assertNotIn("UNRELATED_SECRET_SENTINEL", env)
                self.assertEqual(env["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
                for key in (
                    "HOME",
                    "TMPDIR",
                    "CLANG_MODULE_CACHE_PATH",
                    "SWIFT_MODULECACHE_PATH",
                ):
                    path = Path(env[key])
                    self.assertTrue(path.is_relative_to(self.root / "stage"))
                    self.assertTrue(path.is_dir())
                self.assertEqual(
                    argv[argv.index("-module-cache-path") + 1],
                    env["CLANG_MODULE_CACHE_PATH"],
                )
                # Exercise the actual runner -> subprocess boundary without a compiler.
                probe = [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    "import os,sys;assert os.environ['TMPDIR']==sys.argv[1];"
                    "assert 'UNRELATED_SECRET_SENTINEL' not in os.environ",
                    env["TMPDIR"],
                ]
                staging.run(probe, env=env)
                observed.append(True)
            self.runner(argv, env=env)

        with patch.dict(
            os.environ, {"UNRELATED_SECRET_SENTINEL": "not-a-secret-test-value"}
        ):
            self.stage(runner=compiler)
        self.assertEqual(observed, [True])

    def test_final_verification_interrupt_cannot_leave_success_receipt(self):
        checks = []
        visible_during_final_check = []
        report = self.root / "stage/stage-report.json"

        def interrupt(argv, **kwargs):
            self.runner(argv, **kwargs)
            if "--verify" in argv:
                checks.append(True)
                if len(checks) == 2:
                    visible_during_final_check.append(report.exists())
                    raise KeyboardInterrupt("injected final-verification interruption")

        with self.assertRaises(KeyboardInterrupt):
            self.stage(runner=interrupt)
        self.assertEqual(
            len(checks), 2, "exercise final verification, not initial signing"
        )
        self.assertEqual(visible_during_final_check, [False])
        self.assertFalse(report.exists())
        self.assertEqual(staging.inventory(self.base), self.before)

    def test_new_private_outside_maintenance_required(self):
        for target in (
            self.root,
            self.base / "new-stage",
            self.home / "Applications/Verity.app",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.stage(root=target)
        link = self.root / "linked"
        link.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.stage(root=link / "new")
        self.assertEqual(self.calls, [])

    def test_writable_parent_rejected(self):
        parent = self.root / "public"
        parent.mkdir(mode=0o777)
        parent.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "not writable"):
            self.stage(root=parent / "stage")

    def test_existing_control_version_rejected(self):
        (self.base / "control-versions/native-v1").mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.stage()
        self.assertEqual(self.calls, [])

    def test_schema_and_role_rejection_before_writes(self):
        original = copy.deepcopy(self.manifest)
        for mutation in ("schema", "labels", "bootstrap", "control_id"):
            with self.subTest(mutation=mutation):
                self.manifest = copy.deepcopy(original)
                changes = {}
                if mutation == "schema":
                    self.manifest["schema_version"] = 1
                elif mutation == "labels":
                    self.manifest["labels"]["webui"] = self.manifest["labels"]["agent"]
                elif mutation == "bootstrap":
                    changes["bootstrap"] = "/bin/sh"
                else:
                    changes["control_id"] = "../escape"
                self.save()
                with self.assertRaises((ValueError, RuntimeError)):
                    self.stage(**changes)
                self.assertFalse((self.root / "stage").exists())

    def test_revoked_release_rejected(self):
        (self.base / "revoked-releases.json").write_text(
            json.dumps(
                dict(schema_version=1, release_ids=["fixture"], content_digests=[])
            )
        )
        with self.assertRaisesRegex(RuntimeError, "revoked"):
            self.stage()
        self.assertFalse((self.root / "stage").exists())

    def test_drift_retains_failed_stage_without_success(self):
        def drift(argv, **kwargs):
            self.runner(argv, **kwargs)
            if "--verify" in argv:
                self.selected.write_bytes(b"changed selection")

        with self.assertRaisesRegex(RuntimeError, "changed during staging"):
            self.stage(runner=drift)
        self.assertFalse((self.root / "stage/stage-report.json").exists())

    def test_snapshot_modules_import_without_application(self):
        self.stage()
        snapshot = self.root / "stage/control-versions/native-v1"
        env = {
            "HOME": str(self.home),
            "PATH": "/usr/bin:/bin",
            "HERMES_HOME": str(self.home),
        }
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                "import sys;sys.path.insert(0,sys.argv[1]);"
                "import production_launcher,restart_production,watchdog,approved_restart_job,native_identity;"
                'assert "run_agent" not in sys.modules and "gateway.run" not in sys.modules',
                str(snapshot),
            ],
            env=env,
            capture_output=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
