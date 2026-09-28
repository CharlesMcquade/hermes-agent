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
        (self.base / "production_launcher.py").write_text("unchanged active wrapper")
        self.before = staging.inventory(self.base)
        self.calls = []

    def save(self):
        self.selected.write_text(json.dumps(self.manifest))

    def runner(self, argv):
        self.calls.append(argv)
        if argv[0] == "xcrun":
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

    def test_lab_identity_rejected(self):
        data = json.loads(self.identity.read_text())
        data["purpose"] = "lab-only"
        self.identity.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "dedicated production identity"):
            self.stage()
        self.assertFalse((self.root / "stage").exists())

    def test_signature_failure_has_no_success_receipt(self):
        def reject(argv):
            if "--verify" in argv:
                raise RuntimeError("signature rejected")
            self.runner(argv)

        with self.assertRaisesRegex(RuntimeError, "signature rejected"):
            self.stage(runner=reject)
        self.assertFalse((self.root / "stage/stage-report.json").exists())
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
        def drift(argv):
            self.runner(argv)
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
