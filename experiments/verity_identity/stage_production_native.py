"""Stage (never install or activate) a schema-2 Verity native production candidate.

The stager writes only inside the new root and directs compiler scratch/cache
there. This is not an OS sandbox or a promise about macOS daemon writes. The CLI
signs only that candidate under operator approval. No application imports/probes.
"""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys

SOURCE = Path(__file__).resolve().parent
CONTROL = SOURCE.parents[1] / "scripts/production_control"
sys.path.insert(0, str(CONTROL))
from production_launcher import inventory, load_manifest  # noqa: E402
from native_identity import bootstrap_environment, contract  # noqa: E402
from restart_production import Controller  # noqa: E402

BUNDLE_ID = "com.charles.verity"
FILES = (
    "production_launcher.py",
    "restart_production.py",
    "watchdog.py",
    "approved_restart_job.py",
    "native_identity.py",
)
ROLES = ("agent", "webui")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(argv, *, env=None):
    result = subprocess.run(argv, env=env, capture_output=True, timeout=120)
    if result.returncode:
        raise RuntimeError(f"{Path(argv[0]).name} failed (output withheld)")


def compile_host(root, source, binary, runner=run):
    """Explicit compiler outputs/caches; never inherit caller compiler settings."""
    work = root / "compiler"
    for name in ("home", "tmp", "module-cache", "cache"):
        (work / name).mkdir(mode=0o700, parents=True, exist_ok=False)
    environment = {
        "HOME": str(work / "home"),
        "CFFIXED_USER_HOME": str(work / "home"),
        "TMPDIR": str(work / "tmp"),
        "XDG_CACHE_HOME": str(work / "cache"),
        "CLANG_MODULE_CACHE_PATH": str(work / "module-cache"),
        "SWIFT_MODULECACHE_PATH": str(work / "module-cache"),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    }
    runner(
        [
            "/usr/bin/xcrun",
            "--no-cache",
            "swiftc",
            "-target",
            "arm64-apple-macos14.0",
            "-swift-version",
            "5",
            "-module-cache-path",
            str(work / "module-cache"),
            str(source),
            "-o",
            str(binary),
        ],
        env=environment,
    )


def absolute(path):
    path = Path(path).absolute()
    if path != path.resolve():
        raise ValueError("Symlinks/noncanonical paths are not accepted")
    return path


def put(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o600)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def wrappers(base, version):
    prefix = (
        "#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\n"
        f"sys.path.insert(0, {str(version)!r})\nBASE=Path({str(base)!r})\n"
    )
    result = {
        "production_launcher.py": prefix
        + "import production_launcher as launcher\nlauncher.MANIFEST=BASE/'production-release.json'\nlauncher.main()\n"
    }
    for module in ("restart_production", "watchdog", "approved_restart_job"):
        result[module + ".py"] = prefix + (
            f"import json\nfrom {module} import main\n"
            "result=main(['--base',str(BASE)]+sys.argv[1:])\nprint(json.dumps(result))\n"
            "raise SystemExit(0 if result.get('status') in "
            "('checked','verified','healthy','grace','suspect','cooldown','degraded','busy','restart_requested') else 1)\n"
        )
    return result


def production_environment(old, home, tmpdir):
    """Explicit bootstrap paths, separate from preserved service env/env_files."""
    if not isinstance(tmpdir, (str, Path)) or not Path(tmpdir).is_absolute():
        raise ValueError("An explicit absolute bootstrap TMPDIR is required")
    states = [old["services"][role].get("env", {}).get("HERMES_HOME") for role in ROLES]
    if not all(isinstance(value, str) and value == states[0] for value in states):
        raise ValueError("Selected roles must name one explicit HERMES_HOME")
    return bootstrap_environment({
        "base": str(home),
        "bootstrap_environment": {
            "HOME": str(home), "TMPDIR": str(tmpdir), "HERMES_HOME": states[0],
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
        },
    })


def stage(
    root, selected, identity_path, control_id, bootstrap, *, bootstrap_tmpdir,
    home=None, runner=run
):
    root, selected = absolute(root), absolute(selected)
    base = selected.parent
    home = absolute(home or Path.home())
    final_app = home / "Applications/Verity.app"
    if not re.fullmatch(r"[A-Za-z0-9_-]+", control_id):
        raise ValueError("Invalid control version")
    # Existing directories, symlink destinations, maintenance children and app
    # installation destinations are never usable as a stage root.
    if root.exists() or root.is_relative_to(base) or root.is_relative_to(final_app):
        raise ValueError(
            "Stage requires a NEW directory outside maintenance and final app"
        )
    if not root.parent.is_dir():
        raise ValueError("Stage parent must already exist")
    parent = root.parent.stat()
    if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
        raise ValueError(
            "Stage parent must be operator-owned and not writable by others"
        )
    if selected.name != "production-release.json":
        raise ValueError("Expected explicit selected production-release.json")
    before = selected.read_bytes()
    old = load_manifest(
        selected
    )  # Includes revocation policy; no imports or state reads.
    Controller(base).validate_manifest(old)
    environment = production_environment(old, home, bootstrap_tmpdir)
    if "native_host" in old or "launchd_overrides" in old:
        raise ValueError(
            "Only the initial schema-2 legacy-to-native stage is supported"
        )
    if old.get("launcher_path", str(base / "production_launcher.py")) != str(
        base / "production_launcher.py"
    ):
        raise ValueError("Stable launcher path mismatch")
    if not Path(bootstrap).is_absolute() or not os.access(bootstrap, os.X_OK):
        raise ValueError(
            "Bootstrap interpreter must be an existing absolute executable"
        )
    identity = json.loads(Path(identity_path).read_text(encoding="utf-8"))
    if (
        identity.get("purpose") != "production"
        or identity.get("state") != "complete"
        or identity.get("recovery_readback_verified") is not True
        or identity.get("recovery_signature_challenge_verified") is not True
    ):
        raise ValueError(
            "Completed dedicated production identity/recovery receipt required"
        )
    pin = identity["sha1"]
    if not re.fullmatch(r"[a-fA-F0-9]{40}", pin):
        raise ValueError("Invalid signer fingerprint")
    saved = {}
    for role in ROLES:
        p = absolute(old["services"][role]["plist_path"])
        saved[role] = p.read_bytes()
        definition = plistlib.loads(saved[role])
        if (
            definition.get("Label") != old["labels"][role]
            or definition.get("ProgramArguments")
            != [str(bootstrap), str(base / "production_launcher.py"), role]
            or definition.get("RunAtLoad") is not True
            or definition.get("KeepAlive") is not True
            or definition.get("Program", str(bootstrap)) != str(bootstrap)
        ):
            raise ValueError(
                "Selected job does not match bootstrap/legacy role contract"
            )
    version = base / "control-versions" / control_id
    if version.exists():
        raise ValueError("Final control version already exists")
    # Capture control bytes once; the receipt covers the copied bytes, not a
    # later reread of mutable source. Never copy application/state/credential data.
    wrapper_text = wrappers(base, version)
    saved_wrappers = {name: absolute(base / name).read_bytes() for name in wrapper_text}
    controls = {name: (CONTROL / name).read_bytes() for name in FILES}
    swift = (SOURCE / "ServiceHost.swift").read_bytes()
    root.mkdir(mode=0o700, exist_ok=False)
    put(root / "selected-manifest.json", before)
    for role in ROLES:
        put(root / "rollback" / (role + ".plist"), saved[role])
    for name, data in saved_wrappers.items():
        put(root / "rollback/maintenance" / name, data)
    for name, data in controls.items():
        put(root / "control-versions" / control_id / name, data)
    control_receipt = {name: digest(data) for name, data in controls.items()}
    put(
        root / "control-versions" / control_id / "control-receipt.json",
        encoded(control_receipt),
    )
    for name, text in wrapper_text.items():
        put(root / "maintenance" / name, text.encode())
    launcher_hash = digest(wrapper_text["production_launcher.py"].encode())
    app = root / "Verity.app"
    binary = app / "Contents/MacOS/VerityServiceHost"
    binary.parent.mkdir(mode=0o700, parents=True)
    settings = dict(
        base=str(base),
        bootstrap_python=str(bootstrap),
        launcher=str(base / "production_launcher.py"),
        launcher_sha256=launcher_hash,
        roles=list(ROLES),
        bootstrap_environment=environment,
    )
    put(app / "Contents/Resources/service-settings.json", encoded(settings))
    put(
        app / "Contents/Info.plist",
        plistlib.dumps(
            dict(
                CFBundleIdentifier=BUNDLE_ID,
                CFBundleName="Verity",
                CFBundleExecutable=binary.name,
                CFBundleVersion="1",
                CFBundlePackageType="APPL",
                LSUIElement=True,
                LSMinimumSystemVersion="14.0",
            )
        ),
    )
    put(root / "ServiceHost.swift", swift)
    compile_host(root, root / "ServiceHost.swift", binary, runner=runner)
    requirement = f'identifier "{BUNDLE_ID}" and certificate leaf = H"{pin.lower()}"'
    put(root / "requirements.txt", ("designated => " + requirement + "\n").encode())
    runner([
        "/usr/bin/codesign",
        "--force",
        "--sign",
        pin,
        "--keychain",
        identity["keychain"],
        "--timestamp=none",
        "--requirements",
        str(root / "requirements.txt"),
        str(app),
    ])
    runner([
        "/usr/bin/codesign",
        "--verify",
        "--strict",
        "-R",
        "=" + requirement,
        str(app),
    ])
    candidate = copy.deepcopy(old)
    candidate["release_id"] = old["release_id"] + "-native-" + control_id
    candidate["native_host"] = dict(
        bundle=str(final_app),
        executable=str(final_app / "Contents/MacOS/VerityServiceHost"),
        bundle_id=BUNDLE_ID,
        requirement=requirement,
        inventory=inventory(app),
        launcher_sha256=launcher_hash,
    )
    contract(candidate)
    candidate["launchd_overrides"] = {}
    for role in ROLES:
        definition = plistlib.loads(saved[role])
        definition.pop("Program", None)
        override = dict(
            ProgramArguments=[candidate["native_host"]["executable"], role],
            WorkingDirectory=str(base),
            AssociatedBundleIdentifiers=[BUNDLE_ID],
            AbandonProcessGroup=False,
        )
        candidate["launchd_overrides"][role] = override
        definition.update(override)
        put(root / "launchagents" / (role + ".plist"), plistlib.dumps(definition))
    put(root / "candidate-release.json", encoded(candidate))
    # Fail closed on observed drift; retain incomplete evidence rather than
    # deleting it or publishing a successful receipt. No shared locks are written.
    if (
        selected.read_bytes() != before
        or any(
            Path(old["services"][r]["plist_path"]).read_bytes() != saved[r]
            for r in ROLES
        )
        or any(
            (base / name).read_bytes() != data for name, data in saved_wrappers.items()
        )
    ):
        raise RuntimeError(
            "Selection/definitions changed during staging; discard stage"
        )
    report = dict(
        status="staged_not_activated",
        activation_ready=False,
        final_bundle=str(final_app),
        final_base=str(base),
        final_control_version=str(version),
        bootstrap_python=str(bootstrap),
        bootstrap_tmpdir=str(bootstrap_tmpdir),
        selected_sha256=digest(before),
        candidate_sha256=digest(encoded(candidate)),
        rollback_sha256=inventory(root / "rollback"),
        source_sha256=digest(swift),
        control_sha256=control_receipt,
        launcher_sha256=launcher_hash,
        source_runtime_selection_preserved=candidate["services"] == old["services"],
        gates=[
            "final-path signature/settings preflight",
            "initial AssociatedBundleIdentifiers migration and bounded rollback",
            "signed bootstrap environment live compatibility",
            "final identity permission usage descriptions and grants",
            "exact-artifact isolated lifecycle/restart tests",
            "explicit activation approval",
        ],
    )
    # No success-named file exists during verification, including interruption.
    verify_stage(root, runner=runner, report=report)
    provisional = root / "stage-report.next.json"
    put(provisional, encoded(report))
    provisional.replace(root / "stage-report.json")
    return report


def verify_stage(root, runner=run, *, report=None):
    """Recheck sealed artifacts in place without resolving final installation paths."""
    root = absolute(root)
    manifest = json.loads((root / "candidate-release.json").read_text())
    native = contract(manifest)
    app = root / "Verity.app"
    if inventory(app) != native["inventory"]:
        raise ValueError("Staged native inventory mismatch")
    runner([
        "/usr/bin/codesign",
        "--verify",
        "--strict",
        "-R",
        "=" + native["requirement"],
        str(app),
    ])
    settings = json.loads(
        (app / "Contents/Resources/service-settings.json").read_text()
    )
    if report is None:
        report = json.loads((root / "stage-report.json").read_text())
    old_bytes = (root / "selected-manifest.json").read_bytes()
    old = json.loads(old_bytes)
    if (
        digest((root / "candidate-release.json").read_bytes())
        != report["candidate_sha256"]
        or inventory(root / "rollback") != report["rollback_sha256"]
    ):
        raise ValueError("Staged candidate or rollback bytes changed")
    preserved = {
        k: v
        for k, v in manifest.items()
        if k not in {"native_host", "launchd_overrides", "release_id"}
    }
    if preserved != {k: v for k, v in old.items() if k != "release_id"}:
        raise ValueError("Staged candidate changed selected runtime contract")
    if (
        digest(old_bytes) != report["selected_sha256"]
        or manifest["services"] != old["services"]
        or manifest["labels"] != old["labels"]
        or native["bundle"] != report["final_bundle"]
        or native["bundle_id"] != BUNDLE_ID
    ):
        raise ValueError("Staged selection/final identity mismatch")
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    if (
        info.get("CFBundleIdentifier") != BUNDLE_ID
        or info.get("CFBundleExecutable") != "VerityServiceHost"
    ):
        raise ValueError("Staged bundle metadata mismatch")
    for role in ROLES:
        definition = plistlib.loads(
            (root / "launchagents" / (role + ".plist")).read_bytes()
        )
        expected_definition = plistlib.loads(
            (root / "rollback" / (role + ".plist")).read_bytes()
        )
        expected_definition.pop("Program", None)
        override = dict(
            ProgramArguments=[native["executable"], role],
            WorkingDirectory=report["final_base"],
            AssociatedBundleIdentifiers=[BUNDLE_ID],
            AbandonProcessGroup=False,
        )
        expected_definition.update(override)
        if (
            definition != expected_definition
            or manifest.get("launchd_overrides", {}).get(role) != override
        ):
            raise ValueError("Staged role definition mismatch")
    for name, text in wrappers(
        Path(report["final_base"]), Path(report["final_control_version"])
    ).items():
        if (root / "maintenance" / name).read_bytes() != text.encode():
            raise ValueError("Staged wrapper mismatch")
    expected = dict(
        base=report["final_base"],
        bootstrap_python=report["bootstrap_python"],
        launcher=str(Path(report["final_base"]) / "production_launcher.py"),
        launcher_sha256=native["launcher_sha256"],
        roles=list(ROLES),
        bootstrap_environment=production_environment(
            old, Path(report["final_bundle"]).parent.parent, report["bootstrap_tmpdir"]
        ),
    )
    if (
        settings != expected
        or digest((root / "maintenance/production_launcher.py").read_bytes())
        != native["launcher_sha256"]
    ):
        raise ValueError("Staged signed launcher/settings mismatch")
    version = root / "control-versions" / Path(report["final_control_version"]).name
    if {name: digest((version / name).read_bytes()) for name in FILES} != report[
        "control_sha256"
    ]:
        raise ValueError("Staged control inventory mismatch")
    if inventory(app) != native["inventory"]:
        raise ValueError("Staged bundle changed during inspection")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--selected", required=True, type=Path)
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--control-id", required=True)
    parser.add_argument("--bootstrap-python", required=True)
    parser.add_argument("--bootstrap-tmpdir", required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            stage(
                args.root,
                args.selected,
                args.identity,
                args.control_id,
                args.bootstrap_python,
                bootstrap_tmpdir=args.bootstrap_tmpdir,
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
