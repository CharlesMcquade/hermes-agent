"""Prepare two independently compiled, certificate-signed hosts in a new lab.
No production selection, service registration, trust change, or private-key export.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess

from build import SIGNED_ID, SIGNED_NAME


def command(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=180)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(root, identity_file, python311, python314, bridge311, bridge314):
    root = root.resolve()
    identity = json.loads(identity_file.read_text())
    fingerprint = identity["sha1"]
    if not re.fullmatch(r"[A-Fa-f0-9]{40}", fingerprint):
        raise ValueError("Invalid certificate fingerprint")
    keychain = str(Path(identity["keychain"]).resolve())
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    root.chmod(0o700)
    (root / "tmp").mkdir()
    (root / "signed-lab.json").write_text(
        json.dumps({"id": SIGNED_ID, "name": SIGNED_NAME})
    )
    requirement = f'identifier "{SIGNED_ID}" and certificate leaf = H"{fingerprint}"'
    requirement_file = root / "requirements.txt"
    requirement_file.write_text("designated => " + requirement + "\n")
    runtimes = {}
    for slot, source, bridge in [
        ("a", python311, bridge311),
        ("b", python314, bridge314),
    ]:
        info = json.loads(
            command([
                str(source),
                "-I",
                "-c",
                "import json,sys; print(json.dumps({'base':sys.base_prefix,'exe':sys.executable,'version':sys.version.split()[0]}))",
            ]).stdout
        )
        dest = root / "runtimes" / slot / "python"
        dest.parent.mkdir(parents=True)
        shutil.copyfile(Path(info["exe"]).resolve(), dest)
        dest.chmod(0o700)
        command([
            "codesign",
            "--force",
            "--sign",
            "-",
            "--identifier",
            f"{SIGNED_ID}.python.{slot}",
            str(dest),
        ])
        runtimes[slot] = {"pythonHome": info["base"], "bridge": str(bridge.resolve())}
        print(
            json.dumps({"prepared_python": slot, "version": info["version"]}),
            flush=True,
        )
    settings = {"root": str(root), **runtimes["a"], "runtimes": runtimes}
    src = Path(__file__).resolve().parent
    builds = []
    for revision in ("one", "two"):
        app = root / "builds" / revision / f"{SIGNED_NAME}.app"
        binary = app / "Contents/MacOS/VerityPrototype"
        resources = app / "Contents/Resources"
        resources.mkdir(parents=True)
        binary.parent.mkdir()
        flags = ["-D", "REVISION_TWO"] if revision == "two" else []
        command([
            "xcrun",
            "swiftc",
            "-target",
            "arm64-apple-macos14.0",
            "-swift-version",
            "5",
            *flags,
            str(src / "Host.swift"),
            "-o",
            str(binary),
            "-framework",
            "AppKit",
            "-framework",
            "AVFoundation",
            "-framework",
            "ApplicationServices",
        ])
        shutil.copyfile(src / "probe.py", resources / "probe.py")
        (resources / "settings.json").write_text(json.dumps(settings, indent=2))
        plist = {
            "CFBundleIdentifier": SIGNED_ID,
            "CFBundleName": SIGNED_NAME,
            "CFBundleDisplayName": SIGNED_NAME,
            "CFBundleExecutable": "VerityPrototype",
            "CFBundlePackageType": "APPL",
            "LSUIElement": True,
            "CFBundleVersion": "1" if revision == "one" else "2",
            "CFBundleShortVersionString": "0.2",
            "NSCameraUsageDescription": "Test signed Verity permission continuity. No images or video are captured.",
            "NSAppleEventsUsageDescription": "Test signed Verity child automation with a read-only Finder window count.",
        }
        (app / "Contents/Info.plist").write_bytes(plistlib.dumps(plist))
        command([
            "codesign",
            "--force",
            "--sign",
            fingerprint,
            "--keychain",
            keychain,
            "--timestamp=none",
            "--requirements",
            str(requirement_file),
            str(app),
        ])
        command(["codesign", "--verify", "--strict", "-R", "=" + requirement, str(app)])
        dr = command(["codesign", "-d", "-r-", str(app)]).stdout.strip()
        builds.append({
            "revision": revision,
            "executable_sha256": digest(binary),
            "requirement": dr,
        })
        print(json.dumps(builds[-1]), flush=True)
    assert builds[0]["executable_sha256"] != builds[1]["executable_sha256"]
    assert builds[0]["requirement"] == builds[1]["requirement"]
    # A same-name/ID ad-hoc impostor must not satisfy the signer-pinned identity.
    impostor = root / "negative-signature-control.app"
    shutil.copytree(root / "builds/one" / f"{SIGNED_NAME}.app", impostor)
    command([
        "codesign",
        "--force",
        "--sign",
        "-",
        "--requirements",
        '=designated => identifier "' + SIGNED_ID + '"',
        str(impostor),
    ])
    command(["codesign", "--verify", "--strict", str(impostor)])
    rejection = subprocess.run(
        ["codesign", "--verify", "--strict", "-R", "=" + requirement, str(impostor)],
        capture_output=True,
    )
    assert rejection.returncode != 0, "Signer pin accepted an ad-hoc impostor"
    report = {
        "builds": builds,
        "certificate_sha1": fingerprint,
        "requirement": requirement,
        "same_id_adhoc_rejected": True,
        "source_sha256": {
            p.name: digest(p) for p in (src / "Host.swift", src / "probe.py")
        },
    }
    (root / "build-report.json").write_text(json.dumps(report, indent=2))
    # Initial installation inside lab only; staged builds remain unregistered.
    shutil.copytree(
        root / "builds/one" / f"{SIGNED_NAME}.app", root / f"{SIGNED_NAME}.app"
    )
    command(["codesign", "--verify", "--strict", str(root / f"{SIGNED_NAME}.app")])
    print(
        json.dumps({
            "root": str(root),
            "installed_revision": "one",
            "same_id_adhoc_rejected": True,
        })
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for option in (
        "root",
        "identity",
        "python311",
        "python314",
        "bridge311",
        "bridge314",
    ):
        parser.add_argument("--" + option, required=True, type=Path)
    a = parser.parse_args()
    prepare(a.root, a.identity, a.python311, a.python314, a.bridge311, a.bridge314)
