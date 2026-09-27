"""Build a disposable ad-hoc identity. Never selects/restarts a Hermes service."""

import argparse
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess

ID = "com.charles.verity.prototype"
NAME = "Verity Prototype"
SIGNED_ID = "com.charles.verity.signinglab"
SIGNED_NAME = "Verity Signing Lab"


def app_identity(root):
    marker = root / "signed-lab.json"
    if marker.exists():
        data = json.loads(marker.read_text())
        if data != {"id": SIGNED_ID, "name": SIGNED_NAME}:
            raise ValueError("Not a recognized signing lab")
        return SIGNED_ID, SIGNED_NAME
    return ID, NAME


def build(root, source_python, bridge):
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=False)
    os.chmod(root, 0o700)
    (root / "tmp").mkdir()
    clean = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home())}
    info = json.loads(
        subprocess.check_output(
            [
                str(source_python),
                "-I",
                "-c",
                "import sys,json; print(json.dumps({'base':sys.base_prefix,'exe':sys.executable}))",
            ],
            env=clean,
        )
    )
    for slot in ("a", "b"):
        dest = root / "runtimes" / slot / "python"
        dest.parent.mkdir(parents=True)
        shutil.copyfile(Path(info["exe"]).resolve(), dest)
        dest.chmod(0o700)
        subprocess.run(
            [
                "codesign",
                "--force",
                "--sign",
                "-",
                "--identifier",
                f"{ID}.python.{slot}",
                str(dest),
            ],
            check=True,
        )
    app = root / f"{NAME}.app"
    resources = app / "Contents/Resources"
    resources.mkdir(parents=True)
    binary = app / "Contents/MacOS/VerityPrototype"
    binary.parent.mkdir()
    src = Path(__file__).resolve().parent
    subprocess.run(
        [
            "xcrun",
            "swiftc",
            "-swift-version",
            "5",
            str(src / "Host.swift"),
            "-o",
            str(binary),
            "-framework",
            "AppKit",
            "-framework",
            "AVFoundation",
            "-framework",
            "ApplicationServices",
        ],
        check=True,
    )
    shutil.copyfile(src / "probe.py", resources / "probe.py")
    (resources / "settings.json").write_text(
        json.dumps({
            "root": str(root),
            "pythonHome": info["base"],
            "bridge": str(bridge.resolve()),
        })
    )
    plist = {
        "CFBundleIdentifier": ID,
        "CFBundleName": NAME,
        "CFBundleDisplayName": NAME,
        "CFBundleExecutable": "VerityPrototype",
        "CFBundlePackageType": "APPL",
        "CFBundleVersion": "1",
        "CFBundleShortVersionString": "0.1",
        "LSUIElement": True,
        "NSCameraUsageDescription": "Test Verity permission ownership. No images or video are captured.",
        "NSAppleEventsUsageDescription": "Test Verity child automation with a read-only Finder window count.",
    }
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps(plist))
    subprocess.run(
        ["codesign", "--force", "--sign", "-", "--identifier", ID, str(app)], check=True
    )
    subprocess.run(
        ["codesign", "--verify", "--strict", "--verbose=2", str(app)], check=True
    )
    print(
        json.dumps({
            "root": str(root),
            "app": str(app),
            "signing": "ad-hoc: attribution only, not durable continuity",
        })
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--python", type=Path, required=True)
    p.add_argument("--bridge", type=Path, required=True)
    a = p.parse_args()
    build(a.root, a.python, a.bridge)
