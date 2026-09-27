"""Add broader-permission builds to the existing signed lab, without installing.

Original signed artifacts/reports remain frozen. Reuse the existing certificate
and runtime slots; do not create trust, keys, persistent jobs, or production state.
"""

import argparse
import json
from pathlib import Path
import plistlib
import re
import shutil

from build import SIGNED_ID, SIGNED_NAME
from build_signed import command, digest
from network_probe import target_from, verify_on_link
from verify_signed_live import no_job


USAGE = {
    "NSCameraUsageDescription": "Verify Verity authorization continuity; no images or video are captured.",
    "NSMicrophoneUsageDescription": "Verify Verity authorization continuity; no audio is recorded.",
    "NSContactsUsageDescription": "Verify Verity authorization continuity; no contacts are fetched.",
    "NSCalendarsFullAccessUsageDescription": "Verify Verity authorization continuity; no calendar data is fetched or changed.",
    "NSRemindersFullAccessUsageDescription": "Verify Verity authorization continuity; no reminders are fetched or changed.",
    "NSPhotoLibraryUsageDescription": "Verify Verity authorization continuity; no photos are fetched or changed.",
    "NSSpeechRecognitionUsageDescription": "Verify Verity authorization continuity; no speech is recorded or sent.",
    "NSBluetoothAlwaysUsageDescription": "Verify Verity authorization continuity; no devices are scanned or connected.",
    "NSLocationWhenInUseUsageDescription": "Verify Verity authorization continuity; no location is sampled.",
    "NSLocationUsageDescription": "Verify Verity authorization continuity; no location is sampled.",
    "NSAppleEventsUsageDescription": "Verify Verity read-only Finder automation; results are discarded.",
    "NSLocalNetworkUsageDescription": "Verify Verity can open one chosen local TCP endpoint; no device discovery or application data.",
}


def prepare(root, identity_file, address, port):
    root = root.resolve(strict=True)
    if not no_job():
        raise ValueError("The lab job must be unloaded before building")
    original = json.loads((root / "build-report.json").read_text())
    identity = json.loads(identity_file.read_text())
    fingerprint = identity["sha1"]
    if not re.fullmatch(r"[A-Fa-f0-9]{40}", fingerprint):
        raise ValueError("Invalid signing fingerprint")
    if fingerprint.lower() != original["certificate_sha1"].lower():
        raise ValueError("Refusing a different signer")
    if json.loads((root / "signed-lab.json").read_text()) != {
        "id": SIGNED_ID,
        "name": SIGNED_NAME,
    }:
        raise ValueError("Not the expected isolated lab")
    target = dict(
        zip(("address", "port"), target_from({"address": address, "port": port}))
    )
    verify_on_link(target["address"])
    src = Path(__file__).resolve().parent
    sources = [
        src / n
        for n in ("Host.swift", "probe.py", "permissions_probe.py", "network_probe.py")
    ]
    for source in sources:
        if not source.is_file():
            raise FileNotFoundError(source.name)
    original_app = root / "builds/one" / f"{SIGNED_NAME}.app"
    for revision in ("three", "four"):
        if (root / "builds" / revision).exists():
            raise ValueError("Build destination already exists; inspect before retry")
    report_file = root / "expanded-build-report.json"
    if report_file.exists():
        raise ValueError("An expanded build report already exists")
    command([
        "codesign",
        "--verify",
        "--strict",
        "-R",
        "=" + original["requirement"],
        str(original_app),
    ])
    builds = list(original["builds"])
    for revision, version in (("three", "3"), ("four", "4")):
        app = root / "builds" / revision / f"{SIGNED_NAME}.app"
        shutil.copytree(original_app, app)
        binary = app / "Contents/MacOS/VerityPrototype"
        # Preserve the source artifacts; remove only the copied binary before compiling.
        binary.unlink()
        command([
            "xcrun",
            "swiftc",
            "-target",
            "arm64-apple-macos14.0",
            "-swift-version",
            "5",
            "-D",
            "REVISION_" + revision.upper(),
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
        for source in sources[1:]:
            shutil.copyfile(source, app / "Contents/Resources" / source.name)
        (app / "Contents/Resources/network-target.json").write_text(json.dumps(target))
        plist_file = app / "Contents/Info.plist"
        plist = plistlib.loads(plist_file.read_bytes())
        plist.update(USAGE, CFBundleVersion=version, CFBundleShortVersionString="0.3")
        plist_file.write_bytes(plistlib.dumps(plist))
        command([
            "codesign",
            "--force",
            "--sign",
            fingerprint,
            "--keychain",
            identity["keychain"],
            "--timestamp=none",
            "--requirements",
            str(root / "requirements.txt"),
            str(app),
        ])
        command([
            "codesign",
            "--verify",
            "--strict",
            "-R",
            "=" + original["requirement"],
            str(app),
        ])
        builds.append({
            "revision": revision,
            "executable_sha256": digest(binary),
            "requirement": command(["codesign", "-d", "-r-", str(app)]).stdout.strip(),
        })
        print(json.dumps(builds[-1]), flush=True)
    assert builds[-1]["executable_sha256"] != builds[-2]["executable_sha256"]
    assert len({b["requirement"] for b in builds}) == 1
    report = {
        **original,
        "builds": builds,
        "source_sha256": {p.name: digest(p) for p in sources},
        "original_build_report_sha256": digest(root / "build-report.json"),
        "installed": False,
    }
    report_file.write_text(json.dumps(report, indent=2))
    print(json.dumps({"report": str(report_file), "installed": False}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--address", required=True)
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()
    prepare(args.root, args.identity, args.address, args.port)
