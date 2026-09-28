"""Stage real WebUI + check-only permissions under the service-host topology.

No launchd writes, application installation, credentials, or production selection.
Uses an operator-approved existing signing lab, whose bundle is swapped only by
an explicit live runner with exact restoration. Never starts a real gateway.
"""

import argparse
import copy
import json
import os
from pathlib import Path
import plistlib
import shutil
import sys

from build_controller_lab import digest, run

SOURCE = Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE.parents[1] / "scripts/production_control"))
from production_launcher import inventory, validate  # noqa: E402

ID = "com.charles.verity.signinglab"
NAME = "Verity Signing Lab.app"


def build(root, lab, identity_file, selected):
    root, lab, selected = (
        root.absolute(),
        lab.resolve(strict=True),
        selected.resolve(strict=True),
    )
    assert root == root.resolve() and root != lab
    active = lab / NAME
    original_info = plistlib.loads((active / "Contents/Info.plist").read_bytes())
    assert original_info["CFBundleIdentifier"] == ID
    original_inventory = inventory(active)
    selected_bytes = selected.read_bytes()
    production = json.loads(selected_bytes)
    # No imports or credential-file reads: only validate the selected source tree.
    validate("webui", production["services"])
    original_webui = production["services"]["webui"]
    interpreter = original_webui["argv"][0]
    runtime = json.loads(
        run([
            interpreter,
            "-I",
            "-c",
            'import json,sys,sysconfig;print(json.dumps({"version":sys.version.split()[0],"site":sysconfig.get_path("purelib")}))',
        ]).stdout
    )
    assert runtime["version"].startswith("3.11.")
    settings = json.loads((active / "Contents/Resources/settings.json").read_text())
    slots = settings["runtimes"]
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in ("home", "tmp", "state", "probe", "staged", "runs"):
        (root / name).mkdir(mode=0o700)
    (root / "state/config.yaml").write_text(
        "model:\n  default: test-model\ngateway:\n  enabled: false\ncron:\n  enabled: false\n"
    )
    control = SOURCE.parents[1] / "scripts/production_control"
    shutil.copyfile(control / "production_launcher.py", root / "production_launcher.py")
    shutil.copyfile(
        SOURCE / "permissions_probe.py", root / "probe/permissions_probe.py"
    )
    shutil.copyfile(SOURCE / "probe.py", root / "probe/probe.py")
    # All probe subprocesses preserve this exact ungranted copied executable.
    probes = {}
    for slot in ("a", "b"):
        executable = lab / "runtimes" / slot / "python"
        assert executable.is_file() and not executable.is_symlink()
        cfg = slots[slot]
        probes[slot] = {
            "repo": str(root / "probe"),
            "cwd": str(root),
            "commit": "check-only-permissions",
            "inventory": inventory(root / "probe"),
            "requires": [],
            "probe_modules": [],
            "env_files": [],
            "argv": [
                str(executable),
                "-S",
                "-s",
                "-P",
                "-u",
                str(root / "probe/permissions_probe.py"),
                "permissions-check",
                cfg["bridge"],
            ],
            "env": {
                "HOME": str(Path.home()),
                "PYTHONHOME": cfg["pythonHome"],
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "TMPDIR": str(root / "tmp"),
                "HERMES_HOME": str(root / "state"),
                "HERMES_BASE_HOME": str(root / "state"),
            },
        }
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    webui = copy.deepcopy(original_webui)
    # The source is real and unchanged; state, credentials and interpreter path aren't production.
    webui.update(
        requires=[],
        env_files=[],
        probe_modules=[],
        argv=[
            str(lab / "runtimes/a/python"),
            "-s",
            "-P",
            "-u",
            str(Path(webui["repo"]) / "server.py"),
        ],
    )
    webui["env"] = {
        "HOME": str(root / "home"),
        "HERMES_HOME": str(root / "state"),
        "HERMES_BASE_HOME": str(root / "state"),
        "HERMES_CONFIG_PATH": str(root / "state/config.yaml"),
        "HERMES_WEBUI_STATE_DIR": str(root / "state/webui"),
        "HERMES_WEBUI_HOST": "127.0.0.1",
        "HERMES_WEBUI_PORT": str(port),
        "HERMES_WEBUI_DEFAULT_WORKSPACE": str(root),
        "HERMES_WEBUI_PASSWORD": "",
        "HERMES_WEBUI_TEST_NETWORK_BLOCK": "1",
        "HERMES_WEBUI_AUTO_INSTALL": "0",
        "HERMES_WEBUI_SKIP_ONBOARDING": "1",
        "HERMES_WEBUI_AGENT_DIR": production["services"]["agent"]["repo"],
        "PYTHONHOME": slots["a"]["pythonHome"],
        "PYTHONPATH": os.pathsep.join([
            webui["repo"],
            production["services"]["agent"]["repo"],
            runtime["site"],
        ]),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "TMPDIR": str(root / "tmp"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
    }
    config = {
        "base": str(root),
        "bootstrap_python": interpreter,
        "launcher": str(root / "production_launcher.py"),
        "launcher_sha256": digest(root / "production_launcher.py"),
        "roles": ["agent", "webui"],
    }
    app = root / "staged" / NAME
    resources = app / "Contents/Resources"
    binary = app / "Contents/MacOS/VerityServiceHost"
    resources.mkdir(parents=True)
    binary.parent.mkdir()
    (resources / "service-settings.json").write_text(
        json.dumps(config, indent=2) + "\n"
    )
    info = dict(
        original_info,
        CFBundleExecutable=binary.name,
        CFBundleVersion="5",
        LSMinimumSystemVersion="14.0",
    )
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
    run([
        "xcrun",
        "swiftc",
        "-target",
        "arm64-apple-macos14.0",
        "-swift-version",
        "5",
        str(SOURCE / "ServiceHost.swift"),
        "-o",
        str(binary),
    ])
    identity = json.loads(identity_file.read_text())
    import re

    pin = identity["sha1"]
    assert re.fullmatch("[0-9a-fA-F]{40}", pin)
    requirement = f'identifier "{ID}" and certificate leaf = H"{pin}"'
    req = root / "requirements.txt"
    req.write_text("designated => " + requirement + "\n")
    run([
        "/usr/bin/codesign",
        "--force",
        "--sign",
        pin,
        "--keychain",
        identity["keychain"],
        "--timestamp=none",
        "--requirements",
        str(req),
        str(app),
    ])
    run([
        "/usr/bin/codesign",
        "--verify",
        "--strict",
        "-R",
        "=" + requirement,
        str(app),
    ])
    manifest = {
        "schema_version": 2,
        "release_id": "isolated-combined-" + production["release_id"],
        "labels": {
            r: f"com.charles.verity.combined.{os.getpid()}.{r}"
            for r in ("agent", "webui")
        },
        "state_dir": str(root / "state"),
        "health_url": f"http://127.0.0.1:{port}/health",
        "services": {"webui": webui, "agent": probes["a"]},
        "native_host": {
            "bundle": str(active),
            "executable": str(active / "Contents/MacOS/VerityServiceHost"),
            "bundle_id": ID,
            "requirement": requirement,
            "inventory": inventory(app),
            "launcher_sha256": config["launcher_sha256"],
        },
    }
    (root / "production-release.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (root / "probe-services.json").write_text(json.dumps(probes, indent=2) + "\n")
    meta = {
        "root": str(root),
        "lab": str(lab),
        "active_app": str(active),
        "candidate_app": str(app),
        "original_inventory": original_inventory,
        "candidate_inventory": inventory(app),
        "requirement": requirement,
        "production_manifest_sha256": digest(selected),
        "selected_manifest": str(selected),
        "source_release": production["release_id"],
        "source_webui": webui["repo"],
        "source_agent": production["services"]["agent"]["repo"],
        "runtime_version": runtime["version"],
        "probe_versions": ["3.11", "3.14"],
        "source_sha256": {
            p.name: digest(p)
            for p in [
                SOURCE / "ServiceHost.swift",
                SOURCE / "permissions_probe.py",
                control / "production_launcher.py",
            ]
        },
        "labels": manifest["labels"],
        "staged_only": True,
        "real_gateway_started": False,
    }
    (root / "combined-build.json").write_text(json.dumps(meta, indent=2) + "\n")
    assert (
        selected.read_bytes() == selected_bytes
        and inventory(active) == original_inventory
    )
    print(
        json.dumps({
            k: meta[k]
            for k in (
                "root",
                "source_release",
                "runtime_version",
                "staged_only",
                "real_gateway_started",
            )
        })
    )
    return root


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "lab", "identity", "selected"):
        parser.add_argument("--" + name, type=Path, required=True)
    a = parser.parse_args()
    build(a.root, a.lab, a.identity, a.selected)
