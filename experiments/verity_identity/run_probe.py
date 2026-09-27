"""Finite disposable launchd experiment. Captures receipts and always unloads its job."""

import argparse
import json
import os
from pathlib import Path
import plistlib
import subprocess
import time
import uuid

from build import ID, NAME


def read_events(path):
    events = []
    if path.exists():
        for line in path.read_text().splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # A writer may be halfway through its next line.
    return events


def run(
    root,
    slot="a",
    mode="check",
    timeout=35,
    terminate=False,
    associated=True,
    bare=False,
):
    root = root.resolve()
    app = root / f"{NAME}.app"
    binary = app / "Contents/MacOS/VerityPrototype"
    assert binary.is_file(), "Build first"
    label = ID + ".probe"
    target = f"gui/{os.getuid()}/{label}"
    assert (
        subprocess.run(["launchctl", "print", target], capture_output=True).returncode
        != 0
    ), "A prototype job already exists; do not clobber it"
    run_dir = (
        root / "runs" / (time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6])
    )
    run_dir.mkdir(parents=True)
    stdout, stderr = run_dir / "stdout.jsonl", run_dir / "stderr.log"
    job = {
        "Label": label,
        "ProgramArguments": [str(binary), slot, mode],
        "WorkingDirectory": str(root),
        "RunAtLoad": True,
        "KeepAlive": False,
        "ProcessType": "Interactive",
        "ExitTimeOut": 5,
        "StandardOutPath": str(stdout),
        "StandardErrorPath": str(stderr),
        "EnvironmentVariables": {
            "HOME": str(Path.home()),
            "PATH": "/usr/bin:/bin",
            "TMPDIR": str(root / "tmp"),
        },
    }
    if bare:
        assert mode == "check" and not terminate, (
            "Bare control must never request permission"
        )
        settings = json.loads((app / "Contents/Resources/settings.json").read_text())
        job["ProgramArguments"] = [
            str(root / "runtimes" / slot / "python"),
            "-S",
            "-s",
            "-P",
            "-u",
            str(app / "Contents/Resources/probe.py"),
            "check",
            settings["bridge"],
        ]
        job["EnvironmentVariables"].update(
            PYTHONHOME=settings["pythonHome"], PYTHONDONTWRITEBYTECODE="1"
        )
    elif associated:
        job["AssociatedBundleIdentifiers"] = [ID]
    plist = run_dir / "job.plist"
    plist.write_bytes(plistlib.dumps(job))
    register = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
    subprocess.run([register, "-f", str(app)], check=True, capture_output=True)
    loaded = False
    receipt = {
        "mode": mode,
        "slot": slot,
        "associated": associated and not bare,
        "bare": bare,
        "run_dir": str(run_dir),
    }
    signal_sent = False
    try:
        subprocess.run(
            ["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist)],
            check=True,
            capture_output=True,
        )
        loaded = True
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            events = read_events(stdout)
            if (
                terminate
                and not signal_sent
                and any(e["event"] == "python-start" for e in events)
            ):
                state = subprocess.check_output(
                    ["launchctl", "print", target], text=True
                )
                receipt["launchd_state"] = [
                    s.strip()
                    for s in state.splitlines()
                    if s.strip().startswith(("pid =", "program =", "state ="))
                ]
                subprocess.run(
                    ["launchctl", "kill", "SIGTERM", target],
                    check=True,
                    capture_output=True,
                )
                signal_sent = True
            finished = (
                ("probe-complete",)
                if bare
                else ("child-exit", "spawn-error", "deadline")
            )
            if any(e["event"] in finished for e in events):
                break
            time.sleep(0.2)
        else:
            receipt["timed_out"] = True
        receipt["events"] = read_events(stdout)
        state = subprocess.check_output(["launchctl", "print", target], text=True)
        receipt["final_launchd_state"] = [
            s.strip()
            for s in state.splitlines()
            if s.strip().startswith((
                "pid =",
                "program =",
                "state =",
                "last exit code =",
            ))
        ]
    finally:
        if loaded:
            subprocess.run(
                ["launchctl", "bootout", target], check=True, capture_output=True
            )
        receipt["unloaded"] = (
            subprocess.run(
                ["launchctl", "print", target], capture_output=True
            ).returncode
            != 0
        )
        receipt["events"] = read_events(stdout)
        (run_dir / "receipt.json").write_text(json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))
    assert receipt["unloaded"], "Prototype job not unloaded"
    assert not receipt.get("timed_out"), "No completion before deadline"
    return receipt


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", required=True, type=Path)
    p.add_argument("--slot", choices=["a", "b"], default="a")
    p.add_argument(
        "--mode",
        choices=["check", "request-camera", "request-finder", "sleep", "fail"],
        default="check",
    )
    p.add_argument("--timeout", type=int, default=35)
    p.add_argument("--terminate", action="store_true")
    p.add_argument("--without-association", action="store_true")
    p.add_argument("--bare", action="store_true")
    a = p.parse_args()
    run(
        a.root,
        a.slot,
        a.mode,
        a.timeout,
        a.terminate,
        not a.without_association,
        a.bare,
    )
