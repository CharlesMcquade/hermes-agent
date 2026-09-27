"""Finite disposable launchd experiment. Captures receipts and always unloads its job."""

import argparse
import json
import os
from pathlib import Path
import plistlib
import signal
import subprocess
import sys
import time
import uuid

from build import app_identity


def read_events(path):
    events = []
    if path.exists():
        for line in path.read_text().splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # A writer may be halfway through its next line.
    return events


def job_state(target):
    text = subprocess.check_output(["launchctl", "print", target], text=True)
    # Exact job-level fields; ignore nested launchd resource-group state.
    return dict(
        line.strip().split(" = ", 1)
        for line in text.splitlines()
        if line.startswith((
            "\tstate = ",
            "\tpid = ",
            "\tprogram = ",
            "\tlast exit code = ",
        ))
    )


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
    identity, name = app_identity(root)
    app = root / f"{name}.app"
    binary = app / "Contents/MacOS/VerityPrototype"
    assert binary.is_file(), "Build first"
    label = identity + ".probe"
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
        settings = settings.get("runtimes", {}).get(slot, settings)
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
        job["AssociatedBundleIdentifiers"] = [identity]
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
    interrupted = 0

    def on_signal(number, _frame):
        nonlocal interrupted
        # Defer until bootstrap returns so an interruption cannot bypass cleanup
        # between successful registration and recording ownership.
        interrupted = number

    handlers = {s: signal.signal(s, on_signal) for s in (signal.SIGTERM, signal.SIGINT)}
    state = {}
    try:
        subprocess.run(
            ["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist)],
            check=True,
            capture_output=True,
        )
        loaded = True
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not interrupted:
            events = read_events(stdout)
            if (
                terminate
                and not signal_sent
                and any(e["event"] == "python-start" for e in events)
            ):
                receipt["launchd_state"] = [
                    f"{k} = {v}" for k, v in job_state(target).items()
                ]
                subprocess.run(
                    ["launchctl", "kill", "SIGTERM", target],
                    check=True,
                    capture_output=True,
                )
                signal_sent = True
            state = job_state(target)
            # A child-exit log is emitted before the host exits. Wait for launchd
            # to observe the actual exit, not merely the log line.
            if state.get("state") == "not running" and "pid" not in state:
                break
            time.sleep(0.2)
        else:
            if not interrupted:
                receipt["timed_out"] = True
        receipt["final_launchd_state"] = [f"{k} = {v}" for k, v in state.items()]
        events = read_events(stdout)
        code = state.get("last exit code", "")
        receipt["exit_code"] = int(code) if code.isdecimal() else 70
        if receipt.get("timed_out"):
            receipt["exit_code"] = 124
        elif receipt["exit_code"] == 0:
            # A stopped host alone is not proof that the intended probe ran.
            completed = any(e["event"] == "probe-complete" for e in events)
            normal_child = bare or any(
                e["event"] == "child-exit" and e["status"] == 0 for e in events
            )
            if not (completed and normal_child):
                receipt["exit_code"] = 70
                receipt["error"] = "Process exited without a complete probe"
    finally:
        try:
            if loaded:
                result = subprocess.run(
                    ["launchctl", "bootout", target], capture_output=True
                )
                receipt["bootout_exit_code"] = result.returncode
            receipt["unloaded"] = (
                subprocess.run(
                    ["launchctl", "print", target], capture_output=True
                ).returncode
                != 0
            )
            if interrupted:
                receipt["interrupted_signal"] = interrupted
                receipt["exit_code"] = 128 + interrupted
            if not receipt["unloaded"]:
                receipt["exit_code"] = 70
                receipt["error"] = "Prototype job not unloaded"
            receipt["events"] = read_events(stdout)
            (run_dir / "receipt.json").write_text(json.dumps(receipt, indent=2))
        finally:
            for number, handler in handlers.items():
                signal.signal(number, handler)
    print(json.dumps(receipt, indent=2))
    assert receipt["unloaded"], "Prototype job not unloaded"
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
    receipt = run(
        a.root,
        a.slot,
        a.mode,
        a.timeout,
        a.terminate,
        not a.without_association,
        a.bare,
    )
    sys.exit(receipt["exit_code"])
