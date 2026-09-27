"""Opt-in live runner regressions. No permission requests or production services."""

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from build import ID
from run_probe import read_events


def unloaded():
    return (
        subprocess.run(
            ["launchctl", "print", f"gui/{os.getuid()}/{ID}.probe"], capture_output=True
        ).returncode
        != 0
    )


def run_case(root, mode, expected):
    result = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("run_probe.py")),
            "--root",
            str(root),
            "--mode",
            mode,
        ],
        capture_output=True,
        text=True,
        timeout=50,
    )
    receipt = json.loads(result.stdout)
    assert unloaded() and receipt["unloaded"]
    assert result.returncode == expected, (mode, result.returncode, expected)
    assert receipt["exit_code"] == expected
    assert "state = not running" in receipt["final_launchd_state"]
    return receipt


def verify(root):
    results = []
    receipt = run_case(root, "fail", 23)
    assert "last exit code = 23" in receipt["final_launchd_state"]
    results.append({"case": "cli-propagates-failure-after-exit", "passed": True})

    # Remove only a lab copy temporarily; no signed bundle or source runtime change.
    runtime = root / "runtimes/a/python"
    parked = runtime.with_name("python.parked")
    assert unloaded() and not parked.exists()
    runtime.rename(parked)
    try:
        receipt = run_case(root, "check", 70)
        assert any(e["event"] == "spawn-error" for e in receipt["events"])
        results.append({"case": "spawn-error-is-nonzero", "passed": True})
    finally:
        parked.rename(runtime)

    before = set((root / "runs").iterdir())
    runner = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).with_name("run_probe.py")),
            "--root",
            str(root),
            "--mode",
            "sleep",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    receipt_dir = None
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            fresh = set((root / "runs").iterdir()) - before
            if fresh:
                assert len(fresh) == 1, "Concurrent lab run"
                receipt_dir = fresh.pop()
                events = read_events(receipt_dir / "stdout.jsonl")
                if any(e["event"] == "python-start" for e in events):
                    break
            assert runner.poll() is None, "Runner exited before child start"
            time.sleep(0.1)
        else:
            raise AssertionError("No child start")
        runner.send_signal(signal.SIGTERM)
        stdout, stderr = runner.communicate(timeout=15)
        assert runner.returncode == 143, (runner.returncode, stderr)
        receipt = json.loads(stdout)
        assert receipt["interrupted_signal"] == signal.SIGTERM
        assert receipt["unloaded"] and unloaded()
        for e in receipt["events"]:
            if e["event"] in ("host-start", "python-start"):
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        os.kill(e["pid"], 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.1)
                else:
                    raise AssertionError("Process survived runner termination")
        results.append({
            "case": "runner-sigterm-unloads-job-and-children",
            "passed": True,
        })
    finally:
        if runner.poll() is None:
            runner.kill()
            runner.communicate(timeout=10)
        # Regression failure must not leave our test job installed.
        if receipt_dir is not None and not unloaded():
            subprocess.run(
                ["launchctl", "bootout", f"gui/{os.getuid()}/{ID}.probe"], check=True
            )
    report = {"passed": len(results), "failed": 0, "cases": results}
    (root / "runner-verification.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", required=True, type=Path)
    verify(p.parse_args().root.resolve())
