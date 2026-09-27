"""Live macOS checks after the operator approves prototype camera and Finder consent.

This is an opt-in experiment harness, not part of the unattended test suite.
It never requests additional permissions. Requires the artifacts from build.py.
"""

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import time

from build import NAME
from run_probe import run


def event(receipt, name):
    return next(e for e in receipt["events"] if e["event"] == name)


def gone(pid):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.1)
    return False


def verify(root):
    results = []
    receipts = {}
    scenarios = [
        ("host-a", {"slot": "a"}),
        ("host-b", {"slot": "b"}),
        ("bare-b-negative-control", {"slot": "b", "bare": True}),
        ("child-exit-propagation", {"mode": "fail"}),
        ("host-sigterm-child-cleanup", {"mode": "sleep", "terminate": True}),
        ("host-b-after-controls", {"slot": "b"}),
    ]
    for name, options in scenarios:
        with contextlib.redirect_stdout(io.StringIO()):
            receipt = run(root, **options)
        receipts[name] = receipt
        expected_exit = (
            23
            if options.get("mode") == "fail"
            else 143
            if options.get("terminate")
            else 0
        )
        assert receipt["exit_code"] == expected_exit
        assert "state = not running" in receipt["final_launchd_state"]
        py = event(receipt, "python-start")
        if options.get("bare"):
            assert py["ppid"] == 1
            assert event(receipt, "child-camera")["status"] == 0
            assert event(receipt, "finder-authorization")["status"] == -1744
        else:
            host = event(receipt, "host-start")
            assert host["ppid"] == 1
            assert (
                py["ppid"] == host["pid"] == event(receipt, "child-start")["host_pid"]
            )
            assert py["pid"] == event(receipt, "child-start")["child_pid"]
            assert set(py["env_keys"]) <= {
                "HOME",
                "LC_CTYPE",
                "PATH",
                "PYTHONDONTWRITEBYTECODE",
                "PYTHONHOME",
                "TMPDIR",
                "__CF_USER_TEXT_ENCODING",
            }
            if options.get("mode") == "fail":
                assert event(receipt, "child-exit")["status"] == 23
                assert "last exit code = 23" in receipt["final_launchd_state"]
            elif options.get("terminate"):
                assert event(receipt, "host-signal")["signal"] == 15
                assert event(receipt, "child-exit")["status"] == 15
            else:
                assert host["camera"] == event(receipt, "child-camera")["status"] == 3
                assert event(receipt, "finder-authorization")["status"] == 0
                assert event(receipt, "finder-authorization")["requested"] is False
                assert event(receipt, "finder-operation")["exit_code"] == 0
                assert event(receipt, "child-exit")["status"] == 0
            assert gone(host["pid"]), "Host survived unloading"
        assert gone(py["pid"]), "Python survived unloading"
        assert receipt["unloaded"]
        results.append({
            "case": name,
            "passed": True,
            "receipt": str(Path(receipt["run_dir"]) / "receipt.json"),
        })
        print(json.dumps(results[-1]), flush=True)
    a = event(receipts["host-a"], "python-start")["executable"]
    b = event(receipts["host-b"], "python-start")["executable"]
    assert a != b and Path(a).stat().st_ino != Path(b).stat().st_ino
    binary = root / f"{NAME}.app/Contents/MacOS/VerityPrototype"
    rejected = subprocess.run(
        [str(binary), "b", "arbitrary-command"], capture_output=True
    )
    assert rejected.returncode == 64 and not rejected.stdout
    results.append({"case": "invalid-mode-rejected", "passed": True})
    report = {
        "passed": len(results),
        "failed": 0,
        "cases": results,
        "signing_continuity_tested": False,
        "python_minor_swap_tested": False,
        "scope": "Camera authorization status only; actual read-only Finder event. No capture or private content output.",
    }
    (root / "verification.json").write_text(json.dumps(report, indent=2))
    print(
        json.dumps({
            "passed": len(results),
            "failed": 0,
            "report": str(root / "verification.json"),
        })
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    verify(parser.parse_args().root.resolve())
