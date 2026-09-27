"""Opt-in, check-only expanded grant continuity; reports operational limits honestly."""

import argparse
import contextlib
import io
import json
from pathlib import Path
import re
import subprocess

from build import SIGNED_ID, SIGNED_NAME
from build_signed import digest
from permissions_probe import NAMES
from run_probe import run
from verify_live import event, gone
from verify_signed_live import no_job, select

EXPECTED = {
    "Full Disk Access: Messages": "opened_read_only",
    "Full Disk Access: Safari": "opened_read_only",
    "Accessibility": "authorized",
    "Accessibility Finder role": 0,
    "Input Monitoring": "authorized",
    "Screen Capture": "authorized",
    "Camera": "authorized",
    "Microphone": "authorized",
    "Contacts": "authorized",
    "Calendar": "full_access",
    "Reminders": "full_access",
    "Photos": "authorized",
    "Speech": "authorized",
    "Bluetooth": "authorized",
}
CASES = [
    ("initial-311", "three", "a", False),
    ("rebuilt-host-311", "four", "a", False),
    ("rebuilt-host-314", "four", "b", False),
    ("bare-314-negative-control", "four", "b", True),
    ("hosted-314-after-control", "four", "b", False),
    ("rollback-host-311", "three", "a", False),
    ("rollback-host-314", "three", "b", False),
]


def verify(root):
    report = json.loads((root / "expanded-build-report.json").read_text())
    assert digest(root / "build-report.json") == report["original_build_report_sha256"]
    builds = [r for r in report["builds"] if r["revision"] in ("three", "four")]
    assert (
        len(builds) == 2
        and builds[0]["executable_sha256"] != builds[1]["executable_sha256"]
    )
    for build in builds:
        binary = (
            root
            / "builds"
            / build["revision"]
            / f"{SIGNED_NAME}.app/Contents/MacOS/VerityPrototype"
        )
        info = subprocess.check_output(["otool", "-l", str(binary)], text=True)
        assert re.search(r"\bminos 14\.0\b", info), "Unsupported deployment target"
    results, pids = [], []
    failure = None
    try:
        for name, revision, slot, bare in CASES:
            select(root, revision, report)
            with contextlib.redirect_stdout(io.StringIO()):
                receipt = run(
                    root, slot=slot, mode="permissions-check", timeout=45, bare=bare
                )
            result = {
                "case": name,
                "passed": False,
                "receipt": str(Path(receipt["run_dir"]) / "receipt.json"),
            }
            results.append(result)
            assert receipt["exit_code"] == 0 and receipt["unloaded"]
            py = event(receipt, "python-start")
            assert py["version"].startswith("3.11." if slot == "a" else "3.14.")
            assert py["executable"] == str(root / "runtimes" / slot / "python")
            pids.append(py["pid"])
            permissions = {
                e["name"]: e for e in receipt["events"] if e["event"] == "permission"
            }
            assert set(permissions) == {
                *EXPECTED,
                "Accessibility operation",
                "Location",
            }
            assert all(
                not p["requested"] and p["error_type"] in (None, "EPERM", "EACCES")
                for p in permissions.values()
            )
            if bare:
                assert py["ppid"] == 1
                assert all(permissions[n]["allowed"] is not True for n in EXPECTED)
                for name in ("Full Disk Access: Messages", "Full Disk Access: Safari"):
                    assert permissions[name]["status"] == "denied"
                    assert permissions[name]["error_type"] in ("EPERM", "EACCES")
            else:
                host = event(receipt, "host-start")
                assert (
                    host["build_generation"] == revision and host["bundle"] == SIGNED_ID
                )
                assert host["ppid"] == 1 and py["ppid"] == host["pid"]
                assert host["executable"] == str(
                    root / f"{SIGNED_NAME}.app/Contents/MacOS/VerityPrototype"
                )
                assert all(
                    permissions[n]["allowed"] is True
                    and permissions[n]["status"] == status
                    for n, status in EXPECTED.items()
                )
                assert gone(host["pid"])
            assert gone(py["pid"])
            workers = [e for e in receipt["events"] if e["event"] == "worker-start"]
            assert len(workers) == len(NAMES) and all(
                e["ppid"] == py["pid"] for e in workers
            )
            assert all(gone(e["pid"]) for e in workers)
            result.update(
                passed=True, python_version=py["version"], permissions=permissions
            )
            print(
                json.dumps({k: v for k, v in result.items() if k != "permissions"}),
                flush=True,
            )
        assert len(set(pids)) == len(CASES)
    except BaseException as exc:
        failure = type(exc).__name__
        raise
    finally:
        if no_job():
            select(root, "three", report)
            subprocess.run(
                [
                    "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister",
                    "-f",
                    str(root / f"{SIGNED_NAME}.app"),
                ],
                check=True,
            )
        output = {
            "passed": sum(r["passed"] for r in results),
            "failure_type": failure,
            "cases": results,
            "expected_statuses": EXPECTED,
            "no_loaded_job": no_job(),
            "scope": "FDA read-only open/close without content reads; Finder AX role; remaining categories authorization/preflight only.",
            "not_proven": [
                "Location authorization",
                "successful AX focused-application operation",
                "Local Network enforcement/attribution",
                "production/reboot continuity",
            ],
        }
        (root / "expanded-verification.json").write_text(json.dumps(output, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    verify(parser.parse_args().root.resolve())
