"""Prompt-free live certificate rebuild/rollback and Python-minor continuity gate."""

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

from build import SIGNED_ID, SIGNED_NAME
from build_signed import digest
from run_probe import run
from verify_live import event, gone


def no_job():
    result = subprocess.run(
        ["launchctl", "print", f"gui/{os.getuid()}/{SIGNED_ID}.probe"],
        capture_output=True,
    )
    return result.returncode != 0


def select(root, revision, report):
    if revision not in ("one", "two") or not no_job():
        raise ValueError("Invalid revision or lab job still loaded")
    source = root / "builds" / revision / f"{SIGNED_NAME}.app"
    expected = next(
        r["executable_sha256"] for r in report["builds"] if r["revision"] == revision
    )
    assert digest(source / "Contents/MacOS/VerityPrototype") == expected
    check = ["codesign", "--verify", "--strict", "-R", "=" + report["requirement"]]
    subprocess.run([*check, str(source)], check=True, capture_output=True)
    installed = root / f"{SIGNED_NAME}.app"
    staging = root / (".stage-" + uuid.uuid4().hex + ".app")
    parked = root / "previous" / uuid.uuid4().hex / installed.name
    parked.parent.mkdir(parents=True)
    shutil.copytree(source, staging)
    try:
        if installed.exists():
            installed.rename(parked)
        staging.rename(installed)
        subprocess.run([*check, str(installed)], check=True, capture_output=True)
        assert digest(installed / "Contents/MacOS/VerityPrototype") == expected
    except BaseException:
        # Restore the old lab bundle on failure; never touch a production app.
        if installed.exists():
            installed.rename(parked.parent / "failed-candidate.app")
        if parked.exists():
            parked.rename(installed)
        raise


def verify(root):
    report = json.loads((root / "build-report.json").read_text())
    results = []
    run_ids = []
    cases = [
        ("initial-311", "one", "a", False),
        ("rebuilt-host-311", "two", "a", False),
        ("rebuilt-host-314", "two", "b", False),
        ("bare-314-negative-control", "two", "b", True),
        ("hosted-314-after-control", "two", "b", False),
        ("rollback-host-311", "one", "a", False),
        ("rollback-host-314", "one", "b", False),
    ]
    failure = None
    try:
        for name, revision, slot, bare in cases:
            select(root, revision, report)
            with contextlib.redirect_stdout(io.StringIO()):
                receipt = run(root, slot=slot, bare=bare)
            assert receipt["exit_code"] == 0 and receipt["unloaded"]
            py = event(receipt, "python-start")
            assert py["version"].startswith("3.11." if slot == "a" else "3.14.")
            assert py["executable"] == str(root / "runtimes" / slot / "python")
            assert not event(receipt, "finder-authorization")["requested"]
            if bare:
                assert py["ppid"] == 1
                assert event(receipt, "child-camera")["status"] == 0
                assert event(receipt, "finder-authorization")["status"] == -1744
            else:
                host = event(receipt, "host-start")
                assert host["build_generation"] == revision
                assert host["bundle"] == SIGNED_ID and host["ppid"] == 1
                assert host["executable"] == str(
                    root / f"{SIGNED_NAME}.app/Contents/MacOS/VerityPrototype"
                )
                assert py["ppid"] == host["pid"]
                assert host["camera"] == event(receipt, "child-camera")["status"] == 3
                assert event(receipt, "finder-authorization")["status"] == 0
                assert event(receipt, "finder-operation")["exit_code"] == 0
                assert gone(host["pid"])
            assert gone(py["pid"])
            run_ids.append(py["pid"])
            result = {
                "case": name,
                "passed": True,
                "host_revision": revision,
                "python_version": py["version"],
                "receipt": str(Path(receipt["run_dir"]) / "receipt.json"),
            }
            results.append(result)
            print(json.dumps(result), flush=True)
        assert len(set(run_ids)) == len(run_ids), "Fresh process requirement failed"
        assert (
            report["builds"][0]["executable_sha256"]
            != report["builds"][1]["executable_sha256"]
        )
        assert report["builds"][0]["requirement"] == report["builds"][1]["requirement"]
        assert report["same_id_adhoc_rejected"]
    except BaseException as exc:
        failure = type(exc).__name__
        raise
    finally:
        if no_job():
            select(root, "one", report)
        output = {
            "passed": len(results),
            "failed": int(failure is not None),
            "failure_type": failure,
            "cases": results,
            "signing_continuity_tested": any(
                r["case"] == "rebuilt-host-311" for r in results
            ),
            "python_minor_swap_tested": any(
                r["case"] == "rebuilt-host-314" for r in results
            ),
            "scope": "Camera authorization status and real Finder event through osascript only",
            "restored_revision": "one" if no_job() else "unknown",
            "no_loaded_job": no_job(),
        }
        (root / "signed-verification.json").write_text(json.dumps(output, indent=2))
    print(
        json.dumps({
            "passed": len(results),
            "failed": 0,
            "report": str(root / "signed-verification.json"),
        })
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", required=True, type=Path)
    verify(p.parse_args().root.resolve())
