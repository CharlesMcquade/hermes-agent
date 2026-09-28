"""Opt-in failed-start reporting regressions on synthetic launchd services."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from verify_service_host_live import all_recorded_gone, lab, launchctl


def verify(root):
    root, manifest = lab(root)
    cases = []
    for script, report in (
        ("verify_service_host_live.py", "host-live-verification.json"),
        ("verify_controller_live.py", "controller-live-verification.json"),
    ):
        for label in manifest["labels"].values():
            assert (
                launchctl(
                    "print", f"gui/{os.getuid()}/" + label, check=False
                ).returncode
                != 0
            )
        marker = root / "startup-block"
        assert not marker.exists()
        marker.touch()
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(Path(__file__).with_name(script)),
                    "--root",
                    str(root),
                ],
                capture_output=True,
                text=True,
                timeout=90,
            )
            proof = json.loads((root / report).read_text())
            assert result.returncode != 0 and proof["status"] == "failed", proof
            assert (
                not proof["cleanup_verified"]
                and proof["cleanup_status"] == "inconclusive"
            ), proof
            assert proof["error"] == "Timed out waiting for live fixture condition", (
                proof
            )
            # Failure is deliberate; do not overwrite it with subsequent success.
            saved = root / ("failed-start-" + report)
            assert not saved.exists()
            (root / report).rename(saved)
            # Independent post-failure observation, not a claim of exhaustive
            # process accounting inside an interrupted/readiness-failed run.
            assert all_recorded_gone(root)
            for label in manifest["labels"].values():
                assert (
                    launchctl(
                        "print", f"gui/{os.getuid()}/" + label, check=False
                    ).returncode
                    != 0
                )
            cases.append({
                "name": script.removesuffix(".py") + "_failed_start",
                "passed": True,
                "failure_receipt": saved.name,
                "known_processes_gone": True,
                "jobs_unloaded": True,
                "no_false_cleanup_claim": True,
            })
            print(json.dumps(cases[-1]), flush=True)
        finally:
            marker.unlink()
    proof = {"status": "passed", "cases": cases, "synthetic_services": True}
    path = root / "harness-live-verification.json"
    path.write_text(json.dumps(proof, indent=2) + "\n")
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    verify(parser.parse_args().root)
