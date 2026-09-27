"""Opt-in signed-host blocked-worker cleanup tests; no consent or private APIs."""

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from permissions_probe import MAX_WORKERS
from run_probe import read_events, run
from verify_live import event, gone
from verify_signed_live import no_job, select


def verify_gone(receipt):
    workers = [e for e in receipt["events"] if e["event"] == "worker-start"]
    assert len(workers) == MAX_WORKERS
    parent = event(receipt, "python-start")
    assert all(e["ppid"] == parent["pid"] for e in workers)
    pids = [e["pid"] for e in workers] + [
        parent["pid"],
        event(receipt, "host-start")["pid"],
    ]
    assert all(gone(pid) for pid in pids), "A lab descendant survived cleanup"
    assert no_job() and receipt["unloaded"]
    return len(workers)


def signalled(root, sig):
    before = set((root / "runs").iterdir())
    runner = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).with_name("run_probe.py")),
            "--root",
            str(root),
            "--mode",
            "permissions-sleep",
            "--timeout",
            "20",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            fresh = set((root / "runs").iterdir()) - before
            if fresh:
                assert len(fresh) == 1, "Concurrent lab run"
                records = read_events(fresh.pop() / "stdout.jsonl")
                workers = [e for e in records if e["event"] == "worker-start"]
                if len(workers) == MAX_WORKERS:
                    parent = next(e for e in records if e["event"] == "python-start")
                    # Only signal this run's exact supervisor, not a name-matched process.
                    os.kill(parent["pid"], sig)
                    break
            assert runner.poll() is None
            time.sleep(0.05)
        else:
            raise AssertionError("Workers did not start before host deadline")
        stdout, _ = runner.communicate(timeout=20)
        assert runner.returncode == 128 + sig
        receipt = json.loads(stdout)
        assert not any(e["event"] == "deadline" for e in receipt["events"])
        assert event(receipt, "probe-complete")["exit_code"] == 128 + sig
        return receipt
    finally:
        if runner.poll() is None:
            runner.terminate()  # Runner unloads its exact owned launchd job.
            runner.communicate(timeout=15)


def verify(root):
    report = json.loads((root / "expanded-build-report.json").read_text())
    assert no_job()
    results, failure = [], None
    try:
        select(root, "three", report)
        for name, sig in (
            ("supervisor-sigterm", signal.SIGTERM),
            ("supervisor-sigint", signal.SIGINT),
            ("host-hard-deadline", None),
        ):
            if sig:
                receipt = signalled(root, sig)
            else:
                with contextlib.redirect_stdout(io.StringIO()):
                    receipt = run(root, mode="permissions-sleep", timeout=20)
                assert receipt["exit_code"] == 124
                assert any(e["event"] == "deadline" for e in receipt["events"])
            count = verify_gone(receipt)
            result = dict(
                case=name,
                passed=True,
                workers_gone=count,
                receipt=str(Path(receipt["run_dir"]) / "receipt.json"),
            )
            results.append(result)
            print(json.dumps(result), flush=True)
    except BaseException as exc:
        failure = type(exc).__name__
        raise
    finally:
        if no_job():
            select(root, "three", report)
        (root / "worker-verification.json").write_text(
            json.dumps(
                dict(
                    passed=len(results),
                    failure_type=failure,
                    cases=results,
                    no_loaded_job=no_job(),
                    scope="Blocked dummy workers under the actual signed host; hard deadline uses the verified child process group. Cleanup verified after runner bootout.",
                ),
                indent=2,
            )
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    verify(parser.parse_args().root.resolve())
