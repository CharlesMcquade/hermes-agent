"""Opt-in launchd crash/cleanup gate for synthetic Verity Controller Lab only."""

import argparse
import copy
import json
import os
from pathlib import Path
import plistlib
import re
import signal
import subprocess
import sys
import time
import urllib.request


def launchctl(*args, check=True):
    return subprocess.run(
        ["/bin/launchctl", *args],
        check=check,
        capture_output=True,
        text=True,
        timeout=30,
    )


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def until(check, seconds=16):
    end = time.monotonic() + seconds
    while True:
        try:
            result = check()
            if result:
                return result
        except (OSError, ValueError, KeyError):
            pass
        if time.monotonic() >= end:
            raise AssertionError("Timed out waiting for live fixture condition")
        time.sleep(0.1)


def lab(root):
    if sys.flags.optimize:
        raise RuntimeError("Do not disable lab safety assertions with -O")
    root = root.resolve(strict=True)
    manifest = json.loads((root / "production-release.json").read_text())
    report = json.loads((root / "build-report.json").read_text())
    assert report["root"] == str(root) and report["synthetic_services"] is True
    assert manifest["native_host"]["bundle_id"] == "com.charles.verity.controllerlab"
    assert all(
        re.fullmatch(r"com\.charles\.verity\.controllerlab\.\d+\.(agent|webui)", v)
        for v in manifest["labels"].values()
    )
    assert set(manifest["labels"]) == set(manifest["services"]) == {"agent", "webui"}
    assert manifest["labels"] == report["labels"]
    app = root / "Verity Controller Lab.app"
    exe = app / "Contents/MacOS/VerityServiceHost"
    assert manifest["native_host"]["bundle"] == str(app)
    assert manifest["native_host"]["executable"] == str(exe)
    assert exe.resolve(strict=True) == exe and exe.is_file()
    assert manifest["state_dir"] == str(root / "state")
    for role in ("agent", "webui"):
        path = root / (role + ".plist")
        assert path.resolve(strict=True) == path
        item = manifest["services"][role]
        assert item["plist_path"] == str(path)
        assert item["repo"] == item["cwd"] == str(root / role)
        assert (root / role).resolve(strict=True) == root / role
        expected = {
            "Label": manifest["labels"][role],
            "ProgramArguments": [str(exe), role],
            "WorkingDirectory": str(root),
            "RunAtLoad": True,
            "KeepAlive": True,
            "AssociatedBundleIdentifiers": ["com.charles.verity.controllerlab"],
            "ThrottleInterval": 1,
            "AbandonProcessGroup": False,
            "StandardOutPath": str(root / (role + ".out")),
            "StandardErrorPath": str(root / (role + ".err")),
        }
        assert plistlib.loads(path.read_bytes()) == expected, (
            "Unexpected actual lab plist"
        )
        for output in (role + ".out", role + ".err"):
            assert (root / output).resolve() == root / output
    assert (root / "state").resolve(strict=True) == root / "state"
    return root, manifest


def current(root, manifest, role):
    target = f"gui/{os.getuid()}/" + manifest["labels"][role]
    output = launchctl("print", target).stdout
    match = re.search(r"^\s*pid = (\d+)$", output, re.M)
    if not match:
        return None
    pid = int(match[1])
    records = [
        json.loads(line)
        for line in (root / "state/processes.jsonl").read_text().splitlines()
    ]
    matches = [r for r in records if r["role"] == role and r["ppid"] == pid]
    if not matches:
        return None
    record = matches[-1]
    hosts = [
        json.loads(line)
        for line in (root / (role + ".out")).read_text().splitlines()
        if line.startswith("{")
    ]
    host = next(
        h
        for h in reversed(hosts)
        if h.get("event") == "service-host" and h["pid"] == pid
    )
    record["guard"] = host["guard_pid"]
    if not all(alive(record[k]) for k in ("pid", "ppid", "worker", "guard")):
        return None
    assert record["pgid"] == pid and os.getpgid(record["worker"]) == pid
    if role == "webui":
        with urllib.request.urlopen(manifest["health_url"], timeout=1) as response:
            assert json.load(response)["status"] == "ok"
    return record


def gone(record):
    return all(not alive(record[k]) for k in ("pid", "ppid", "worker", "guard"))


def all_recorded_gone(root):
    # Include short-lived crash-loop processes not observed by current().
    ids, groups = set(), set()
    path = root / "state/processes.jsonl"
    if path.exists():
        for line in path.read_text().splitlines():
            record = json.loads(line)
            ids.update(record[k] for k in ("pid", "ppid", "worker"))
            groups.add(record["pgid"])
    for role in ("agent", "webui"):
        path = root / (role + ".out")
        if path.exists():
            for line in path.read_text().splitlines():
                if not line.startswith("{"):
                    continue
                record = json.loads(line)
                if record.get("event") == "service-host":
                    ids.update(record[k] for k in ("pid", "child_pid", "guard_pid"))
                    groups.add(record["pgid"])
    if not ids or not groups:
        return False  # Missing evidence is not proof of an empty process tree.
    if any(alive(pid) for pid in ids):
        return False
    output = subprocess.run(
        ["/bin/ps", "-axo", "pid=,pgid="], check=True, capture_output=True, text=True
    ).stdout
    return not any(int(line.split()[1]) in groups for line in output.splitlines())


def set_cleanup_outcome(report, errors, attempted):
    # Conservatively withhold a complete-accounting claim for failed runs: a
    # process may have started before its first receipt was emitted.
    if errors:
        state = "failed"
    elif not attempted:
        state = "not_started"
    elif report["status"] == "failed":
        state = "inconclusive"
    else:
        state = "verified"
    report["cleanup_status"] = state
    report["cleanup_verified"] = state == "verified"


def record_initial_pair(report, pair):
    report["cases"].append({
        "name": "native_pair_and_shared_groups",
        "passed": True,
        "pair": copy.deepcopy(pair),
    })


def verify(root):
    root, manifest = lab(root)
    loaded, records = [], []
    report = {"cases": [], "synthetic_services": True, "status": "running"}
    try:
        # Validate the signed on-disk host before executing even its negative case.
        control = Path(__file__).resolve().parents[2] / "scripts/production_control"
        sys.path.insert(0, str(control))
        from restart_production import Controller

        Controller(root).preflight(manifest)
        # No shell/interactive invocation accepted: launchd ownership is required.
        bare = subprocess.run(
            [manifest["native_host"]["executable"], "webui"], capture_output=True
        )
        assert bare.returncode == 64
        report["cases"].append({"name": "reject_non_launchd_start", "passed": True})
        for role in ("agent", "webui"):
            target = f"gui/{os.getuid()}/" + manifest["labels"][role]
            assert launchctl("print", target, check=False).returncode != 0
            loaded.append(target)  # Also clean up a partially successful bootstrap.
            launchctl("bootstrap", f"gui/{os.getuid()}", str(root / (role + ".plist")))
        pair = {
            r: until(lambda r=r: current(root, manifest, r)) for r in ("agent", "webui")
        }
        records.extend(pair.values())
        record_initial_pair(report, pair)
        cases = [
            ("webui_host_sigterm", "webui", "ppid", signal.SIGTERM),
            ("agent_child_sigkill", "agent", "pid", signal.SIGKILL),
            ("webui_host_sigkill", "webui", "ppid", signal.SIGKILL),
            ("webui_guard_sigkill", "webui", "guard", signal.SIGKILL),
            ("agent_kickstart", "agent", "ppid", None),
        ]
        for name, role, field, sig in cases:
            old = pair[role]
            sibling = "webui" if role == "agent" else "agent"
            if sig is None:
                launchctl(
                    "kickstart", "-k", f"gui/{os.getuid()}/" + manifest["labels"][role]
                )
            else:
                # Confirm exact launchd ownership again immediately before signaling.
                assert current(root, manifest, role) == old
                os.kill(old[field], sig)

            def replacement():
                value = current(root, manifest, role)
                return value if value and value["ppid"] != old["ppid"] else None

            pair[role] = until(replacement)
            records.append(pair[role])
            until(lambda: gone(old))
            assert current(root, manifest, sibling) == pair[sibling]
            case = {
                "name": name,
                "passed": True,
                "old": old,
                "new": pair[role],
                "old_group_gone": True,
                "sibling_unchanged": True,
            }
            report["cases"].append(case)
            print(json.dumps({"case": name, "passed": True}), flush=True)
    except BaseException as exc:
        report.update(status="failed", error_type=type(exc).__name__, error=str(exc))
        raise
    finally:
        errors = []
        for target in reversed(loaded):
            launchctl("bootout", "--wait", target, check=False)
            if launchctl("print", target, check=False).returncode == 0:
                errors.append("Still loaded: " + target)
        try:
            if loaded:
                until(lambda: all(gone(r) for r in records) and all_recorded_gone(root))
        except AssertionError:
            errors.append("Known fixture PIDs survived unload")
        set_cleanup_outcome(report, errors, loaded)
        if errors:
            report.update(status="failed", cleanup_errors=errors)
        elif report["status"] == "running":
            report["status"] = "passed"
        (root / "host-live-verification.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
        print(
            json.dumps({
                "report": str(root / "host-live-verification.json"),
                "status": report["status"],
                "cleanup_verified": report["cleanup_verified"],
                "cleanup_status": report["cleanup_status"],
            }),
            flush=True,
        )
        if errors:
            raise AssertionError(errors)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    verify(parser.parse_args().root)
