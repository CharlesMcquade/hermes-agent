"""Opt-in launchd crash/cleanup gate for synthetic Verity Controller Lab only."""

import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
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
    root = root.resolve(strict=True)
    manifest = json.loads((root / "production-release.json").read_text())
    report = json.loads((root / "build-report.json").read_text())
    assert report["root"] == str(root) and report["synthetic_services"] is True
    assert manifest["native_host"]["bundle_id"] == "com.charles.verity.controllerlab"
    assert all(
        re.fullmatch(r"com\.charles\.verity\.controllerlab\.\d+\.(agent|webui)", v)
        for v in manifest["labels"].values()
    )
    assert {
        Path(manifest["services"][r]["plist_path"]).parent for r in ("agent", "webui")
    } == {root}
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
    if any(alive(pid) for pid in ids):
        return False
    output = subprocess.run(
        ["/bin/ps", "-axo", "pid=,pgid="], check=True, capture_output=True, text=True
    ).stdout
    return not any(int(line.split()[1]) in groups for line in output.splitlines())


def verify(root):
    root, manifest = lab(root)
    loaded, records = [], []
    report = {"cases": [], "synthetic_services": True, "status": "running"}
    try:
        # No shell/interactive invocation accepted: launchd ownership is required.
        bare = subprocess.run(
            [manifest["native_host"]["executable"], "webui"], capture_output=True
        )
        assert bare.returncode == 64
        report["cases"].append({"name": "reject_non_launchd_start", "passed": True})
        for role in ("agent", "webui"):
            target = f"gui/{os.getuid()}/" + manifest["labels"][role]
            assert launchctl("print", target, check=False).returncode != 0
            launchctl("bootstrap", f"gui/{os.getuid()}", str(root / (role + ".plist")))
            loaded.append(target)
        pair = {
            r: until(lambda r=r: current(root, manifest, r)) for r in ("agent", "webui")
        }
        records.extend(pair.values())
        report["cases"].append({
            "name": "native_pair_and_shared_groups",
            "passed": True,
            "pair": pair,
        })
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
            until(lambda: all(gone(r) for r in records) and all_recorded_gone(root))
        except AssertionError:
            errors.append("Known fixture PIDs survived unload")
        report["cleanup_verified"] = not errors
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
                "cleanup_verified": not errors,
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
