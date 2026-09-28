"""Reversible, lab-only service-topology runner. No production job writes."""

import contextlib
import fcntl
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import time

from build_combined_lab import ID, NAME
from build_controller_lab import digest, run

SOURCE = Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE.parents[1] / "scripts/production_control"))
from production_launcher import inventory  # noqa: E402
from native_identity import process_identity, verify_signature  # noqa: E402
from restart_production import ControlError  # noqa: E402
from verify_service_host_live import launchctl, alive, until  # noqa: E402


def events(path):
    if not path.exists():
        return []
    result = []
    for line in path.read_text().splitlines():
        if line.startswith("{"):
            try:
                result.append(json.loads(line))
            except ValueError:
                pass  # In-flight incomplete line, never counted as completion.
    return result


class Lab:
    def __init__(self, root):
        if sys.flags.optimize:
            raise RuntimeError("Safety assertions must be enabled")
        self.root = root.resolve(strict=True)
        self.meta = json.loads((self.root / "combined-build.json").read_text())
        assert self.meta["root"] == str(self.root)
        self.original = Path(self.meta["active_app"])
        self.lab = Path(self.meta["lab"])
        assert (
            self.original == self.lab / NAME
            and self.original.resolve() == self.original
        )
        self.candidate = Path(self.meta["candidate_app"])
        assert self.candidate == self.root / "staged" / NAME
        self.manifest = json.loads((self.root / "production-release.json").read_text())
        self.probes = json.loads((self.root / "probe-services.json").read_text())
        self.saved_manifest = (self.root / "production-release.json").read_bytes()
        assert self.meta["labels"] == self.manifest["labels"]
        assert all(
            re.fullmatch(r"com\.charles\.verity\.combined\.\d+\.(agent|webui)", v)
            for v in self.meta["labels"].values()
        )
        self.jobs = []
        self.paths = []
        self.pids = set()
        self.groups = set()
        self.clean = False
        self.restored = False

    def no_jobs(self):
        listed = launchctl("list").stdout
        assert not any(
            ID + ".probe" in line or "com.charles.verity.combined." in line
            for line in listed.splitlines()
        ), "Lab job already loaded"
        # Refuse replacing a lab binary in use. Read executable paths only.
        out = subprocess.check_output(["/bin/ps", "-axo", "pid=,comm="], text=True)
        assert not any(str(self.original) in line for line in out.splitlines()), (
            "Lab app in use"
        )

    def check_signature(self, app):
        run([
            "/usr/bin/codesign",
            "--verify",
            "--strict",
            "-R",
            "=" + self.meta["requirement"],
            str(app),
        ])

    @contextlib.contextmanager
    def installed(self):
        with (self.lab / "combined-test.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.no_jobs()
            assert inventory(self.original) == self.meta["original_inventory"]
            assert inventory(self.candidate) == self.meta["candidate_inventory"]
            self.check_signature(self.original)
            self.check_signature(self.candidate)
            parked = self.root / "original-preserved.bundle"
            staging = self.lab / ".combined-stage.app"
            assert not parked.exists() and not staging.exists()
            shutil.copytree(self.candidate, staging)
            prior = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}

            def interrupted(signum, frame):
                raise InterruptedError("Lab runner interrupted")

            for sig in prior:
                signal.signal(sig, interrupted)
            try:
                self.original.rename(parked)
                staging.rename(self.original)
                self.check_signature(self.original)
                yield self
            finally:
                for sig in prior:
                    signal.signal(sig, signal.SIG_IGN)
                try:
                    for target in reversed(self.jobs):
                        launchctl("bootout", "--wait", target, check=False)
                    self.collect()
                    self.no_jobs()
                    until(self.known_gone)
                    self.clean = True
                finally:
                    # Restoration is attempted even if cleanup proof fails. Never
                    # mutate a production bundle or discard the parked original.
                    if parked.exists():
                        if self.original.exists():
                            self.original.rename(
                                self.root / f"used-service-host-{time.time_ns()}.bundle"
                            )
                        parked.rename(self.original)
                    if staging.exists():
                        shutil.rmtree(staging)
                    (self.root / "production-release.json").write_bytes(
                        self.saved_manifest
                    )
                    self.restored = (
                        inventory(self.original) == self.meta["original_inventory"]
                    )
                    self.check_signature(self.original)
                    assert self.restored
                    for sig, handler in prior.items():
                        signal.signal(sig, handler)

    def collect(self):
        for path in self.paths:
            for event in events(path):
                if event.get("event") == "service-host":
                    self.pids.update(
                        event[k] for k in ("pid", "child_pid", "guard_pid")
                    )
                    self.groups.add(event["pgid"])
                elif event.get("event") in ("python-start", "worker-start"):
                    self.pids.add(event["pid"])

    def known_gone(self):
        if any(alive(pid) for pid in self.pids):
            return False
        output = subprocess.check_output(["/bin/ps", "-axo", "pid=,pgid="], text=True)
        return not any(
            int(line.split()[1]) in self.groups for line in output.splitlines()
        )

    def start(self, role, slot=None, bare=False, keepalive=False):
        assert role in ("agent", "webui") and (slot is None or slot in ("a", "b"))
        self.no_jobs()
        assert inventory(self.original) == self.meta["candidate_inventory"]
        manifest = json.loads(self.saved_manifest)
        if slot is not None:
            manifest["services"][role] = self.probes[slot]
        else:
            assert role == "webui" and not bare
        (self.root / "production-release.json").write_text(
            json.dumps(manifest, indent=2) + "\n"
        )
        item = manifest["services"][role]
        assert item.get("env_files") == []
        # The agent role can only be our check-only probe, never a real gateway.
        if role == "agent":
            assert item["argv"][5:7] == [
                str(self.root / "probe/permissions_probe.py"),
                "permissions-check",
            ]
        directory = self.root / "runs" / str(time.time_ns())
        directory.mkdir()
        label = self.meta["labels"][role]
        target = f"gui/{os.getuid()}/" + label
        out = directory / "out.jsonl"
        definition = {
            "Label": label,
            "RunAtLoad": True,
            "KeepAlive": keepalive,
            "ThrottleInterval": 1,
            "AbandonProcessGroup": False,
            "WorkingDirectory": str(self.root),
            "StandardOutPath": str(out),
            "StandardErrorPath": str(directory / "err.log"),
        }
        if bare:
            definition.update(
                ProgramArguments=item["argv"], EnvironmentVariables=item["env"]
            )
        else:
            definition.update(
                ProgramArguments=[
                    str(self.original / "Contents/MacOS/VerityServiceHost"),
                    role,
                ],
                AssociatedBundleIdentifiers=[ID],
            )
        plist = directory / "job.plist"
        plist.write_bytes(plistlib.dumps(definition))
        assert launchctl("print", target, check=False).returncode != 0
        self.paths.append(out)
        self.jobs.append(target)
        launchctl("bootstrap", f"gui/{os.getuid()}", str(plist))
        return target, out, manifest

    def stop(self, target):
        launchctl("bootout", "--wait", target, check=False)
        assert launchctl("print", target, check=False).returncode != 0
        self.collect()
        until(self.known_gone)

    def permission(self, role, slot, bare=False):
        target, out, manifest = self.start(role, slot, bare)
        try:
            until(
                lambda: any(e.get("event") == "probe-complete" for e in events(out)), 45
            )
            until(
                lambda: "state = not running" in launchctl("print", target).stdout, 10
            )
            result = events(out)
            end = next(e for e in result if e.get("event") == "probe-complete")
            assert end["exit_code"] == 0
            py = next(e for e in result if e.get("event") == "python-start")
            if bare:
                assert py["ppid"] == 1
            else:
                host = next(e for e in result if e.get("event") == "service-host")
                assert py["ppid"] == host["pid"] and host["child_pid"] == py["pid"]
                assert any(
                    e.get("event") == "service-exit" and e["status"] == 0
                    for e in result
                )
            assert py["executable"] == manifest["services"][role]["argv"][0]
            return {
                "role": role,
                "slot": slot,
                "bare": bare,
                "events": result,
                "output": str(out),
            }
        finally:
            self.stop(target)

    def web_identity(self, target, manifest):
        output = launchctl("print", target).stdout
        match = re.search(r"^\s*pid = (\d+)\s*$", output, re.M)
        if not match:
            return None
        host = int(match[1])
        from restart_production import Host

        listeners = Host().listener(manifest["health_url"])
        if len(listeners) != 1:
            return None
        child = next(iter(listeners))
        parent = process_identity(host)
        record = process_identity(child)
        assert parent["ppid"] == 1 and record["ppid"] == host
        assert parent["executable"] == str(
            self.original / "Contents/MacOS/VerityServiceHost"
        )
        assert parent["argv"] == [parent["executable"], "webui"]
        assert record["argv"] == manifest["services"]["webui"]["argv"]
        assert verify_signature(host, self.meta["requirement"])
        self.pids.update((host, child))
        self.groups.add(host)
        return {"host": parent, "child": record}

    def audit(self):
        assert (
            digest(Path(self.meta["selected_manifest"]))
            == self.meta["production_manifest_sha256"]
        )
        return {
            "lab_restored_exactly": self.restored,
            "known_processes_gone": self.clean,
            "production_selection_unchanged": True,
            "permission_requests": False,
            "real_gateway_started": False,
        }
