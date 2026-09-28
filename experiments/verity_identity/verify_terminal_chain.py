"""Check FDA/AX through the real WebUI PTY, with A/B/A and explicit shell cleanup."""

import argparse
import errno
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import threading
import urllib.error
import urllib.request

from combined_lab import Lab, ControlError, digest, process_identity
from restart_production import Host
from verify_service_host_live import alive, launchctl, until


class TerminalStream:
    def __init__(self, response):
        self.response = response
        self.text = ""
        self.errors = []
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.thread.start()

    def read(self):
        event = None
        try:
            for raw in self.response:
                line = raw.decode().strip()
                if line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    data = json.loads(line[5:])
                    if event == "output":
                        self.text += data["text"]
                    elif event == "terminal_error":
                        self.errors.append(data)
        except (OSError, ValueError) as exc:
            self.errors.append(type(exc).__name__)

    def records(self):
        result = []
        for line in self.text.replace("\r", "").splitlines():
            begin = line.find("{")
            if begin < 0:
                continue
            try:
                result.append(json.loads(line[begin:]))
            except ValueError:
                continue
        return result


def check_result(records, bare):
    assert (
        sum(
            r.get("event") == "chain-complete" and r.get("exit_code") == 0
            for r in records
        )
        == 1
    )
    assert any(
        r.get("event") == "network-control"
        and r.get("errno") in (errno.EPERM, errno.EACCES)
        for r in records
    )
    permissions = [r for r in records if r.get("event") == "permission"]
    assert all(not r.get("requested", False) for r in permissions)
    for name in (
        "Full Disk Access: Messages",
        "Full Disk Access: Safari",
        "Accessibility",
        "Accessibility Finder role",
    ):
        rows = [r for r in permissions if r.get("name") == name]
        assert len(rows) == 1, name
        assert rows[0]["allowed"] is (not bare), (name, rows[0])
        if name.startswith("Full Disk Access:"):
            assert rows[0]["status"] == ("denied" if bare else "opened_read_only")
    return permissions


def verify(root):
    lab = Lab(root)
    assert (
        digest(root / "terminal_permission_probe.py")
        == lab.meta["terminal_probe_sha256"]
    )
    report = {
        "status": "running",
        "cases": [],
        "terminal_api": True,
        "inference_requested": False,
    }
    try:
        with lab.installed():
            for bare, slots, name in (
                (False, ("a", "b"), "hosted"),
                (True, ("a", "b"), "bare"),
                (False, ("b",), "hosted_recheck"),
            ):
                target, out, manifest = lab.start("webui", bare=bare, sandbox=True)
                base = manifest["health_url"].removesuffix("/health")
                session = None
                shell = None
                stream = None

                def request(path, body=None, sse=False):
                    req = urllib.request.Request(
                        base + path,
                        data=None if body is None else json.dumps(body).encode(),
                        headers={"Origin": base, "Content-Type": "application/json"},
                    )
                    response = urllib.request.urlopen(req, timeout=90 if sse else 10)
                    if sse:
                        return response
                    with response:
                        return json.load(response)

                def ready():
                    try:
                        if not bare:
                            identity = lab.web_identity(target, manifest)
                            if not identity:
                                return None
                        else:
                            match = re.search(
                                r"^\s*pid = (\d+)\s*$",
                                launchctl("print", target).stdout,
                                re.M,
                            )
                            if not match:
                                return None
                            pid = int(match[1])
                            if Host().listener(manifest["health_url"]) != {pid}:
                                return None
                            child = process_identity(pid)
                            assert child["ppid"] == 1
                            assert (
                                child["argv"] == manifest["services"]["webui"]["argv"]
                            )
                            lab.pids.add(pid)
                            lab.groups.add(os.getpgid(pid))
                            identity = {"child": child}
                        assert request("/health?deep=1")["status"] == "ok"
                        return identity
                    except (ControlError, urllib.error.URLError):
                        return None

                try:
                    identity = until(ready, 90)
                    server_pid = identity["child"]["pid"]
                    session = request(
                        "/api/session/new", {"workspace": str(root), "worktree": False}
                    )["session"]["session_id"]
                    started = request(
                        "/api/terminal/start",
                        {
                            "session_id": session,
                            "rows": 24,
                            "cols": 120,
                            "restart": False,
                        },
                    )
                    assert started["running"] and started["workspace"] == str(root)
                    children = subprocess.check_output(
                        ["/bin/ps", "-axo", "pid=,ppid="], text=True
                    )
                    shells = [
                        process_identity(int(row.split()[0]))
                        for row in children.splitlines()
                        if int(row.split()[1]) == server_pid
                    ]
                    shells = [p for p in shells if p["argv"] == ["/bin/sh", "-i"]]
                    assert len(shells) == 1, "exact PTY shell not found"
                    shell = shells[0]
                    shell_group = os.getpgid(shell["pid"])
                    assert shell_group == shell["pid"] and shell_group != os.getpgrp()
                    lab.pids.add(shell["pid"])
                    lab.groups.add(shell_group)
                    stream = TerminalStream(
                        request("/api/terminal/output?session_id=" + session, sse=True)
                    )
                    for slot in slots:
                        stream.text = ""
                        item = lab.probes[slot]
                        argv = [
                            "/usr/bin/env",
                            "-i",
                            "HOME=" + str(root / "home"),
                            "PYTHONHOME=" + item["env"]["PYTHONHOME"],
                            "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
                            "TMPDIR=" + str(root / "tmp"),
                            item["argv"][0],
                            "-S",
                            "-s",
                            "-P",
                            "-u",
                            str(root / "terminal_permission_probe.py"),
                            str(root),
                            slot,
                        ]
                        command = (
                            shlex.join(argv)
                            + '; printf "\\nVERITY_STATUS:%s\\n" "$?"\n'
                        )
                        assert request(
                            "/api/terminal/input",
                            {"session_id": session, "data": command},
                        )["ok"]
                        start = until(
                            lambda: next(
                                (
                                    r
                                    for r in stream.records()
                                    if r.get("event") == "chain-start"
                                ),
                                None,
                            ),
                            15,
                        )
                        chain = process_identity(start["pid"])
                        assert chain["ppid"] == shell["pid"]
                        assert chain["executable"] == item["argv"][0]
                        assert process_identity(shell["pid"]) == shell
                        assert process_identity(server_pid) == identity["child"]
                        lab.pids.add(chain["pid"])
                        lab.groups.add(start["pgid"])
                        assert request(
                            "/api/terminal/input",
                            {"session_id": session, "data": "GO\n"},
                        )["ok"]
                        until(
                            lambda: re.search(
                                r"^VERITY_STATUS:\d+$",
                                stream.text.replace("\r", ""),
                                re.M,
                            ),
                            70,
                        )
                        assert re.search(
                            r"^VERITY_STATUS:0$", stream.text.replace("\r", ""), re.M
                        ), "probe command failed"
                        records = stream.records()
                        for event in records:
                            if event.get("event") == "bounded-worker":
                                lab.pids.add(event["pid"])
                        result = check_result(records, bare)
                        assert not stream.errors
                        report["cases"].append({
                            "name": name + "_" + slot,
                            "passed": True,
                            "bare": bare,
                            "identity": identity,
                            "shell": shell,
                            "probe": chain,
                            "permissions": result,
                            "os_outbound_denied": True,
                        })
                        print(
                            json.dumps({"case": name + "_" + slot, "passed": True}),
                            flush=True,
                        )
                finally:
                    if session is not None:
                        try:
                            request("/api/terminal/close", {"session_id": session})
                        finally:
                            if shell is not None:
                                # Narrow fallback only for this verified PTY session group.
                                try:
                                    until(lambda: not alive(shell["pid"]), 5)
                                except AssertionError:
                                    if process_identity(shell["pid"]) == shell:
                                        os.killpg(shell["pid"], signal.SIGKILL)
                    if stream is not None:
                        stream.thread.join(5)
                        stream.response.close()
                    lab.stop(target)
        report["status"] = "passed"
    except BaseException as exc:
        report.update(status="failed", error_type=type(exc).__name__, error=str(exc))
        raise
    finally:
        report.update(lab.audit())
        (root / "terminal-chain-verification.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
        print(json.dumps({k: v for k, v in report.items() if k != "cases"}), flush=True)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    verify(parser.parse_args().root.resolve())
