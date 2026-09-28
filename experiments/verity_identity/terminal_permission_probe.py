"""Fixed, bounded worker set for the real WebUI PTY experiment; never requests consent."""

import errno
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys

WORKERS = ("Full Disk Access: Messages", "Full Disk Access: Safari", "Accessibility")


def emit(**data):
    print(json.dumps(data), flush=True)


def network_control():
    """A missing OS restriction fails before permissions; no application payload."""
    with socket.socket() as sock:
        sock.settimeout(1)
        code = sock.connect_ex(("192.0.2.1", 9))
    assert code in (errno.EPERM, errno.EACCES), f"OS outbound deny missing: {code}"
    emit(event="network-control", errno=code, passed=True)


def main():
    root, slot = Path(sys.argv[1]).resolve(), sys.argv[2]
    assert slot in ("a", "b")
    item = json.loads((root / "probe-services.json").read_text())[slot]
    assert sys.executable == item["argv"][0]
    emit(
        event="chain-start",
        pid=os.getpid(),
        ppid=os.getppid(),
        pgid=os.getpgrp(),
        executable=sys.executable,
        version=sys.version.split()[0],
    )
    # Hold the exact live chain until the harness has checked kernel ancestry.
    assert select.select([sys.stdin], [], [], 15)[0], "identity handshake timed out"
    assert sys.stdin.readline().strip() == "GO"
    network_control()
    for name in WORKERS:
        env = dict(item["env"])
        if not name.startswith("Full Disk Access:"):
            env["HOME"] = str(root / "home")
        args = item["argv"] + ["--worker", name]
        with subprocess.Popen(
            args,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as child:
            emit(event="bounded-worker", pid=child.pid, ppid=os.getpid(), name=name)
            try:
                out, err = child.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate()
                raise RuntimeError("permission worker deadline") from None
            assert child.returncode == 0, f"worker exit {child.returncode}"
            records = [
                json.loads(line) for line in out.splitlines() if line.startswith("{")
            ]
            assert any(r.get("event") == "permission" for r in records), (
                "missing result"
            )
            for event in records:
                assert not event.get("requested", False)
                emit(**event)
    emit(event="chain-complete", exit_code=0)


if __name__ == "__main__":
    main()
