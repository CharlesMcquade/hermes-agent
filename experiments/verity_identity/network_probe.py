"""One operator-selected on-link TCP endpoint; no discovery or application data.

Even check mode can trigger macOS's Local Network alert when state is unknown.
Use only after consent to this test. A connect success is connectivity evidence,
not independently proof of permission enforcement; use a lab Settings deny/allow
control and a contemporaneous known-working control process.
"""

import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time


def emit(event, **values):
    print(json.dumps(dict(event=event, **values)), flush=True)


def target_from(data):
    ip = ipaddress.ip_address(data["address"])
    ranges = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    if ip.version != 4 or not any(ip in ipaddress.ip_network(r) for r in ranges):
        raise ValueError("An explicit RFC1918 IPv4 target is required")
    port = data["port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid TCP port")
    return str(ip), port


def validate_link(address, route, local_address, mask):
    fields = dict(
        line.strip().split(": ", 1) for line in route.splitlines() if ": " in line
    )
    flags = fields.get("flags", "").strip("<>").split(",")
    interface = fields.get("interface", "")
    if (
        not re.fullmatch(r"en[0-9]+", interface)
        or "UP" not in flags
        or any(flag in flags for flag in ("GATEWAY", "REJECT", "BLACKHOLE"))
    ):
        raise ValueError(
            "Target must use a directly attached en interface, not a router/VPN"
        )
    subnet = ipaddress.IPv4Network(local_address + "/" + mask, strict=False)
    target = ipaddress.IPv4Address(address)
    if target not in subnet or target in (
        subnet.network_address,
        subnet.broadcast_address,
        ipaddress.IPv4Address(local_address),
    ):
        raise ValueError(
            "Target must be a distinct unicast peer in the interface subnet"
        )
    return interface


def verify_on_link(address):
    def query(argv):
        return subprocess.check_output(
            argv, text=True, stderr=subprocess.DEVNULL, timeout=5
        ).strip()

    route = query(["/sbin/route", "-n", "get", address])
    fields = dict(
        line.strip().split(": ", 1) for line in route.splitlines() if ": " in line
    )
    interface = fields.get("interface", "")
    if not re.fullmatch(r"en[0-9]+", interface):
        raise ValueError("No supported directly attached interface")
    local = query(["/usr/sbin/ipconfig", "getifaddr", interface])
    mask = query(["/usr/sbin/ipconfig", "getoption", interface, "subnet_mask"])
    return validate_link(address, route, local, mask)


def main():
    mode, _bridge = sys.argv[1:]
    if mode not in ("network-check", "network-request"):
        raise ValueError("Unknown mode")
    target = target_from(
        json.loads(Path(__file__).with_name("network-target.json").read_text())
    )
    verify_on_link(target[0])  # Fail closed before any connection; routes can change.
    emit(
        "python-start",
        pid=os.getpid(),
        ppid=os.getppid(),
        executable=str(Path(sys.executable).resolve()),
        version=sys.version.split()[0],
    )
    # Keep the responsible host alive after initial failure so macOS can show
    # its alert (TN3179 FB16131937). Request mode gives the operator time.
    deadline = time.monotonic() + (180 if mode == "network-request" else 0)
    attempts = 0
    while True:
        attempts += 1
        try:
            with socket.create_connection(target, timeout=3):
                pass  # No send, recv, HTTP request, credentials, or remote mutation.
            emit(
                "local-network",
                connected=True,
                attempts=attempts,
                application_payload=False,
            )
            break
        except OSError as exc:
            if attempts == 1:
                emit(
                    "network-first-attempt",
                    connected=False,
                    errno=exc.errno,
                    error_type=type(exc).__name__,
                )
            if time.monotonic() >= deadline:
                emit(
                    "local-network",
                    connected=False,
                    errno=exc.errno,
                    error_type=type(exc).__name__,
                    attempts=attempts,
                    application_payload=False,
                )
                break
            time.sleep(1)
    emit("probe-complete")


if __name__ == "__main__":
    main()
