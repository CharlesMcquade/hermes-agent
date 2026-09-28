"""Real frozen WebUI lifecycle under Verity; isolated HOME and no gateway."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import urllib.request

from combined_lab import Lab, ControlError
from verify_service_host_live import until, alive

ASSETS = ("boot.js", "ui.js", "panels.js", "embed-host.js", "i18n.js")


def verify(root):
    lab = Lab(root)
    report = {
        "status": "running",
        "cases": [],
        "real_webui": True,
        "messaging_delivery_tested": False,
    }
    try:
        with lab.installed():
            target, out, manifest = lab.start("webui", keepalive=True)
            base = manifest["health_url"].removesuffix("/health")

            def fetch(path, data=None):
                request = urllib.request.Request(
                    base + path,
                    data=None if data is None else json.dumps(data).encode(),
                    headers={"Origin": base, "Content-Type": "application/json"},
                )
                with urllib.request.urlopen(request, timeout=8) as response:
                    return response.read()

            def ready(previous=None):
                try:
                    identity = lab.web_identity(target, manifest)
                except ControlError:
                    return None  # Not listening yet or process changed mid-observation.
                if (
                    not identity
                    or previous is not None
                    and identity["host"]["pid"] == previous["host"]["pid"]
                ):
                    return None
                health = json.loads(fetch("/health?deep=1"))
                assert health["status"] == "ok"
                return identity

            current = until(ready, 90)
            for name in ASSETS:
                assert (
                    hashlib.sha256(fetch("/static/" + name)).digest()
                    == hashlib.sha256(
                        (
                            Path(manifest["services"]["webui"]["repo"])
                            / "static"
                            / name
                        ).read_bytes()
                    ).digest()
                )
            report["cases"].append({
                "name": "real_webui_cold_start",
                "passed": True,
                "identity": current,
                "served_assets": list(ASSETS),
            })
            print(
                json.dumps({"case": "real_webui_cold_start", "passed": True}),
                flush=True,
            )
            for field, sig, name in [
                ("host", signal.SIGTERM, "real_webui_host_sigterm"),
                ("child", signal.SIGKILL, "real_webui_python_sigkill"),
                ("host", signal.SIGKILL, "real_webui_host_sigkill"),
                ("child", None, "real_webui_api_restart"),
            ]:
                old = current
                assert lab.web_identity(target, manifest) == old
                lab.collect()
                old_pids = set(lab.pids)
                if sig is None:
                    response = json.loads(fetch("/api/webui/restart", {}))
                    assert response["status"] == "restarting"
                else:
                    os.kill(old[field]["pid"], sig)
                current = until(lambda: ready(old), 90)
                until(lambda: all(not alive(p) for p in old_pids))
                case = {
                    "name": name,
                    "passed": True,
                    "old": old,
                    "new": current,
                    "old_recorded_pids_gone": True,
                }
                report["cases"].append(case)
                print(json.dumps({"case": name, "passed": True}), flush=True)
            lab.stop(target)
        report["status"] = "passed"
    except BaseException as exc:
        report.update(status="failed", error_type=type(exc).__name__, error=str(exc))
        raise
    finally:
        report.update(lab.audit())
        (root / "real-webui-verification.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
        print(json.dumps({k: v for k, v in report.items() if k != "cases"}))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    verify(parser.parse_args().root.resolve())
