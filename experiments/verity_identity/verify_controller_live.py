"""Real controller integration with synthetic services; never a production cutover."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import time

SOURCE = Path(__file__).resolve().parent
CONTROL = SOURCE.parents[1] / "scripts/production_control"
sys.path.insert(0, str(CONTROL))
sys.path.insert(0, str(SOURCE))
from production_launcher import inventory  # noqa: E402
from restart_production import Controller, ControlError, save_json  # noqa: E402
from watchdog import tick  # noqa: E402
from verify_service_host_live import (
    lab,
    launchctl,
    current,
    until,
    gone,
    all_recorded_gone,
)  # noqa: E402


def operation(root, kind, result_path, candidate=None):
    root, manifest = lab(root)
    assert result_path.parent == root and os.getppid() == 1
    c = Controller(root, timeout=12, stable_seconds=1)
    try:
        if kind == "restart":
            result = c.restart(candidate=candidate, yes=True)
        else:
            raise ValueError("Unknown isolated operation")
    except Exception as exc:
        result = {
            "status": "error",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
    save_json(result_path, result)
    return result


def independent(root, kind, candidate=None):
    label = f"com.charles.verity.controllerlab.{os.getpid()}.controller"
    target = f"gui/{os.getuid()}/" + label
    assert launchctl("print", target, check=False).returncode != 0
    result = root / f"operation-{time.time_ns()}.json"
    argv = [
        sys.executable,
        "-I",
        "-B",
        str(Path(__file__).resolve()),
        "--root",
        str(root),
        "--operation",
        kind,
        "--result",
        str(result),
    ]
    if candidate:
        argv += ["--candidate", str(candidate)]
    definition = {
        "Label": label,
        "ProgramArguments": argv,
        "WorkingDirectory": str(root),
        "RunAtLoad": True,
        "KeepAlive": False,
        "EnvironmentVariables": {
            "HOME": str(root / "home"),
            "TMPDIR": str(root / "tmp"),
        },
        "StandardOutPath": str(root / "controller.out"),
        "StandardErrorPath": str(root / "controller.err"),
    }
    plist = root / "controller.plist"
    plist.write_bytes(plistlib.dumps(definition))
    try:
        launchctl("bootstrap", f"gui/{os.getuid()}", str(plist))
        until(lambda: result.exists(), 75)
        value = json.loads(result.read_text())
        # Result file can precede interpreter exit; require stopped launchd state.
        until(lambda: "state = not running" in launchctl("print", target).stdout, 8)
        return value
    finally:
        launchctl("bootout", "--wait", target, check=False)
        assert launchctl("print", target, check=False).returncode != 0


def verify(root):
    root, manifest = lab(root)
    loaded, records = [], []
    proof = {"cases": [], "status": "running", "synthetic_services": True}
    original = (root / "production-release.json").read_bytes()
    original_plists = {
        r: (root / (r + ".plist")).read_bytes() for r in ("agent", "webui")
    }
    c = Controller(root, timeout=12, stable_seconds=1)

    def pair():
        value = {
            r: until(lambda r=r: current(root, manifest, r)) for r in ("agent", "webui")
        }
        records.extend(value.values())
        return value

    def passed(name, **fields):
        proof["cases"].append({"name": name, "passed": True, **fields})
        print(json.dumps({"case": name, "passed": True}), flush=True)

    try:
        # Native preflight must be done before any job is started.
        c.preflight(manifest)
        definitions = c.definitions(manifest)
        for role in ("agent", "webui"):
            target = c.target(manifest, role)
            assert launchctl("print", target, check=False).returncode != 0
            launchctl("bootstrap", f"gui/{os.getuid()}", str(root / (role + ".plist")))
            loaded.append(target)
        live = pair()
        snap = c.snapshot(manifest, definitions)
        assert c.host.listener(manifest["health_url"]) == {live["webui"]["pid"]}
        assert live["webui"]["pid"] != live["webui"]["ppid"]
        passed("accept_owned_native_python_listener", snapshot=snap)
        before = pair()
        result = independent(root, "restart")
        assert result["status"] == "verified", result
        after = pair()
        assert all(before[r]["ppid"] != after[r]["ppid"] for r in before)
        until(lambda: all(gone(r) for r in before.values()))
        passed("independent_controller_pair_restart", result=result)
        state = tick(c, grace=0)
        assert state["status"] == "healthy", state
        passed("watchdog_healthy_native_pair", result=state)
        before = pair()
        (root / "deep-failure").touch()
        try:
            state = tick(c, grace=0)
            assert state["status"] == "degraded", state
            assert pair() == before
        finally:
            (root / "deep-failure").unlink()
        passed("watchdog_deep_failure_preserves_pair", result=state)
        before = pair()
        (root / "shallow-failure").touch()
        try:
            suspect = tick(c, grace=0)
            requested = tick(c, grace=0)
            assert suspect["status"] == "suspect", suspect
            assert requested["status"] == "restart_requested", requested
        finally:
            (root / "shallow-failure").unlink()
        after = pair()
        assert after["agent"] == before["agent"]
        assert after["webui"]["ppid"] != before["webui"]["ppid"]
        until(lambda: gone(before["webui"]))
        assert tick(c, grace=0)["status"] == "healthy"
        passed(
            "watchdog_shallow_restart_webui_only", suspect=suspect, requested=requested
        )
        before = pair()
        # A real foreign loopback listener: expected positive process+HTTP proof
        # cannot be fabricated by a matching JSON health response.
        outsider = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                'import http.server;http.server.HTTPServer(("127.0.0.1",0),http.server.BaseHTTPRequestHandler).serve_forever()',
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            from urllib.parse import urlsplit

            # No request is made to this unrelated server: ownership must fail first.
            output = until(
                lambda: (
                    subprocess.run(
                        [
                            "/usr/sbin/lsof",
                            "-a",
                            "-p",
                            str(outsider.pid),
                            "-iTCP",
                            "-sTCP:LISTEN",
                            "-Fn",
                        ],
                        capture_output=True,
                        text=True,
                    ).stdout
                )
            )
            port = next(
                line.rsplit(":", 1)[1]
                for line in output.splitlines()
                if line.startswith("n")
            )
            foreign = copy.deepcopy(manifest)
            foreign["health_url"] = f"http://127.0.0.1:{port}/health"
            assert urlsplit(foreign["health_url"]).port
            try:
                c.snapshot(foreign, definitions)
            except ControlError as exc:
                passed("reject_live_unrelated_listener", error=str(exc))
            else:
                raise AssertionError("Foreign listener accepted")
            assert pair() == before
        finally:
            outsider.terminate()
            outsider.wait(timeout=5)
        # A signer-valid *different release* that exits at launch passes byte
        # preflight, fails readiness, and must restore the exact old pair.
        candidate = copy.deepcopy(manifest)
        broken = root / "broken-webui"
        shutil.copytree(root / "webui", broken, dirs_exist_ok=True)
        (broken / "main.py").write_text("raise SystemExit(9)\n")
        item = candidate["services"]["webui"]
        item.update(
            repo=str(broken),
            cwd=str(broken),
            inventory=inventory(broken),
            argv=[sys.executable, "-I", "-B", str(broken / "main.py"), "webui"],
            commit="fixture-bad",
        )
        candidate["release_id"] = "synthetic-broken-candidate"
        candidate_path = root / "candidate.json"
        save_json(candidate_path, candidate)
        result = independent(root, "restart", candidate_path)
        assert result["status"] == "rolled_back", result
        assert (root / "production-release.json").read_bytes() == original
        assert all(
            (root / (r + ".plist")).read_bytes() == b
            for r, b in original_plists.items()
        )
        after = pair()
        c.snapshot(manifest, definitions)
        passed("bad_candidate_exact_rollback", result=result)
        before = pair()
        source = root / "webui/main.py"
        source_bytes = source.read_bytes()
        try:
            source.write_bytes(source_bytes + b"\n# unapproved tamper\n")
            result = independent(root, "restart")
            assert result["status"] == "error", result
            assert pair() == before
        finally:
            source.write_bytes(source_bytes)
        passed("source_tamper_refused_before_stop", result=result)
        before = pair()
        settings = (
            Path(manifest["native_host"]["bundle"])
            / "Contents/Resources/service-settings.json"
        )
        saved = settings.read_bytes()
        try:
            settings.write_bytes(saved + b"\n")
            result = independent(root, "restart")
            assert result["status"] == "error", result
            assert pair() == before
        finally:
            settings.write_bytes(saved)
        passed("native_bundle_tamper_refused_before_stop", result=result)
        c.preflight(manifest)
        c.snapshot(manifest, c.definitions(manifest))
    except BaseException as exc:
        proof.update(status="failed", error_type=type(exc).__name__, error=str(exc))
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
            errors.append("Known lab processes survived unload")
        proof["cleanup_verified"] = not errors
        proof["source_sha256"] = {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in [
                CONTROL / "restart_production.py",
                CONTROL / "watchdog.py",
                CONTROL / "native_identity.py",
                SOURCE / "ServiceHost.swift",
            ]
        }
        if errors:
            proof.update(status="failed", cleanup_errors=errors)
        elif proof["status"] == "running":
            proof["status"] = "passed"
        path = root / "controller-live-verification.json"
        path.write_text(json.dumps(proof, indent=2) + "\n")
        print(
            json.dumps({
                "report": str(path),
                "status": proof["status"],
                "cleanup_verified": not errors,
            })
        )
        if errors:
            raise AssertionError(errors)
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--operation", choices=["restart"])
    parser.add_argument("--result", type=Path)
    parser.add_argument("--candidate", type=Path)
    args = parser.parse_args()
    if args.operation:
        operation(args.root, args.operation, args.result, args.candidate)
    else:
        verify(args.root)
