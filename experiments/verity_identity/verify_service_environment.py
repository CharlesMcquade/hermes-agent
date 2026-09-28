"""Opt-in synthetic bootstrap-environment gate; builds/signs/launches only fresh lab content.

Requires explicit operator approval. Example (NOT an offline test):
  env -u PYTHONPATH -u PYTHONSAFEPATH TMPDIR="$SCRATCH" "$PYTHON" -B \
    experiments/verity_identity/verify_service_environment.py \
    --root "$FRESH_ROOT" --identity "$APPROVED_SIGNER_JSON" --approve-live-lab

Never imports or executes production_launcher.py or real app/service content.
Signer metadata uses the existing public sha1/keychain schema. No key creation,
keychain unlock, global launchd environment changes, or installed jobs.
"""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import uuid

from verify_service_host_live import alive, launchctl, set_cleanup_outcome, until
from stage_production_native import compile_host

SOURCE = Path(__file__).resolve().parent
BUNDLE_ID = "com.charles.verity.environmentlab"
SENTINEL = "VERITY_ENVIRONMENT_SECRET_SENTINEL"
RUNTIME_KEYS = ("LC_CTYPE", "__CF_USER_TEXT_ENCODING")
# Fixed fixture only. It reports the environment then waits in its host's group.
FIXTURE = """import json,os,pathlib,sys,time
base=pathlib.Path(__file__).resolve().parent
role=sys.argv[1]
assert role in ("agent","webui")
assert sys.argv[2:]==["--manifest",str(base/"production-release.json")]
keys=("HOME","TMPDIR","HERMES_HOME","PATH","PYTHONNOUSERSITE","PYTHONDONTWRITEBYTECODE")
record=dict(role=role,pid=os.getpid(),ppid=os.getppid(),pgid=os.getpgrp(),
            env={k:os.environ[k] for k in keys if k in os.environ},env_keys=sorted(os.environ),
            runtime_added={k:os.environ[k] for k in ("LC_CTYPE","__CF_USER_TEXT_ENCODING") if k in os.environ})
(base/(role+".receipt.json")).write_text(json.dumps(record))
while True: time.sleep(1)
"""


def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=90)


def defaults(base):
    return dict(
        HOME=str(base / "home"),
        TMPDIR=str(base / "tmp"),
        HERMES_HOME=str(base / "state"),
        PATH="/usr/bin:/bin:/usr/sbin:/sbin",
        PYTHONNOUSERSITE="1",
        PYTHONDONTWRITEBYTECODE="1",
    )


def variants(base):
    legacy = dict(
        base=str(base),
        bootstrap_python=sys.executable,
        launcher=str(base / "production_launcher.py"),
        launcher_sha256=hashlib.sha256(FIXTURE.encode()).hexdigest(),
        roles=["agent", "webui"],
    )
    explicit = dict(
        defaults(base),
        HOME=str(base / "explicit-home"),
        TMPDIR=str(base / "explicit-tmp"),
        HERMES_HOME=str(base / "explicit-state"),
    )
    yield "legacy", legacy, defaults(base)
    yield "explicit", dict(legacy, bootstrap_environment=explicit), explicit
    bad_values = [
        None,
        [],
        {},
        dict(explicit, EXTRA="no"),
        {k: v for k, v in explicit.items() if k != "HOME"},
    ]
    for key in explicit:
        for value in (1, True, "bad\u0000value"):
            bad_values.append(dict(explicit, **{key: value}))
    for key in ("HOME", "TMPDIR", "HERMES_HOME"):
        for value in ("", "relative"):
            bad_values.append(dict(explicit, **{key: value}))
    for key in ("PATH", "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE"):
        bad_values.append(dict(explicit, **{key: "wrong"}))
    for index, value in enumerate(bad_values):
        yield f"invalid-{index}", dict(legacy, bootstrap_environment=value), None
    yield "unknown-setting", dict(legacy, UNKNOWN="no"), None


def records(job):
    path = job["out"]
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.startswith("{")
    ]


def runtime_environment(expected):
    """Measure known runtime additions from a direct child with the same six inputs.

    Output is restricted even on a failed check: never dump unexpected values.
    This is a synthetic Python baseline, not a permission-attribution control.
    """
    probe = (
        "import os,json; keys=" + repr(tuple(expected) + RUNTIME_KEYS) + ";"
        "print(json.dumps(dict(keys=sorted(os.environ),"
        "values={k:os.environ[k] for k in keys if k in os.environ})))"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", probe], env=expected,
        capture_output=True, text=True, check=True, timeout=15,
    )
    observed = json.loads(result.stdout)
    assert set(observed["keys"]) <= set(expected) | set(RUNTIME_KEYS)
    assert all(observed["values"][key] == value for key, value in expected.items())
    return dict(
        keys=observed["keys"],
        added={key: observed["values"][key] for key in RUNTIME_KEYS if key in observed["values"]},
    )


def ready(job, expected, runtime=None):
    output = launchctl("print", job["target"]).stdout
    match = re.search(r"^\s*pid = (\d+)$", output, re.M)
    if expected is None:
        if not re.search(r"^\s*last exit code = 78(?:: EX_CONFIG)?$", output, re.M):
            return False
        assert not match and not job["receipt"].exists()
        assert not any(r.get("event") == "service-host" for r in records(job))
        assert any(r.get("event") == "host-refused" for r in records(job))
        return True
    if not match or not job["receipt"].exists():
        return False
    pid = int(match[1])
    hosts = [
        r for r in records(job) if r.get("event") == "service-host" and r["pid"] == pid
    ]
    if not hosts:
        return False
    host = hosts[-1]
    receipt = json.loads(job["receipt"].read_text())
    assert receipt["env"] == expected
    runtime = runtime or dict(keys=sorted(expected), added={})
    assert receipt["env_keys"] == runtime["keys"]
    assert receipt.get("runtime_added", {}) == runtime["added"]
    assert SENTINEL not in receipt["env_keys"]
    assert receipt["role"] == job["role"] == host["role"]
    assert host["ppid"] == 1 and host["pgid"] == host["pid"]
    assert receipt["ppid"] == receipt["pgid"] == pid
    assert receipt["pid"] == host["child_pid"]
    assert all(
        alive(host[k]) and os.getpgid(host[k]) == pid
        for k in ("pid", "child_pid", "guard_pid")
    )
    return {"host": host, "receipt": receipt}


def all_gone(jobs):
    ids, groups = set(), set()
    for job in jobs:
        for record in records(job):
            if record.get("event") == "service-host":
                ids.update(record[k] for k in ("pid", "child_pid", "guard_pid"))
                groups.add(record["pgid"])
        if job["receipt"].exists():
            record = json.loads(job["receipt"].read_text())
            ids.update((record["pid"], record["ppid"]))
            groups.add(record["pgid"])
    if not ids or not groups:
        return False
    if any(alive(pid) for pid in ids):
        return False
    output = subprocess.run(
        ["/bin/ps", "-axo", "pid=,pgid=,comm="],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout
    binaries = {str(job["binary"]) for job in jobs}
    for line in output.splitlines():
        _, pgid, command = line.strip().split(None, 2)
        if int(pgid) in groups or command in binaries:
            return False
    return True


def verify(root, identity_path):
    if sys.flags.optimize:
        raise RuntimeError("Do not disable safety assertions with -O")
    if sys.platform != "darwin":
        raise RuntimeError("This gate requires macOS")
    # Resolve the parent first; never reuse a prior signed artifact or report.
    root = root.absolute()
    root = root.parent.resolve(strict=True) / root.name
    root.mkdir(mode=0o700, exist_ok=False)
    identity = json.loads(identity_path.read_text())
    pin = identity["sha1"]
    if not isinstance(pin, str) or not re.fullmatch(r"[a-fA-F0-9]{40}", pin):
        raise ValueError("Invalid approved signer fingerprint")
    keychain = identity["keychain"]
    if (
        not isinstance(keychain, str)
        or not Path(keychain).is_absolute()
        or "\u0000" in keychain
    ):
        raise ValueError("Invalid approved keychain path")
    binary = root / "compiled-ServiceHost"
    compile_host(root, SOURCE / "ServiceHost.swift", binary)
    requirement = f'identifier "{BUNDLE_ID}" and certificate leaf = H"{pin.lower()}"'
    req = root / "requirements.txt"
    req.write_text("designated => " + requirement + "\n")
    jobs, attempted = [], []
    report = dict(status="running", synthetic_services=True, cases=[])
    unique = uuid.uuid4().hex
    try:
        # Each case receives its own immutable signed bundle and fixed launcher.
        for name, _, _ in variants(root):
            base = root / name
            base.mkdir(mode=0o700)
            settings, expected = next((s, e) for n, s, e in variants(base) if n == name)
            runtime = runtime_environment(expected) if expected is not None else None
            for folder in (
                "home",
                "tmp",
                "state",
                "explicit-home",
                "explicit-tmp",
                "explicit-state",
            ):
                (base / folder).mkdir(mode=0o700)
            launcher = base / "production_launcher.py"
            launcher.write_text(FIXTURE)
            app = base / "Environment Lab.app"
            exe = app / "Contents/MacOS/VerityServiceHost"
            exe.parent.mkdir(parents=True)
            shutil.copy2(binary, exe)
            resources = app / "Contents/Resources"
            resources.mkdir()
            (resources / "service-settings.json").write_text(json.dumps(settings))
            (app / "Contents/Info.plist").write_bytes(
                plistlib.dumps(
                    dict(
                        CFBundleIdentifier=BUNDLE_ID,
                        CFBundleExecutable=exe.name,
                        CFBundleName="Environment Lab",
                        CFBundleVersion="1",
                        CFBundlePackageType="APPL",
                        LSUIElement=True,
                    )
                )
            )
            run([
                "/usr/bin/codesign",
                "--force",
                "--sign",
                pin,
                "--keychain",
                keychain,
                "--timestamp=none",
                "--requirements",
                str(req),
                str(app),
            ])
            run([
                "/usr/bin/codesign",
                "--verify",
                "--strict",
                "-R",
                "=" + requirement,
                str(app),
            ])
            assert launcher.read_text() == FIXTURE
            for role in ("agent", "webui"):
                label = f"{BUNDLE_ID}.{unique}.{name}.{role}"
                target = f"gui/{os.getuid()}/{label}"
                job = dict(
                    target=target,
                    role=role,
                    binary=exe,
                    out=base / (role + ".out"),
                    receipt=base / (role + ".receipt.json"),
                )
                path = base / (role + ".plist")
                definition = dict(
                    Label=label,
                    ProgramArguments=[str(exe), role],
                    WorkingDirectory=str(base),
                    RunAtLoad=True,
                    KeepAlive=False,
                    AbandonProcessGroup=False,
                    AssociatedBundleIdentifiers=[BUNDLE_ID],
                    EnvironmentVariables={SENTINEL: "synthetic-not-a-secret"},
                    StandardOutPath=str(job["out"]),
                    StandardErrorPath=str(base / (role + ".err")),
                )
                path.write_bytes(plistlib.dumps(definition))
                assert plistlib.loads(path.read_bytes()) == definition
                assert launchctl("print", target, check=False).returncode != 0
                jobs.append(job)
                attempted.append(target)
                launchctl("bootstrap", f"gui/{os.getuid()}", str(path))
                evidence = until(lambda: ready(job, expected, runtime))
                report["cases"].append(
                    dict(
                        name=name,
                        role=role,
                        passed=True,
                        evidence=copy.deepcopy(evidence),
                        direct_runtime_baseline=copy.deepcopy(runtime),
                    )
                )
    except BaseException as exc:
        report.update(status="failed", error_type=type(exc).__name__, error=str(exc))
        raise
    finally:
        errors = []
        for target in reversed(attempted):
            # check=False only covers nonzero exits, not spawn/timeout errors.
            # Isolate each command so one failure cannot strand later targets.
            try:
                launchctl("bootout", "--wait", target, check=False)
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append("Bootout failed: " + target + ": " + type(exc).__name__)
            try:
                if launchctl("print", target, check=False).returncode == 0:
                    errors.append("Still loaded: " + target)
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append("Job absence unverified: " + target + ": " + type(exc).__name__)
        try:
            if attempted:
                until(lambda: all_gone(jobs))
        except (AssertionError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
            errors.append(
                "Fixture cleanup could not be verified: " + type(exc).__name__
            )
        set_cleanup_outcome(report, errors, attempted)
        if errors:
            report.update(status="failed", cleanup_errors=errors)
        elif report["status"] == "running":
            report["status"] = "passed"
        (root / "environment-verification.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
        print(
            json.dumps({
                k: report[k] for k in ("status", "cleanup_status", "cleanup_verified")
            })
        )
        if errors:
            raise AssertionError(errors)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--approve-live-lab", action="store_true", required=True)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    verify(args.root, args.identity)
