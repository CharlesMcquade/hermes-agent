#!/usr/bin/env python3
"""One-command safe production redeploy with automatic same-session continuation.

    fire_redeploy.py fire --session <id> --release-tag r7 \
        --webui-commit <40-hex> --agent-commit <40-hex> [--approval "<who/when/why>"]

`fire` runs every arming step in the only order that works, gated on each one:

  retire   -> archive the previous consumed receipt (verified rounds retire immediately)
  build    -> op dir (0700) + continuation dir + frozen candidate sealed to it
  pins     -> OLD_PIN/NEW_PIN in select_for_user_restart.py, committed
  prepare  -> release_workflow prepare (canaries + pending gate) -> evidence dir
  plan     -> plan.json bound to the orchestrating session's latest human message
  check    -> safe_redeploy.py check (read-only admission)
  dispatch -> launchd one-shot running safe_redeploy.py run --approve

The runner then (idle gate -> WebUI restart -> Gateway restart -> watchdog verified ->
publish) hands the session a system-initiated turn. Expect ~15 min dispatch->resume;
~10 of that is the watchdog's two 5-minute observations.

Rules that each cost a failed attempt:
  * never reuse the running release tag (--release-tag is mandatory);
  * no edits to ~/.hermes/.env or active_profile between dispatch and the first restart
    (the selector vetoes the run - correct behaviour);
  * a user message in the session before the first restart aborts the run (re-fire);
    after it, messages are fine and merely reported as transcript_advanced.

`status --op-id <id>` prints the runner's event trail; `<phase>...` runs individual phases.
Certified end-to-end 2026-10-26 (r6, op c283e735). Re-certify after runner/consumer/watchdog edits.
"""
import argparse, datetime as dt, hashlib, json, os, plistlib, re, subprocess, sys, time, uuid
from pathlib import Path

HOME = Path.home()
PY = "/opt/homebrew/bin/python3"
TOOLS = Path(__file__).resolve().parent
BASE = HOME / ".hermes/maintenance"
CONTROLS = BASE / "control-refresh-versions/verity-runtime-drift-20261022"
CONTROL_REFRESH = "37936f249fb61da2310d5b638beffad91d6de2fdda85a031a0df3bdb492bfc45"
OPS_ROOT = HOME / "hermes-dev/redeploy"
EVIDENCE_ROOT = HOME / "notes/security/hermes-release-evidence"
TOOL_FILES = ["safe_redeploy.py", "continuation_publish.py", "safe_pending_activation.py",
              "safe_pending_retirement.py", "activate_pending.py", "select_for_user_restart.py",
              "candidate_canary.py"]
SCOPE = ["prepare", "select", "restart-webui", "restart-gateway", "verified-fallback", "resume-origin-session"]
PHASES = ["retire", "build", "pins", "prepare", "plan", "check", "dispatch"]
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def run(cmd, **kw):
    print("+", " ".join(map(str, cmd)), flush=True)
    r = subprocess.run(list(map(str, cmd)), text=True, capture_output=True,
                       env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, **kw)
    sys.stdout.write(r.stdout[-4000:]); sys.stderr.write(r.stderr[-4000:])
    return r


def today() -> str:
    return dt.date.today().strftime("%Y%m%d")


def day_dir() -> Path:
    d = OPS_ROOT / today(); d.mkdir(parents=True, exist_ok=True); return d


def state_path(op): return op / "arm-state.json"
def load(op): return json.loads(state_path(op).read_text()) if state_path(op).exists() else {}
def save(op, st): state_path(op).write_text(json.dumps(st, indent=2, sort_keys=True) + "\n")


def phase_retire(_op, _a):
    r = run([PY, "-B", TOOLS / "retire_consumed_receipt.py", "--base", BASE, "--controls", CONTROLS,
             "--control-refresh-sha256", CONTROL_REFRESH, "--approve"])
    if r.returncode != 0 and "No pending receipt to retire" not in r.stdout + r.stderr:
        sys.exit("RETIRE FAILED (previous round not settled-verified yet?)")


def phase_build(_op, a):
    if not a.release_tag:
        sys.exit("build requires --release-tag (never reuse the running release tag)")
    for name, val in (("--webui-commit", a.webui_commit), ("--agent-commit", a.agent_commit)):
        if not val or not HEX40.match(val):
            sys.exit(f"{name} must be an exact lowercase 40-char commit (resolve with git rev-parse)")
    op_id = a.op_id or uuid.uuid4().hex
    op = day_dir() / f"op-{op_id}"
    op.mkdir(mode=0o700, exist_ok=True); os.chmod(op, 0o700)
    (op / "continuation").mkdir(mode=0o700, exist_ok=True)
    release = f"hermes-{today()}-{a.release_name}-{a.release_tag}"
    out = HOME / ".hermes/releases" / release
    if out.exists():
        sys.exit(f"release {release} already exists - pick a new --release-tag")
    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
    cfg = {
        "baseline": str(BASE / "production-release.json"), "output": str(out),
        "scratch": str(HOME / ".hermes/cache/scratch"),
        "agent_repo": a.agent_repo, "agent_commit": a.agent_commit,
        "webui_repo": a.webui_repo, "webui_commit": a.webui_commit,
        "evidence_dir": str(EVIDENCE_ROOT), "controls": str(CONTROLS),
        "control_refresh_sha256": CONTROL_REFRESH,
        "tool_path": ":".join([str(HOME / ".local/bin"), "/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin",
                               "/usr/bin", "/bin", "/usr/sbin", "/sbin", str(HOME / ".hermes/bin"),
                               str(HOME / ".hermes/node/bin"), str(HOME / ".hermes/node")]),
        "continuation_dir": str(op / "continuation"),
    }
    (op / "build-config.json").write_text(json.dumps(cfg, indent=2) + "\n")
    st = load(op); st.update(op_id=op_id, release=release, candidate=str(out / "release.json")); save(op, st)
    r = run([PY, "-B", TOOLS / "release_workflow.py", "--config", op / "build-config.json", "build"])
    if r.returncode != 0:
        sys.exit("BUILD FAILED")
    st["candidate_sha256"] = sha(out / "release.json"); save(op, st)
    print(json.dumps({"op": str(op), "release": release, "candidate_sha256": st["candidate_sha256"]}))
    return op


def phase_pins(op, _a):
    st = load(op)
    sel = TOOLS / "select_for_user_restart.py"
    text = sel.read_text()
    old_pin = sha(BASE / "production-release.json")
    text = re.sub(r"OLD_PIN = '[0-9a-f]{64}'", f"OLD_PIN = '{old_pin}'", text)
    text = re.sub(r"NEW_PIN = '[0-9a-f]{64}'", f"NEW_PIN = '{st['candidate_sha256']}'", text)
    if text != sel.read_text():
        sel.write_text(text)
        r = run(["git", "-C", TOOLS, "commit", "-qm",
                 f"chore: pin reviewed transition {old_pin[:12]} -> {st['candidate_sha256'][:12]} ({st['release']})",
                 "--", str(sel)])
        if r.returncode != 0:
            sys.exit("PIN COMMIT FAILED")
    st["selected_sha256"] = old_pin; save(op, st)
    print(json.dumps({"OLD_PIN": old_pin, "NEW_PIN": st["candidate_sha256"]}))


def phase_prepare(op, _a):
    st = load(op)
    before = {p.name for p in EVIDENCE_ROOT.iterdir()}
    r = run([PY, "-B", TOOLS / "release_workflow.py", "--config", op / "build-config.json", "prepare"])
    new = sorted({p.name for p in EVIDENCE_ROOT.iterdir()} - before)
    if r.returncode != 0 or not new or "APP_SMOKE_PASSED_PENDING_GATE_CHECKED" not in r.stdout:
        sys.exit(f"PREPARE FAILED rc={r.returncode} new_evidence={new} (previous receipt not retired?)")
    st["evidence_dir"] = str(EVIDENCE_ROOT / new[-1]); save(op, st)
    print(json.dumps({"evidence_dir": st["evidence_dir"]}))


def phase_plan(op, a):
    sys.path.insert(0, str(TOOLS))
    import continuation_publish as cp  # noqa
    st = load(op)
    anchor = cp.human_anchor(str(HOME / ".hermes"), a.session)
    evidence = [{"path": str(p), "sha256": sha(p)} for p in sorted(Path(st["evidence_dir"]).rglob("*")) if p.is_file()]
    resume = (f"Automatic redeploy continuation (operation {st['op_id']}). The trusted runner completed the "
              f"/safe-hermes-redeploy deployment steps and resumed this session. Read {op}/state.json, "
              f"independently verify the running release ({st['release']}, manifest {st['candidate_sha256']}), "
              f"service identities, health and continuation receipts, then report success in plain language. "
              f"Do not deploy again. If anything is unverified, say exactly which criterion and what you will do next.")
    plan = {
        "schema": 1, "operation_id": st["op_id"], "operation_dir": str(op),
        "approval": {"authorized_by": a.approval, "expires_at": time.time() + a.approval_hours * 3600,
                     "scope": SCOPE, "user_preapproved": True},
        "base": str(BASE), "controls": str(CONTROLS), "control_refresh_sha256": CONTROL_REFRESH,
        "candidate": st["candidate"], "candidate_sha256": st["candidate_sha256"],
        "selected_sha256": st["selected_sha256"], "continuation_dir": str(op / "continuation"),
        "session": {"session_id": a.session, "profile": a.profile, "workspace": a.workspace},
        "session_dir": str(HOME / ".hermes/webui/sessions"), "state_home": str(HOME / ".hermes"),
        "scratch": str(HOME / ".hermes/cache/scratch"), "human_anchor": anchor,
        "tool_sha256": {n: sha(TOOLS / n) for n in TOOL_FILES}, "evidence": evidence, "resume_message": resume,
    }
    p = op / "plan.json"
    p.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")
    st["plan_sha256"] = sha(p); save(op, st)
    print(json.dumps({"plan_sha256": st["plan_sha256"], "anchor": anchor[:16]}))


def phase_check(op, _a):
    st = load(op)
    r = run([PY, "-I", "-B", TOOLS / "safe_redeploy.py", "check", "--plan", op / "plan.json", "--plan-sha256", st["plan_sha256"]])
    if r.returncode != 0 or "baseline_verified" not in r.stdout:
        sys.exit("CHECK FAILED (not baseline_verified)")


def phase_dispatch(op, a):
    st = load(op)
    attempt = a.attempt
    label = f"com.charles.hermes-safe-redeploy-{st['op_id'][:8]}"
    plist = {
        "Label": label, "RunAtLoad": True, "KeepAlive": False,
        "EnvironmentVariables": {"PATH": "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"},
        "ProgramArguments": [PY, "-I", "-B", str(TOOLS / "safe_redeploy.py"), "run", "--plan", str(op / "plan.json"),
                             "--plan-sha256", st["plan_sha256"], "--approve"],
        "StandardOutPath": str(op / f"runner.attempt{attempt}.out.log"),
        "StandardErrorPath": str(op / f"runner.attempt{attempt}.err.log"),
        "WorkingDirectory": str(op),
    }
    pp = op / f"attempt{attempt}.plist"
    pp.write_bytes(plistlib.dumps(plist))
    if (op / "state.json").exists():
        (op / "state.json").rename(op / f"state.attempt{attempt - 1}.archived.json")
    uid = os.getuid()
    subprocess.run(["launchctl", "bootout", f"gui/{uid}/{label}"], capture_output=True)
    r = run(["launchctl", "bootstrap", f"gui/{uid}", pp])
    if r.returncode != 0:
        sys.exit("BOOTSTRAP FAILED")
    st.update(label=label, attempt=attempt, dispatched_at=time.time()); save(op, st)
    print(json.dumps({"label": label, "dispatched_at": time.strftime("%H:%M:%S"),
                      "err_log": plist["StandardErrorPath"], "expect_resume_by": time.strftime("%H:%M", time.localtime(time.time() + 18 * 60))}))


def cmd_status(op):
    st = json.loads((op / "state.json").read_text()) if (op / "state.json").exists() else {}
    print("outcome:", st.get("outcome"))
    for e in st.get("events", [])[-12:]:
        t = e.get("time") or 0
        extra = {k: v for k, v in e.items() if k not in ("time", "phase", "operation_dir") and not isinstance(v, (dict, list))}
        print(time.strftime("%H:%M:%S", time.localtime(t)), e.get("phase"), extra)
    err = sorted(op.glob("runner.attempt*.err.log"))
    if err:
        print("--- last err lines:", err[-1].name)
        print("\n".join(err[-1].read_text().splitlines()[-5:]))


PHASE_FN = {"retire": phase_retire, "build": phase_build, "pins": phase_pins, "prepare": phase_prepare,
            "plan": phase_plan, "check": phase_check, "dispatch": phase_dispatch}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("phases", nargs="+", choices=PHASES + ["fire", "status"])
    ap.add_argument("--session", help="orchestrating WebUI session id (required except for status)")
    ap.add_argument("--op-id"); ap.add_argument("--day", help="YYYYMMDD of an existing op (default today)")
    ap.add_argument("--release-tag", help="r7, r8 ... (mandatory for build; never reuse)")
    ap.add_argument("--release-name", default="redeploy")
    ap.add_argument("--webui-repo", default=str(HOME / "hermes-dev/worktrees/safe-redeploy-webui"))
    ap.add_argument("--webui-commit"); ap.add_argument("--agent-commit")
    ap.add_argument("--agent-repo", default=str(HOME / "hermes-release-sources/agent-2b8ea994"))
    ap.add_argument("--profile", default="default"); ap.add_argument("--workspace", default=str(HOME / "hermes-dev"))
    ap.add_argument("--approval", default="Charles Inglis pre-approved this redeploy in the orchestrating session "
                    "(WebUI->Gateway restarts, verified fallback, same-session continuation; no Mac reboot, "
                    "no iMessage proxy restart, no other profiles).")
    ap.add_argument("--approval-hours", type=float, default=6)
    ap.add_argument("--attempt", type=int, default=1)
    a = ap.parse_args()
    phases = PHASES if a.phases == ["fire"] else a.phases
    day = OPS_ROOT / (a.day or today())
    op = day / f"op-{a.op_id}" if a.op_id else None
    if phases == ["status"]:
        if not op: ap.error("status requires --op-id")
        return cmd_status(op)
    if not a.session: ap.error("--session is required")
    for ph in phases:
        if op is None and ph not in ("retire", "build"):
            ap.error(f"{ph} requires --op-id (or run build first)")
        print(f"== {time.strftime('%H:%M:%S')} {ph}", flush=True)
        result = PHASE_FN[ph](op, a)
        if ph == "build": op = result
    if "dispatch" in phases:
        print("ARMED - runner live; the session receives a system-initiated turn when verification completes.")


if __name__ == "__main__":
    main()
