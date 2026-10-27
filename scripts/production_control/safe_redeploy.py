#!/usr/bin/env python3
"""Scoped, checkpointed WebUI redeploy. Run only through an independent launchd job.

No credentials, generic shell payloads or transcript writes. Existing installed
controllers own preparation, selection and process identity. A private admission
receipt grants one operation; fail-closed ambiguity never means retry a chat turn.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import activate_pending as admission
import continuation_publish as continuation
import select_for_user_restart as routing

SCOPE = ["prepare", "select", "restart-webui", "restart-gateway", "verified-fallback", "resume-origin-session"]
HARD_RUN_SECONDS = 2400


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def stable(action, *, attempts=10):
    """Bounded retry for live state rewritten outside our lock.

    Transient conditions absorbed: the gateway rewrites gateway_state.json, the
    running WebUI's embedded watchdog rewrites watchdog-state.json and holds
    control.lock during ticks (ControlError/BlockingIOError on non-blocking
    acquisition), and both stability checks (tooling + installed controller) can
    lose a rewrite race. Content checks still gate everything — only these
    transient races are absorbed. Everything else propagates.
    """
    transient_msgs = {'Input changed during read', 'Retained file changed while reading'}
    last = None
    for attempt in range(attempts):
        try:
            return action()
        except Exception as exc:  # installed ControlError is not a RuntimeError
            transient = (str(exc) in transient_msgs
                         or 'owns control.lock' in str(exc)
                         or isinstance(exc, BlockingIOError))
            if not transient:
                raise
            last = exc
        time.sleep(0.25 * (attempt + 1))
    raise RuntimeError('Observational state did not stabilize: ' + str(last))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def raw(path):
    return admission.retained(Path(path))


def atomic(path, value):
    path = Path(path)
    data = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    tmp = path.with_name(path.name + ".writing-" + uuid.uuid4().hex)
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        require(raw(path) == data, "Checkpoint readback failed")
    finally:
        if tmp.exists():
            tmp.unlink()


class Checkpoint:
    def __init__(self, directory, plan_pin):
        self.directory = Path(directory)
        self.path = self.directory / "state.json"
        self.pin = plan_pin
        self.value = json.loads(raw(self.path)) if self.path.exists() else {"plan_sha256": plan_pin, "events": []}
        require(self.value["plan_sha256"] == plan_pin, "Operation directory reused for another plan")

    def __call__(self, phase, **fields):
        event = {"phase": phase, "time": time.time(), **fields}
        self.value.update(phase=phase, updated_at=event["time"])
        self.value["events"].append(event)
        # Summary handles persist across subsequent phase changes.
        for key in ("pending_pin", "controller_operation_id", "binding", "request", "terminal", "outcome"):
            if key in fields:
                self.value[key] = fields[key]
        atomic(self.path, self.value)
        print(json.dumps({"phase": phase, "operation_dir": str(self.directory)}), flush=True)


@contextmanager
def operation_lock(directory):
    path = Path(directory) / "runner.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(info.st_uid == os.getuid() and info.st_nlink == 1 and info.st_mode & 0o777 == 0o600,
                "Unsafe runner lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def read_plan(path, pin):
    data = stable(lambda: raw(path))
    require(re.fullmatch("[0-9a-f]{64}", pin) and sha(data) == pin, "Plan pin mismatch")
    plan = json.loads(data)
    require("gateway_active_agents_advisory" not in plan, "Unproven gateway idle override refused")
    require(plan.get("schema") == 1 and plan.get("approval", {}).get("scope") == SCOPE,
            "Missing scoped approval")
    expires = plan["approval"].get("expires_at")
    require(type(expires) in (float, int) and math.isfinite(expires) and time.time() < expires,
            "Deployment approval expired")
    require(plan["approval"].get("user_preapproved") is True, "Explicit preapproval required")
    require(re.fullmatch("[0-9a-f]{32}", plan["operation_id"]), "Invalid operation ID")
    require(plan["session"]["profile"] == "default", "Only default profile is admitted")
    for key in ("operation_dir", "base", "controls", "candidate", "continuation_dir", "session_dir", "state_home", "scratch"):
        p = Path(plan[key])
        require(p.is_absolute() and p == p.resolve(), "Noncanonical plan path: " + key)
    require(Path(path).parent == Path(plan["operation_dir"]), "Plan must live in its operation directory")
    require(Path(plan["continuation_dir"]).parent == Path(plan["operation_dir"]), "Continuation must be operation-owned")
    require(Path(plan["operation_dir"]).stat().st_mode & 0o777 == 0o700, "Operation directory must be private")
    source = Path(__file__).resolve().parent
    required = {"safe_redeploy.py", "continuation_publish.py", "safe_pending_activation.py", "safe_pending_retirement.py",
                "activate_pending.py", "select_for_user_restart.py", "candidate_canary.py"}
    require(set(plan["tool_sha256"]) == required, "Incomplete reviewed tool inventory")
    for name, checksum in plan["tool_sha256"].items():
        require(sha(raw(source / name)) == checksum, "Tool bytes changed since approval: " + name)
    require(plan.get("evidence"), "Regression and isolated-startup evidence required")
    for item in plan["evidence"]:
        require(sha(raw(item["path"])) == item["sha256"], "Evidence changed since approval")
    require(sha(raw(plan["candidate"])) == plan["candidate_sha256"], "Candidate pin mismatch")
    candidate = json.loads(raw(plan["candidate"]))
    env = candidate["services"]["webui"]["env"]
    require(env.get("HERMES_WEBUI_CONTINUATION_DIR") == plan["continuation_dir"] and
            env.get("HERMES_WEBUI_CHAT_BACKEND") == "legacy" and
            env.get("HERMES_WEBUI_RUNTIME_ADAPTER") == "legacy-direct", "Candidate continuation settings mismatch")
    require(candidate["state_dir"] == plan["state_home"], "Candidate state ownership mismatch")
    return plan, candidate


@contextmanager
def patient_locked(c, *, timeout=180):
    """Acquire the controller lock, outlasting watchdog ticks.

    The running WebUI's embedded watchdog holds control.lock for each tick and
    the installed controller raises ControlError/BlockingIOError on a
    non-blocking collision. Wait-and-retry is correct here: tick duration is
    seconds, and every caller re-validates state after acquisition.
    """
    deadline = time.monotonic() + timeout
    while True:
        cm = c.locked()
        try:
            cm.__enter__()
        except Exception as exc:
            transient = isinstance(exc, BlockingIOError) or 'owns control.lock' in str(exc)
            if not transient or time.monotonic() > deadline:
                raise
            time.sleep(0.5)
            continue
        try:
            yield
        finally:
            cm.__exit__(None, None, None)
        return


def initial_inspection(c, pending, plan, candidate):
    """Read-only admission. An exact expired mixed pair is a recovery gate, not readiness."""
    base = Path(plan["base"])
    selected = c.retained_file(c.manifest_path)[0]
    require(sha(selected) == plan["selected_sha256"], "Initial selected manifest changed")
    old = c.validate_manifest(json.loads(selected))
    profile_guard = routing.profile_routing_guard(candidate)

    def observe_admission():
        with patient_locked(c):
            refresh = c.refresh_admission()
            for manifest in (old, candidate):
                c.check_revocation(manifest); c.preflight(manifest)
            recovery_pin = plan.get("recovery_pending_sha256")
            if recovery_pin:
                r, previous, newer, unchanged = pending.load(c, recovery_pin)
                require(c.clock() > r["deadline"], "Recovery pending operation has not expired")
                require(selected == pending.decode(r["old"]), "Recovery selector is not its retained fallback")
                effective, running, identities = pending.effective_pair(c, previous, newer)
                c.snapshot(effective, c.definitions(effective))
                unchanged()
                state = {"status": "requires_verified_baseline_recovery", "running": running, "process_identity": identities}
            else:
                require(not os.path.lexists(base / pending.RECEIPT), "Unapproved pending operation exists")
                txn = c.read_transaction()
                require(txn and txn["phase"] in ("verified", "rolled_back") and "pending_restart_sha256" not in txn,
                        "Nonterminal or fenced baseline")
                state = {"status": "baseline_verified", "proof": c.snapshot(old, c.definitions(old))}
            refresh(); profile_guard()
            return state
    state = stable(observe_admission)
    state["routing"] = routing.prove_routes(candidate, Path(plan["scratch"]))
    return old, profile_guard, state


IDENTITY_FIELDS = ("session_id", "profile", "workspace", "model", "model_provider")


def verify_authorization(plan):
    require(time.time() < plan["approval"]["expires_at"], "Deployment approval expired")
    require(continuation.human_anchor(plan["state_home"], plan["session"]["session_id"]) == plan["human_anchor"],
            "User intervened after deployment was armed")


def verify_binding(consumer, plan, binding, *, exact=False, authorize=True):
    """Refresh before publication; after publication the immutable revision wins.

    authorize=False is the post-service-action scope: once a service has been
    signalled, a new human message in the orchestrating session is the moment
    to report, not grounds to abort (and never grounds to roll back a verified
    deployment). Identity and approval expiry still hold; the consumer's claim
    enforces the exact published revision on its side.
    """
    if authorize:
        verify_authorization(plan)
    else:
        require(time.time() < plan["approval"]["expires_at"], "Deployment approval expired")
    current = consumer.inspect_binding(binding["session_id"], binding["profile"], binding["workspace"],
                                       session_dir=Path(plan["session_dir"]), profile_home=Path(plan["state_home"]))
    require(all(current[k] == binding[k] for k in IDENTITY_FIELDS),
            "Session identity changed since deployment was armed")
    if exact:
        require(current == binding, "Published session revision changed")
    return current


def settlement_health(c, pending, pin, baseline):
    if not pin:
        return c.health(baseline)

    def observe():
        with patient_locked(c):
            refresh = c.refresh_admission()
            _, old, new, unchanged = pending.load(c, pin)
            effective, _, identities = pending.effective_pair(c, old, new)
            health = c.health(effective)
            refresh(); unchanged()
            require(pending.effective_pair(c, old, new)[2] == identities, "Settlement owners changed")
            return health
    return stable(observe)


def services_idle(c, pending, pin, *, report=None):
    def observe():
        refresh = c.refresh_admission()
        _, old, new, unchanged = pending.load(c, pin, allow_unfenced=True)
        effective, _, identities = pending.effective_pair(c, old, new)
        health = c.health(effective)
        state = json.loads(c.retained_file(Path(effective["state_dir"]) / "gateway_state.json")[0])
        require(state.get("pid") == identities["agent"]["child"]["pid"] and
                state.get("gateway_state") == "running", "Gateway idle owner mismatch")
        # This is the runtime's aggregate in-flight count, not its agent cache.
        # active_work is diagnostic detail emitted only while draining.
        observation = {
            "webui_status": health.get("status"),
            "webui_active_runs": health.get("active_runs"),
            "webui_active_streams": health.get("active_streams"),
            "gateway_active_agents": state.get("active_agents"),
        }
        if report is not None:
            report(observation)
        idle = (health.get("status") == "ok" and not state.get("active_work") and
                all(type(observation[k]) is int and observation[k] == 0 for k in
                    ("webui_active_runs", "webui_active_streams", "gateway_active_agents")))
        refresh(); unchanged()
        require(pending.effective_pair(c, old, new)[2] == identities, "Idle owners changed")
        return idle
    return stable(observe)


def idle_checkpoint(c, pending, pin, checkpoint, *, guard=None):
    def guarded(phase, **fields):
        checkpoint(phase, **fields)
        if phase in ("before_kick", "before_restore_selection"):
            if guard is not None:
                guard()
            require(services_idle(c, pending, pin), "Work appeared before service action")
    return guarded


def wait_idle(c, pending, pin, timeout=300, stable_seconds=10, *, guard=None, binding_probe=None):
    """Observe 10s of continuous idle AND a settled binding digest; report blockers."""
    deadline = c.monotonic() + timeout
    idle_since, last_report_at, last_report = None, None, None
    observed, last_revision, stable = {}, None, False
    while c.monotonic() < deadline:
        if guard is not None:
            guard()
        with patient_locked(c):
            idle = services_idle(c, pending, pin, report=observed.update)
            revision = binding_probe() if binding_probe is not None else "unprobed"
        now = c.monotonic()
        stable = idle and revision is not None and revision == last_revision
        if observed != last_report or last_report_at is None or now - last_report_at >= 10:
            print(json.dumps({"step": "idle_observation", "binding_stable": stable, **observed}), flush=True)
            last_report, last_report_at = dict(observed), now
        if stable:
            if idle_since is None:
                idle_since = now
            elif now - idle_since >= stable_seconds:
                if guard is not None:
                    guard()
                return
        else:
            idle_since = None
        last_revision = revision
        c.sleep(1)
    observed["binding_stable"] = stable
    raise RuntimeError("Services still have active work; no restart authorized: " + json.dumps(observed, sort_keys=True))


def execute(plan, candidate, checkpoint):
    require("gateway_active_agents_advisory" not in plan, "Unproven gateway idle override refused")
    from safe_pending_activation import run_activation, rollback_pending
    from safe_pending_retirement import retire
    base, controls = Path(plan["base"]), Path(plan["controls"])
    bytes_ = admission.prehash_bundle(base, controls, plan["control_refresh_sha256"])
    with admission.installed_modules(controls, bytes_) as (controller, pending):
        c = controller.Controller(base, control_refresh_sha256=plan["control_refresh_sha256"])
        consumer = continuation.load_consumer(candidate)
        deployment = continuation.deployment_binding(candidate)
        authorization_guard = lambda: verify_authorization(plan)
        if checkpoint.value.get("outcome") in ("worker_entered", "rolled_back", "failed_before_selection", "ambiguous",
                                                "verified_unreported"):
            return checkpoint.value
        # A terminal write may have reached disk before its checkpoint. It is
        # irrevocable authority: do not select, signal, or revalidate session state.
        if os.path.lexists(Path(plan["continuation_dir"]) / "terminal.json"):
            checkpoint("continuation_ambiguous", outcome="ambiguous")
            return checkpoint.value
        pending_pin = checkpoint.value.get("pending_pin")
        phases = {event["phase"] for event in checkpoint.value.get("events", [])}
        recovery_done = "baseline_recovered" in phases
        archive = Path(plan["operation_dir"]) / "previous-receipt"
        if not pending_pin and "preparing" in phases and os.path.lexists(base / pending.RECEIPT):
            pending_pin = sha(c.retained_file(base / pending.RECEIPT)[0])
            with patient_locked(c):
                r, _, _, unchanged = pending.load(c, pending_pin, allow_unfenced=True)
                require(r["old"]["sha256"] == plan["selected_sha256"] and
                        r["new"]["sha256"] == plan["candidate_sha256"], "Foreign preparation after interruption")
                unchanged()
            checkpoint("prepared", pending_pin=pending_pin, controller_operation_id=r["operation_id"])
        if not pending_pin:
            if plan.get("recovery_pending_sha256") and not recovery_done and os.path.lexists(archive / "retirement.json"):
                retire(c, pending, plan["recovery_pending_sha256"], archive, checkpoint=checkpoint)
                checkpoint("baseline_recovered")
                recovery_done = True
            inspection_plan = dict(plan, recovery_pending_sha256=None) if recovery_done else plan
            old, profile_guard, report = initial_inspection(c, pending, inspection_plan, candidate)
            checkpoint("admitted", inspection=report)
            binding = checkpoint.value.get("binding")
            if binding is None:
                binding = continuation.capture_settled(consumer, **plan["session"],
                    session_dir=plan["session_dir"], state_home=plan["state_home"],
                    expected_anchor=plan["human_anchor"],
                    health=lambda: settlement_health(c, pending,
                        None if recovery_done else plan.get("recovery_pending_sha256"), old))
                checkpoint("session_settled", binding=binding)
            binding = verify_binding(consumer, plan, binding)
            recovery_pin = plan.get("recovery_pending_sha256")
            if recovery_pin and not recovery_done:
                wait_idle(c, pending, recovery_pin, guard=authorization_guard)
                authorization_guard()
                checkpoint("baseline_recovery_started")
                stable(lambda: rollback_pending(c, pending, recovery_pin,
                    idle_checkpoint(c, pending, recovery_pin, checkpoint, guard=authorization_guard)))
                stable(lambda: retire(c, pending, recovery_pin,
                                      Path(plan["operation_dir"]) / "previous-receipt",
                                      checkpoint=checkpoint))
                checkpoint("baseline_recovered")
            profile_guard()
            verify_binding(consumer, plan, binding)
            continuation.initialize(consumer, plan["continuation_dir"], deployment)
            # Durable pending.prepare is the only preparation authority. An interrupted
            # call is reconciled by exact old/new pins below, never blindly repeated.
            checkpoint("preparing")
            if os.path.lexists(base / pending.RECEIPT):
                receipt_raw = c.retained_file(base / pending.RECEIPT)[0]
                recovered_pin = sha(receipt_raw)
                with patient_locked(c):
                    r, _, _, unchanged = pending.load(c, recovered_pin, allow_unfenced=True)
                    require(r["old"]["sha256"] == plan["selected_sha256"] and
                            r["new"]["sha256"] == plan["candidate_sha256"], "Foreign preparation after interruption")
                    unchanged()
                prepared = {"receipt_sha256": recovered_pin}
            else:
                prepared = stable(lambda: pending.prepare(c, Path(plan["candidate"]),
                    expected_old_sha256=plan["selected_sha256"], expected_new_sha256=plan["candidate_sha256"]))
            pending_pin = prepared["receipt_sha256"]
            with patient_locked(c):
                r, _, _, unchanged = pending.load(c, pending_pin)
                unchanged()
            checkpoint("prepared", pending_pin=pending_pin, controller_operation_id=r["operation_id"])
        else:
            profile_guard = routing.profile_routing_guard(candidate)
            binding = checkpoint.value["binding"]
            with patient_locked(c):
                r, old, new, unchanged = pending.load(c, pending_pin, allow_unfenced=True)
                require(r["old"]["sha256"] == plan["selected_sha256"] and
                        r["new"]["sha256"] == plan["candidate_sha256"], "Resumed pending pins differ")
                unchanged()
        selected = False
        activated = False
        try:
            request = checkpoint.value.get("request")
            # Do not revalidate a claimed session as if its resumed messages were
            # human intervention. The immutable claim is the replay fence.
            if checkpoint.value.get("terminal"):
                checkpoint("continuation_observed", outcome=continuation.receipt_status(consumer, plan["continuation_dir"], request)["status"])
                return checkpoint.value
            profile_guard()
            def binding_probe():
                try:
                    return consumer.inspect_binding(
                        binding["session_id"], binding["profile"], binding["workspace"],
                        session_dir=Path(plan["session_dir"]), profile_home=Path(plan["state_home"]),
                    )["session_revision"]
                except consumer.Refused as exc:
                    if str(exc) == "pending durable work":
                        return None
                    raise
            wait_idle(c, pending, pending_pin, guard=authorization_guard, binding_probe=binding_probe)
            if request is None:
                binding = verify_binding(consumer, plan, binding)
                checkpoint("binding_refreshed", binding=binding)
                request = continuation.publish_request(consumer, plan["continuation_dir"],
                    admission_id=plan["operation_id"], controller_operation_id=r["operation_id"],
                    deployment=deployment, binding=binding, message=plan["resume_message"], runtime_adapter="legacy-direct")
                checkpoint("resume_request_published", request=request)
            # A published request cannot be rebound, including after interruption.
            binding = request["binding"]
            binding_guard = lambda: verify_binding(consumer, plan, binding, exact=True)
            post_restart_guard = lambda: verify_binding(consumer, plan, binding, authorize=False)
            # The human-anchor kill switch covers everything up to the FIRST
            # service signal. Past that edge the only remaining action is the
            # report to the session; aborting there (A3, 2026-10-26) left a
            # verified deployment with no continuation and one exception away
            # from an unwanted rollback.
            past_edge = []
            def edge_guard():
                (post_restart_guard if past_edge else binding_guard)()
            def edge_checkpoint(phase, **fields):
                checkpoint(phase, **fields)
                if phase == "before_kick" and not past_edge:
                    binding_guard()  # last anchor check, at the signal boundary
                    past_edge.append(phase)
            binding_guard()
            checkpoint("selecting")
            binding_guard()
            pending.select(c, pending_pin)
            selected = True
            require(sha(c.retained_file(c.manifest_path)[0]) == plan["candidate_sha256"], "Selection readback mismatch")
            checkpoint("selected")
            profile_guard()
            # run_activation owns its own bounded lock patience; wrapping it in
            # stable() restarted the whole activation on one lock collision.
            proof = run_activation(c, pending, pending_pin,
                idle_checkpoint(c, pending, pending_pin, edge_checkpoint, guard=edge_guard))
            activated = True
            profile_guard(); post_restart_guard()
            def publish_verified_terminal():
                with patient_locked(c):
                    refresh = c.refresh_admission()
                    r, _, new, unchanged = pending.load(c, pending_pin)
                    result = json.loads(c.retained_file(base / pending.RESULT)[0])
                    require(result.get("status") == "verified" and result.get("operation_id") == r["operation_id"]
                            and result.get("receipt_sha256") == pending_pin and result.get("selected") == "new",
                            "Missing exact terminal controller outcome")
                    require(sha(c.retained_file(c.manifest_path)[0]) == plan["candidate_sha256"], "Terminal selection drift")
                    fresh = c.snapshot(new, c.definitions(new))
                    require(result.get("candidate_identity") == fresh["process_identity"] and
                            result.get("process_identity") == fresh["process_identity"] and
                            proof.get("proof", {}).get("process_identity") == fresh["process_identity"],
                            "Terminal owner changed after settlement")
                    health = c.health(new)
                    refresh(); unchanged(); profile_guard()
                    post_restart_guard()
                    return continuation.publish_terminal(consumer, plan["continuation_dir"], request, fresh, health)
            terminal = stable(publish_verified_terminal)
            checkpoint("resume_terminal_published", terminal=terminal)
            until = time.monotonic() + 60
            while time.monotonic() < until:
                status = continuation.receipt_status(consumer, plan["continuation_dir"], request)
                if status["status"] == "worker_entered":
                    checkpoint("continuation_entered", outcome="worker_entered", stream_id=status["stream_id"])
                    return checkpoint.value
                time.sleep(1)
            # Healthy deployment, uncertain continuation: NEVER restart or replay.
            checkpoint("continuation_ambiguous", outcome="ambiguous")
            return checkpoint.value
        except Exception as exc:
            # Publication can succeed before a checkpoint/fsync error. Presence of
            # terminal authority disallows rollback/replay until independent review.
            terminal_exists = os.path.lexists(Path(plan["continuation_dir"]) / "terminal.json")
            checkpoint("operation_error", error=str(exc))
            if terminal_exists:
                checkpoint("continuation_ambiguous", outcome="ambiguous")
                return checkpoint.value
            if activated:
                # A verified activation is never rolled back for a reporting
                # failure: healthy deployment, no resume published. Terminal
                # outcome so a rerun does not re-select; the error still propagates.
                checkpoint("continuation_unpublished", outcome="verified_unreported")
                raise
            if selected or sha(c.retained_file(c.manifest_path)[0]) == plan["candidate_sha256"]:
                wait_idle(c, pending, pending_pin, guard=authorization_guard)
                checkpoint("rollback_started")
                stable(lambda: rollback_pending(c, pending, pending_pin,
                    idle_checkpoint(c, pending, pending_pin, checkpoint, guard=authorization_guard)))
                checkpoint("rollback_verified", outcome="rolled_back")
            else:
                checkpoint("stopped_before_selection", outcome="failed_before_selection")
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "run"))
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--approve", action="store_true")
    args = parser.parse_args(argv)

    def _alarm(signum, frame):
        raise RuntimeError(f"Hard runner timeout after {HARD_RUN_SECONDS}s — no phase progress")

    if args.action == "run":
        import signal
        signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(HARD_RUN_SECONDS)
    print(json.dumps({"step": "read_plan"}), flush=True)
    plan, candidate = read_plan(args.plan, args.plan_sha256)
    if args.action == "check":
        require(not args.approve, "Check accepts no approval flag")
        base, controls = Path(plan["base"]), Path(plan["controls"])
        print(json.dumps({"step": "prehash"}), flush=True)
        bytes_ = admission.prehash_bundle(base, controls, plan["control_refresh_sha256"])
        with admission.installed_modules(controls, bytes_) as (controller, pending):
            c = controller.Controller(base, control_refresh_sha256=plan["control_refresh_sha256"])
            print(json.dumps({"step": "inspection"}), flush=True)
            _, _, result = initial_inspection(c, pending, plan, candidate)
            print(json.dumps(result, indent=2))
        return 0
    require(args.approve and os.getppid() == 1, "Run requires explicit approval and a launchd-owned independent process")
    require(os.getpgrp() == os.getpid(), "Runner must own its process group")
    print(json.dumps({"step": "prehash"}), flush=True)
    with operation_lock(plan["operation_dir"]):
        checkpoint = Checkpoint(plan["operation_dir"], args.plan_sha256)
        result = execute(plan, candidate, checkpoint)
    return 0 if result.get("outcome") == "worker_entered" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        import traceback
        traceback.print_exc(file=sys.stderr)
        print(json.dumps({"status": "blocked_or_failed", "error": str(error)}), file=sys.stderr)
        raise SystemExit(2)
