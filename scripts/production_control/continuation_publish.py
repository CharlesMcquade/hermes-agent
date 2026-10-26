"""Trusted publisher for the private WebUI post-restart consumer.

This module never starts a turn or edits a transcript. It imports only the
hash-verified, stdlib-only consumer module, and publishes immutable private
records. The caller owns installed-controller admission and the operation lock.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from urllib.parse import quote

FILES = ("server.py", "api/routes.py", "api/post_restart_continuation.py",
         "api/runtime_adapter.py", "api/streaming.py")


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def load_consumer(manifest):
    """Execute exactly the module bytes included in the admitted inventory."""
    item = manifest["services"]["webui"]
    root = Path(item["repo"])
    path = root / "api/post_restart_continuation.py"
    raw = path.read_bytes()
    expected = item["inventory"].get("api/post_restart_continuation.py", {}).get("sha256")
    require(expected == hashlib.sha256(raw).hexdigest(), "Consumer inventory mismatch")
    spec = importlib.util.spec_from_file_location("_redeploy_continuation", path)
    if spec is None:
        raise RuntimeError("Cannot resolve continuation module")
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def deployment_binding(manifest):
    item = manifest["services"]["webui"]
    root = Path(item["repo"])
    hashes = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in FILES}
    require(all(item["inventory"].get(name, {}).get("sha256") == value for name, value in hashes.items()),
            "Continuation execution inventory mismatch")
    return {"release": str(root), "release_revision": item["commit"],
            "execution_digest": digest(hashes)}


def human_anchor(state_home, session_id):
    """Preserve user intervention even if an identical message is sent twice.

    Hermes delivers its own background-process and delegation notifications as
    user-role transcript rows; they are system noise, not human intervention,
    and must not trip the anchor between dispatch and continuation.
    """
    path = Path(state_home) / "state.db"
    for attempt in range(5):
        try:
            return _human_anchor_once(path, session_id)
        except sqlite3.OperationalError as exc:
            # Read-only opens on the WAL-mode state.db can transiently fail while
            # the owning process checkpoints; the anchor is re-read on every
            # settlement tick, so a single collision must not abort the run.
            if attempt == 4 or "unable to open" not in str(exc) and "locked" not in str(exc):
                raise
            time.sleep(0.5 * (attempt + 1))


def _human_anchor_once(path, session_id):
    with sqlite3.connect("file:" + quote(str(path), safe="/") + "?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        columns = {r[1] for r in db.execute("PRAGMA table_info(messages)")}
        kind = "display_kind" if "display_kind" in columns else "NULL AS display_kind"
        rows = db.execute(
            f"SELECT message_uid, content, {kind} FROM messages "
            "WHERE session_id=? AND role='user' ORDER BY id DESC", (session_id,))
        for row in rows:
            text = re.sub(r"^\[Workspace::v1: [^\r\n]+\]\r?\n", "", row["content"] or "", count=1)
            if row["display_kind"] != "steer" and text.startswith((
                    "[IMPORTANT: Background process", "[ASYNC DELEGATION BATCH")):
                continue
            require(bool(row["message_uid"]), "Missing durable user anchor")
            return digest({"message_uid": row["message_uid"], "content": text})
    raise RuntimeError("Missing durable user anchor")


def capture_settled(consumer, *, session_id, profile, workspace, session_dir,
                    state_home, expected_anchor, health, timeout=600, sleep=time.sleep,
                    clock=time.monotonic):
    """Wait for the initiating turn to settle; never clear pending metadata."""
    deadline = clock() + timeout
    while clock() < deadline:
        require(human_anchor(state_home, session_id) == expected_anchor,
                "User intervened after deployment was armed")
        try:
            binding = consumer.inspect_binding(session_id, profile, workspace,
                                               session_dir=Path(session_dir),
                                               profile_home=Path(state_home))
        except consumer.Refused as exc:
            # All other refusals are real ownership/identity failures, not busy.
            if str(exc) != "pending durable work":
                raise
        else:
            status = health()
            if status.get("status") == "ok" and status.get("active_runs") == 0 and status.get("active_streams") == 0:
                require(human_anchor(state_home, session_id) == expected_anchor,
                        "User intervened at settlement")
                return binding
        sleep(1)
    raise RuntimeError("Initiating session did not settle; no restart authorized")


def initialize(consumer, directory, deployment):
    directory = Path(directory)
    require(directory.is_absolute() and directory == directory.resolve(), "Noncanonical continuation directory")
    directory.mkdir(mode=0o700, parents=False, exist_ok=True)
    with consumer.Store(directory) as store, store.locked():
        prior = store.read("deployment.json")
        if prior is None:
            store.write("deployment.json", deployment)
        else:
            require(prior == deployment, "Continuation store belongs to a different release")


def publish_request(consumer, directory, *, admission_id, controller_operation_id,
                    deployment, binding, message, runtime_adapter="legacy-direct"):
    request = {"operation_admission_id": admission_id,
               "controller_operation_id": controller_operation_id,
               "deployment": deployment, "binding": binding, "message": message,
               "runtime_adapter": runtime_adapter}
    with consumer.Store(directory) as store, store.locked():
        prior = store.read("request.json")
        if prior is None:
            store.write("request.json", request)
        else:
            require(prior == request, "Immutable continuation request differs")
    return request


def publish_terminal(consumer, directory, request, proof, health):
    """Caller has independently verified the exact installed terminal result."""
    identity = proof["process_identity"]["webui"]["child"]
    require(proof.get("health") == "ok" and proof.get("deep_health") == "ok",
            "Missing verified live health")
    require(health.get("status") == "ok" and health.get("server_started_at"),
            "Missing owner health start identity")
    terminal = {"status": "terminal_verified",
                "operation_admission_id": request["operation_admission_id"],
                "controller_operation_id": request["controller_operation_id"],
                "request_digest": digest(request), "owner_pid": identity["pid"],
                "owner_started_at": health["server_started_at"],
                "deployment": request["deployment"]}
    with consumer.Store(directory) as store, store.locked():
        prior = store.read("terminal.json")
        if prior is None:
            store.write("terminal.json", terminal)
        else:
            require(prior == terminal, "Terminal proof already bound to another owner")
    return terminal


def receipt_status(consumer, directory, request):
    op = request["operation_admission_id"]
    with consumer.Store(directory) as store, store.locked():
        claim = store.read(op + ".claim.json")
        entry = store.read(op + ".entered.json")
        result = store.read(op + ".result.json")
    if claim is None:
        return {"status": "waiting"}
    require(claim.get("request_digest") == digest(request), "Foreign continuation claim")
    if not entry or not result:
        return {"status": "claimed_not_confirmed"}
    require(entry.get("operation_admission_id") == op and
            entry.get("status") == "worker_entered" and
            result.get("operation_admission_id") == op and
            entry.get("stream_id") == result.get("stream_id") and result.get("stream_id"),
            "Continuation entry/result mismatch")
    require(not result.get("error"), "Continuation launch was rejected")
    return {"status": "worker_entered", "stream_id": entry["stream_id"]}
