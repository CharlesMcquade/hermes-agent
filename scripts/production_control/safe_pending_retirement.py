"""Crash-recoverable retirement of an exactly proved pending handoff.

The installed pending protocol remains the authority. Retirement does not select
or signal services, and an old selector without a matching live pair is refused.
An immutable private archive journals every byte before removing the fence.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(raw):
    return base64.b64encode(raw).decode("ascii")


def decode(value):
    return base64.b64decode(value, validate=True)


def retire(c, pending, pin, archive, *, checkpoint=lambda *a, **k: None):
    """Retire verified NEW or stably restored OLD; caller serializes its run.

    Idempotent across each unlink/transaction write; no other bytes are accepted.
    The archive must be the operation's dedicated absolute 0700 directory.
    """
    archive = Path(archive)
    require(archive.is_absolute() and archive == archive.resolve(), "Unsafe retirement archive")
    archive.mkdir(mode=0o700, parents=False, exist_ok=True)
    require(archive.stat().st_uid == os.getuid() and archive.stat().st_mode & 0o777 == 0o700,
            "Retirement archive must be private")
    journal = archive / "retirement.json"
    receipt_path = c.base / pending.RECEIPT
    result_path = c.base / pending.RESULT
    with c.locked():
        refresh = c.refresh_admission()
        refresh()
        if journal.exists():
            saved = json.loads(c.retained_file(journal)[0])
            require(saved.get("schema") == 1 and saved["pin"] == pin, "Foreign retirement journal")
        else:
            r, old, new, unchanged = pending.load(c, pin)
            selected = c.retained_file(c.manifest_path)[0]
            target = old if selected == pending.decode(r["old"]) else new
            require(selected in (pending.decode(r["old"]), pending.decode(r["new"])), "Foreign selection")
            result = {}
            dead_round = False
            if target is old:
                if c.clock() > r["deadline"]:
                    pass
                else:
                    # Charles-directed design change (2026-10-26): a NEVER-SELECTED
                    # round whose durable result still observes OLD is retireable
                    # before its deadline — the handoff never took effect, so the
                    # deadline protects nothing. The evidence is journaled verbatim;
                    # anything else still refuses closed.
                    result_path = c.base / pending.RESULT
                    require(os.path.lexists(result_path), "No durable result for dead-round retirement")
                    dead_result = json.loads(c.retained_file(result_path)[0])
                    require(dead_result.get("operation_id") == r["operation_id"]
                            and dead_result.get("selected") != "new",
                            "Unexpired old pending handoff cannot retire")
                    dead_round = True
            else:
                result = json.loads(c.retained_file(result_path)[0])
                require(result.get("status") == "verified" and result.get("operation_id") == r["operation_id"]
                        and result.get("receipt_sha256") == pin, "Candidate handoff is not terminal")
            c.check_revocation(target)
            c.preflight(target)
            proof = c.snapshot(target, c.definitions(target))
            require("process_identity" in proof, "Missing live retirement identity")
            if target is new:
                require(result.get("selected") == "new" and
                        result.get("process_identity") == proof["process_identity"] and
                        result.get("candidate_identity") == proof["process_identity"],
                        "Terminal retirement owner changed")
            transaction = c.retained_file(c.transaction_path)[0]
            txn = c.read_transaction()
            require(txn and txn.get("phase") in ("verified", "rolled_back")
                    and txn.get("pending_restart_sha256") == pin, "Foreign transaction fence")
            clear = dict(txn)
            clear.pop("pending_restart_sha256")
            envelope = json.loads(transaction)
            envelope["transaction"] = clear
            envelope["sha256"] = sha(json.dumps(clear, sort_keys=True, separators=(",", ":")).encode())
            cleared = (json.dumps(envelope, indent=2, sort_keys=True) + "\n").encode()
            saved = {"schema": 1, "pin": pin, "selection": encode(selected),
                     "receipt": encode(c.retained_file(receipt_path)[0]),
                     "result": encode(c.retained_file(result_path)[0]) if result_path.exists() else None,
                     "transaction": encode(transaction), "cleared": encode(cleared), "proof": proof,
                     "dead_round": dead_round}
            refresh(); unchanged()
            require(c.snapshot(target, c.definitions(target))["process_identity"] == proof["process_identity"],
                    "Retirement owner changed")
            raw = (json.dumps(saved, sort_keys=True) + "\n").encode()
            fd = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(raw); f.flush(); os.fsync(f.fileno())
            _sync(archive)
            require(c.retained_file(journal)[0] == raw, "Retirement journal readback failed")
        target = c.validate_manifest(json.loads(decode(saved["selection"])))
        require(sha(decode(saved["receipt"])) == pin, "Retirement receipt pin mismatch")
        expected_files = {receipt_path: decode(saved["receipt"]),
                          result_path: decode(saved["result"]) if saved["result"] is not None else None}
        def guard():
            refresh()
            require(c.retained_file(c.manifest_path)[0] == decode(saved["selection"]), "Selection changed during retirement")
            require(c.retained_file(c.transaction_path)[0] in (decode(saved["transaction"]), decode(saved["cleared"])),
                    "Transaction changed during retirement")
            for path, value in expected_files.items():
                if os.path.lexists(path):
                    require(value is not None and c.retained_file(path)[0] == value, "Foreign pending file during retirement")
            c.check_revocation(target)
            c.preflight(target)
            require(c.snapshot(target, c.definitions(target))["process_identity"] == saved["proof"]["process_identity"],
                    "Retirement owner changed")
        guard()
        # Missing receipt with a fence is fail-closed for the watchdog. Never leave
        # an unfenced active receipt for a new preparation to accidentally reuse.
        for path in (result_path, receipt_path):
            guard()
            if os.path.lexists(path):
                checkpoint("retiring_file", name=path.name, receipt_sha256=pin)
                guard()
                path.unlink()
                _sync(c.base)
        guard()
        checkpoint("retiring_fence", receipt_sha256=pin)
        guard()
        from restart_production import atomic_write
        if c.retained_file(c.transaction_path)[0] != decode(saved["cleared"]):
            atomic_write(c.transaction_path, decode(saved["cleared"]))
        require(c.retained_file(c.transaction_path)[0] == decode(saved["cleared"]), "Retirement readback failed")
        require("pending_restart_sha256" not in c.read_transaction(), "Fence not retired")
        return {"status": "retired", "receipt_sha256": pin, "archive": str(archive)}


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
