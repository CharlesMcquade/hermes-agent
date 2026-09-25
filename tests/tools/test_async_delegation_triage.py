"""Durable opt-in triage uses the real SQLite ledger in isolated HERMES_HOME."""
import queue
import time

from tools import async_delegation as ledger


def _finished(delegation_id, parent="parent-A", completed_at=None):
    now = completed_at or time.time()
    with ledger._DB_LOCK, ledger._transaction() as conn:
        conn.execute("""INSERT INTO async_delegations
            (delegation_id, origin_session, parent_session_id, state, dispatched_at,
             completed_at, updated_at, event_json, result_json)
            VALUES (?, 'route', ?, 'completed', ?, ?, ?, ?, ?)""",
            (delegation_id, parent, now, now, now,
             '{"type":"async_delegation"}', '{"summary":"important correction"}'))


def test_exact_owner_opt_in_and_atomic_settlement(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    _finished("a")
    _finished("b")
    assert ledger.late_result_disposition("parent-A", "a") == "wake"
    assert ledger.admit_late_result("parent-A", "a") is None
    assert ledger.finalize_parent_delegations("other", ["a"]) == []
    assert ledger.finalize_parent_delegations("parent-A", ["a", "missing", "a"]) == ["a"]
    assert ledger.late_result_disposition("parent-A", "a") == "triage"
    token = ledger.admit_late_result("parent-A", "a")
    assert token and ledger.admit_late_result("parent-A", "a") is None
    assert ledger.claim_completion_delivery("a", "normal") is False
    assert not ledger.settle_late_result("other", "a", token, "suppress")
    assert not ledger.settle_late_result("parent-A", "a", "wrong", "suppress")
    assert ledger.settle_late_result("parent-A", "a", token, "suppress")
    assert ledger.get_durable_delegation("a")["delivery_state"] == "suppressed"
    assert ledger.get_durable_delegation("a")["result"]["summary"] == "important correction"
    assert ledger.late_result_disposition("parent-A", "a") == "settled"
    assert ledger.late_result_disposition("other", "a") == "wake"
    assert ledger.late_result_disposition("parent-A", "b") == "wake"
    assert ledger.admit_late_result("parent-A", "a") is None


def test_retry_restart_and_preserve_unresolved(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    _finished("old", completed_at=time.time() - 60 * 3600)
    ledger.finalize_parent_delegations("parent-A", ["old"])
    token = ledger.admit_late_result("parent-A", "old")
    assert token
    with ledger._DB_LOCK, ledger._transaction() as conn:
        conn.execute("""UPDATE async_delegation_triage SET triage_claimed_at=0 WHERE delegation_id='old'""")
        conn.execute("""UPDATE async_delegations SET delivery_claimed_at=0 WHERE delegation_id='old'""")
    newer = ledger.admit_late_result("parent-A", "old")
    assert newer and newer != token
    assert not ledger.settle_late_result("parent-A", "old", token, "suppress")
    assert ledger.settle_late_result("parent-A", "old", newer, "wake")
    assert ledger.get_durable_delegation("old")["delivery_state"] == "pending"
    assert ledger.claim_completion_delivery("old", "normal")
    assert ledger.release_completion_delivery("old", "normal")
    monkeypatch.setattr(ledger, "_MAX_RETAINED_COMPLETED", 0)
    monkeypatch.setattr(ledger, "_MAX_DURABLE_PENDING", 0)
    ledger._prune_durable_records()
    assert ledger.get_durable_delegation("old") is not None
    # Existing replay age policy remains visible and queryable rather than erasing results.
    ledger.restore_undelivered_completions(queue.Queue())
    assert ledger.get_durable_delegation("old")["delivery_state"] == "pending"
    assert ledger.get_durable_delegation("old")["result"]["summary"] == "important correction"


def test_replay_cutoff_preserves_only_unresolved_opted_in(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    old = time.time() - 60 * 3600
    for ident in ("opted", "ordinary"):
        _finished(ident, completed_at=old)
    assert ledger.finalize_parent_delegations("parent-A", ["opted"]) == ["opted"]
    events = queue.Queue()
    assert ledger.restore_undelivered_completions(events) == 1
    assert events.get_nowait()["restored"] is True
    assert ledger.get_durable_delegation("opted")["delivery_state"] == "pending"
    assert ledger.get_durable_delegation("ordinary")["delivery_state"] == "dropped"


def test_prune_removes_orphans_and_acknowledged_only(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    for ident in ("pending", "delivered", "orphan"):
        _finished(ident)
    ledger.finalize_parent_delegations("parent-A", ["pending", "delivered", "orphan"])
    with ledger._DB_LOCK, ledger._transaction() as conn:
        conn.execute("UPDATE async_delegations SET delivery_state='delivered' WHERE delegation_id='delivered'")
        conn.execute("DELETE FROM async_delegations WHERE delegation_id='orphan'")
    monkeypatch.setattr(ledger, "_MAX_RETAINED_COMPLETED", 0)
    ledger._prune_durable_records()
    with ledger._DB_LOCK, ledger._transaction() as conn:
        assert conn.execute("SELECT delegation_id FROM async_delegation_triage").fetchall() == [("pending",)]
    assert ledger.get_durable_delegation("pending") is not None
    assert ledger.get_durable_delegation("delivered") is None


def test_normal_claim_precedes_triage_and_blocks_suppression(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    _finished("race")
    assert ledger.claim_completion_delivery("race", "normal")
    assert ledger.finalize_parent_delegations("parent-A", ["race"]) == ["race"]
    assert ledger.admit_late_result("parent-A", "race") is None
    assert ledger.get_durable_delegation("race")["delivery_state"] == "pending"
    assert ledger.release_completion_delivery("race", "normal")
    token = ledger.admit_late_result("parent-A", "race")
    assert token
    assert not ledger.claim_completion_delivery("race", "competing")
    assert ledger.settle_late_result("parent-A", "race", token, "suppress")
