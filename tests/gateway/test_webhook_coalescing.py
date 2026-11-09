"""Per-route webhook event coalescing (#92066): rapid distinct events on one entity debounce into
a single agent run on the latest event's state; unrelated or unkeyed events are never merged."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from gateway.config import PlatformConfig
from gateway.platforms import webhook_ingress
from gateway.platforms.webhook import WebhookAdapter, _INSECURE_NO_AUTH


def _make_adapter(routes=None):
    extra = {"host": "127.0.0.1", "port": 0, "routes": routes or {}, "rate_limit": 100}
    return WebhookAdapter(PlatformConfig(enabled=True, extra=extra))


def _capture_admissions(adapter, monkeypatch):
    """Stand in for the durable producer: the adapter admits every dispatched event through
    ``admit_producer`` (immediate and coalesced paths alike), never a spawned ``handle_message``.
    Returns the list of admitted events; the finalize task is a no-op."""
    admitted = []

    async def _admit(_adapter, event):
        admitted.append(event)
        return SimpleNamespace(admission_id=f"adm-{len(admitted)}", ref=SimpleNamespace(profile_id="default"))

    async def _finalize(event, authority, receipt):
        return None

    monkeypatch.setattr(webhook_ingress, "admit_producer", _admit)
    monkeypatch.setattr(adapter, "_finalize_delivery", _finalize)
    adapter._message_handler = SimpleNamespace(__self__=SimpleNamespace())
    monkeypatch.setattr("gateway.session_authorities.authority_for_profile_id", lambda runner, pid: object())
    return admitted


def _coalesce_route(**coalesce):
    return {"secret": _INSECURE_NO_AUTH, "prompt": "PR {pull_request.number}: {action}",
            "coalesce": coalesce or {"key": "pull_request.number"}}


def _mock_request(body: bytes, route_name: str = "pr", delivery_id: str = ""):
    req = MagicMock()
    req.headers = {"X-GitHub-Delivery": delivery_id} if delivery_id else {}
    req.content_length = len(body)
    req.match_info = {"route_name": route_name}
    req.method = "POST"

    async def _read():
        return body

    req.read = _read
    return req


def _payload(pr_number=None, action: str = "synchronize") -> bytes:
    body: dict = {"action": action}
    if pr_number is not None:
        body["pull_request"] = {"number": pr_number}
    return json.dumps(body).encode()


@pytest.mark.asyncio
@pytest.mark.parametrize("route, match", [
    ({**_coalesce_route(), "coalesce": {"window_seconds": 5}}, "coalesce block"),
    ({**_coalesce_route(), "coalesce": "pull_request.number"}, "coalesce block"),
    (_coalesce_route(key="pull_request.number", window_seconds=0), "window_seconds"),
    (_coalesce_route(key="pull_request.number", max_wait_seconds=True), "max_wait_seconds"),
    ({**_coalesce_route(), "deliver_only": True, "deliver": "telegram"}, "deliver_only"),
    ({**_coalesce_route(), "cron_job": "sweeper"}, "cron_job"),
])
async def test_invalid_coalesce_config_rejected_at_connect(route, match, tmp_path, monkeypatch):
    with pytest.raises(ValueError, match=match):
        await _make_adapter(routes={"pr": route}).connect()
    # The same block on a hot-reloaded dynamic route is skipped (warned), never admitted — it would
    # otherwise raise inside the request handler.
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "webhook_subscriptions.json").write_text(json.dumps({"dyn": route}), encoding="utf-8")
    adapter = _make_adapter()
    adapter._reload_dynamic_routes()
    assert "dyn" not in adapter._routes


@pytest.mark.asyncio
async def test_rapid_same_entity_events_dispatch_once_with_latest(monkeypatch):
    """Three events on PR 7 → one run carrying the last event's prompt/delivery id and a superseded
    note; a different PR in the same burst is its own group; a provider retry (same delivery id)
    is dropped by idempotency before coalescing and is not counted."""
    adapter = _make_adapter(routes={"pr": _coalesce_route(key="pull_request.number", window_seconds=0.05)})
    admitted = _capture_admissions(adapter, monkeypatch)

    statuses = []
    for i, action in enumerate(["opened", "synchronize", "synchronize"]):
        resp = await adapter._handle_webhook(_mock_request(_payload(7, action), delivery_id=f"d{i}"))
        statuses.append((resp.status, json.loads(resp.text)["status"]))
    retry = await adapter._handle_webhook(_mock_request(_payload(7), delivery_id="d2"))
    other = await adapter._handle_webhook(_mock_request(_payload(8), delivery_id="other"))
    assert statuses == [(202, "coalesced")] * 3
    assert json.loads(retry.text)["status"] == "duplicate"
    assert json.loads(other.text)["status"] == "coalesced"
    assert admitted == []

    await asyncio.sleep(0.15)

    events = {e.message_id: e for e in admitted}
    assert set(events) == {"d2", "other"}
    assert "PR 7: synchronize" in events["d2"].text and "3 webhook events" in events["d2"].text
    assert "coalesced" not in events["other"].text
    assert adapter._coalescer.pending == {}


@pytest.mark.asyncio
async def test_max_wait_caps_starvation_and_unresolved_key_dispatches_immediately(monkeypatch):
    adapter = _make_adapter(routes={"pr": _coalesce_route(key="pull_request.number", window_seconds=10,
                                                          max_wait_seconds=0.1)})
    admitted = _capture_admissions(adapter, monkeypatch)

    # An event without the key field must not be folded into a shared "{pull_request.number}" group.
    resp = await adapter._handle_webhook(_mock_request(_payload(None, "created"), delivery_id="nokey"))
    assert json.loads(resp.text)["status"] == "accepted"
    assert len(admitted) == 1

    # A stream faster than the 10s window still dispatches once max_wait (0.1s) elapses.
    for i in range(3):
        await adapter._handle_webhook(_mock_request(_payload(5), delivery_id=f"s{i}"))
        await asyncio.sleep(0.02)
    await asyncio.sleep(0.15)
    assert len(admitted) == 2
    assert "3 webhook events" in admitted[-1].text


@pytest.mark.asyncio
async def test_bound_runner_admission_failure_is_not_acked_or_legacy_dispatched(monkeypatch):
    """A bound runner cannot silently fall back to background handle_message dispatch: admission
    failure must propagate as a retryable HTTP 503, with neither a receipt nor delivery authority."""
    adapter = _make_adapter(routes={"pr": {"secret": _INSECURE_NO_AUTH, "prompt": "PR 7"}})
    _capture_admissions(adapter, monkeypatch)
    legacy_calls = []

    async def _legacy(event):
        legacy_calls.append(event)

    async def _reject(_adapter, event):
        raise RuntimeError("authority unavailable")

    adapter.handle_message = _legacy
    monkeypatch.setattr(webhook_ingress, "admit_producer", _reject)

    response = await adapter._handle_webhook(_mock_request(_payload(7), delivery_id="failed"))

    assert response.status == 503
    assert legacy_calls == []
    assert adapter._seen_deliveries == {}
    assert adapter._pending_deliveries == set()
    assert adapter._delivery_info == {}


@pytest.mark.asyncio
async def test_failed_coalesced_admission_releases_every_receipt(monkeypatch):
    """The early coalesced ack is only reversible if a later admission failure releases both the
    latest delivery and every superseded sibling, without publishing an uncommitted destination."""
    adapter = _make_adapter(routes={"pr": _coalesce_route(key="pull_request.number", window_seconds=60)})
    _capture_admissions(adapter, monkeypatch)
    for delivery_id in ("first", "latest"):
        response = await adapter._handle_webhook(_mock_request(_payload(7), delivery_id=delivery_id))
        assert response.status == 202
    assert len(adapter._seen_deliveries) == 2

    attempts = []

    async def _reject(_adapter, event):
        attempts.append(event.message_id)
        raise RuntimeError("authority unavailable")

    monkeypatch.setattr(webhook_ingress, "admit_producer", _reject)
    await adapter.disconnect()

    assert attempts == ["latest"]
    assert adapter._seen_deliveries == {}
    assert adapter._delivery_info == {}


@pytest.mark.asyncio
async def test_disconnect_flushes_pending_groups(monkeypatch):
    adapter = _make_adapter(routes={"pr": _coalesce_route(key="pull_request.number", window_seconds=60)})
    admitted = _capture_admissions(adapter, monkeypatch)
    await adapter._handle_webhook(_mock_request(_payload(4), delivery_id="pend"))
    assert admitted == []

    await adapter.disconnect()

    assert len(admitted) == 1
    assert admitted[0].message_id == "pend"
    assert adapter._coalescer.pending == {}
