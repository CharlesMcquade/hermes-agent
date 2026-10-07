"""Composed ingress -> real adapter scheduler -> SQLite -> reply transport regressions.

Only the LLM handler and external transport are replaced. No Messages access.
The fixture uses the hardened proxy's wire schema (not a fabricated `text` field).
"""
import asyncio
import json
from types import SimpleNamespace

import pytest
from gateway.config import GatewayConfig, Platform, PlatformConfig
from gateway.platforms.base import SendResult
from gateway.platforms.webhook import WebhookAdapter
from gateway.session import SessionStore


def proxy_payload(**overrides):
    return dict(dict(sender="peer", prompt="hello", message_guid="msg", chat_guid="chat",
                     chat_identifier="peer", is_group=False, timestamp=1,
                     reply_capability="fixture-capability", attachments=[], history=[]), **overrides)


async def drain(adapter):
    async with asyncio.timeout(5):
        while adapter._background_tasks:
            await asyncio.sleep(.01)


@pytest.fixture
def harness(tmp_path):
    route = dict(secret="INSECURE_NO_AUTH", persistent_session=True, prompt="Framed: {prompt}",
                 deliver="telegram", deliver_extra={"chat_id": "{reply_capability}"}, toolsets=["safe"])
    adapter = WebhookAdapter(PlatformConfig(enabled=True, extra={"host": "127.0.0.1",
        "routes": {"a": route, "b": dict(route, toolsets=["terminal"])}}))
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    store = SessionStore(sessions, GatewayConfig())
    adapter.gateway_runner = SimpleNamespace(session_store=store, _session_db=store._db,
        _session_key_for_source=store._generate_session_key,
        _profile_name_for_source=lambda source, **kw: "default")
    events, ids, sent = [], [], []

    async def handler(event):
        events.append(event)
        entry = store.get_or_create_session(event.source)
        ids.append(entry.session_id)
        return "reply " + event.message_id

    async def transport(platform, content, delivery):
        sent.append((content, delivery["deliver_extra"]["chat_id"]))
        return SendResult(success=True)

    adapter._message_handler = handler
    adapter._deliver_cross_platform = transport
    yield adapter, store, events, ids, sent
    store._db.close()


async def post(adapter, payload, delivery="one", route="a"):
    class Request:
        match_info = {"route_name": route}
        headers = {"X-Request-ID": delivery}
        method = "POST"
        content_length = len(json.dumps(payload).encode())
        async def read(self):
            return json.dumps(payload).encode()
    response = await adapter._handle_webhook(Request())
    return response


@pytest.mark.asyncio
@pytest.mark.parametrize("invariant", ["reply", "persistence"])
async def test_persistent_reply_and_sqlite_lifecycle(harness, invariant):
    a, store, events, ids, sent = harness
    for delivery in ("one", "two"):
        assert (await post(a, proxy_payload(reply_capability=delivery), delivery)).status == 202
        await drain(a)
    if invariant == "reply":
        assert sent == [("reply one", "one"), ("reply two", "two")]
    else:
        assert ids[0] == ids[1]
        assert store._db.get_session(ids[0])["ended_at"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("invariant", ["route", "policy"])
async def test_route_isolation_and_spoofed_participant_policy(harness, invariant):
    a, store, events, ids, sent = harness
    for route, sender in (("a", "peer"), ("b", "peer"), ("a", "webhook:b")):
        await post(a, proxy_payload(sender=sender), route + sender, route)
        await drain(a)
    if invariant == "route":
        assert events[0].source.chat_id != events[1].source.chat_id
        assert ids[0] != ids[1]
        assert ids[0] == ids[2]
    else:
        assert [a.toolsets_for_source(e.source) for e in events] == [["safe"], ["terminal"], ["safe"]]
    assert events[2].raw_message["sender"] == "webhook:b"


@pytest.mark.asyncio
async def test_actual_proxy_prompt_slash_is_not_hidden_by_template(harness):
    a, _, events, _, sent = harness
    await post(a, proxy_payload(prompt="/new"))
    await drain(a)
    assert events[0].text == "/new"
    assert events[0].allow_gateway_control is True
    assert sent == [("reply one", "fixture-capability")]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [[], None, "string", 3, True])
async def test_nonobject_ingress_is_400(harness, payload):
    a, _, events, _, _ = harness
    assert (await post(a, payload)).status == 400
    assert not events and not a._background_tasks


@pytest.mark.asyncio
@pytest.mark.parametrize("second_route,second_prompt", [("a", "hello"), ("b", "hello"), ("a", "/status")])
async def test_concurrent_route_delivery_is_bound_to_each_turn(harness, second_route, second_prompt):
    a, store, events, ids, sent = harness
    started, release = asyncio.Event(), asyncio.Event()
    original = a._message_handler
    async def handler(event):
        if event.message_id == "one":
            started.set()
            await release.wait()
        # Also exercise direct runner progress sends without reply_to.
        await a.send(event.source.chat_id, "progress " + event.message_id)
        return await original(event)
    a._message_handler = handler
    await post(a, proxy_payload(reply_capability="cap-one"), "one")
    await asyncio.wait_for(started.wait(), 5)
    await post(a, proxy_payload(reply_capability="cap-two", prompt=second_prompt), "two", second_route)
    # Same-route follow-up is queued; separate route can finish in parallel.
    if second_route == "b" or second_prompt == "/status":
        async with asyncio.timeout(5):
            while not sent:
                await asyncio.sleep(.01)
    release.set()
    await drain(a)
    assert set(sent) == {("progress one", "cap-one"), ("reply one", "cap-one"),
                         ("progress two", "cap-two"), ("reply two", "cap-two")}


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["valid", "prefix", "directory", "nul", "symlink", "type", "traversal"])
async def test_attachment_containment_through_ingress(harness, tmp_path, kind, monkeypatch):
    a, _, events, _, _ = harness
    # Different OS identity from the gateway HOME, as with a separate proxy user.
    root = tmp_path / "proxy-home" / "Library" / "Messages" / "Attachments"
    root.mkdir(parents=True)
    if kind != "valid":
        from pathlib import Path
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "proxy-home")
    good = root / "image.png"
    good.write_bytes(b"fixture image")
    outside = root.with_name("Attachments-escape")
    outside.mkdir()
    secret = outside / "image.png"
    secret.write_bytes(b"must not read")
    link = root / "link.png"
    link.symlink_to(secret)
    paths = {"valid": str(good), "prefix": str(secret), "directory": str(root),
             "nul": str(good) + "\x00", "symlink": str(link), "type": [str(good)],
             "traversal": str(root / ".." / "Attachments-escape" / "image.png")}
    a._routes["a"]["attachment_roots"] = [str(root)]
    response = await post(a, proxy_payload(attachments=[dict(path=paths[kind], mime="image/png")]))
    await drain(a)
    if kind == "valid":
        assert response.status == 202
        assert len(events) == 1
        from pathlib import Path
        assert len(events[0].media_urls) == 1
        snapshot = Path(events[0].media_urls[0])
        good.unlink()
        good.symlink_to(secret)  # deferred vision must never reopen attacker-controlled path
        assert snapshot.read_bytes() == b"fixture image"
    else:
        assert response.status == 503
        assert not events and not a._seen_deliveries


@pytest.mark.asyncio
async def test_payload_cannot_grant_attachment_roots(harness, tmp_path):
    a, _, events, _, _ = harness
    image = tmp_path / "private.png"
    image.write_bytes(b"private")
    response = await post(a, proxy_payload(attachment_roots=[str(tmp_path)],
                               attachments=[dict(path=str(image), mime="image/png")]))
    await drain(a)
    assert response.status == 503
    assert not events and not a._seen_deliveries


@pytest.mark.asyncio
async def test_group_participants_isolate_even_with_shared_group_setting(harness):
    a, store, events, ids, sent = harness
    store.config.group_sessions_per_user = False
    for i, sender in enumerate(["alice", "bob", "alice"]):
        await post(a, proxy_payload(is_group=True, sender=sender), str(i))
        await drain(a)
    assert ids[0] != ids[1] and ids[0] == ids[2]


@pytest.mark.asyncio
async def test_one_shot_close_and_unbound_persistent_send_fails_closed(harness):
    a, store, events, ids, sent = harness
    a._routes["a"]["persistent_session"] = False
    await post(a, proxy_payload())
    await drain(a)
    assert store._db.get_session(ids[0])["end_reason"] == "webhook_complete"
    assert sent == [("reply one", "fixture-capability")]
    a._routes["a"]["persistent_session"] = True
    await post(a, proxy_payload(), "two")
    await drain(a)
    assert not (await a.send(events[-1].source.chat_id, "late unbound reply")).success


@pytest.mark.asyncio
async def test_route_policy_snapshot_survives_config_change_while_running(harness):
    a, _, events, _, sent = harness
    entered, release = asyncio.Event(), asyncio.Event()
    original = a._message_handler
    async def handler(event):
        entered.set()
        await release.wait()
        assert a.toolsets_for_source(event.source) == ["safe"]
        return await original(event)
    a._message_handler = handler
    await post(a, proxy_payload())
    await asyncio.wait_for(entered.wait(), 5)
    a._routes["a"]["toolsets"][:] = ["terminal"]
    a._routes["a"]["deliver_extra"]["chat_id"] = "wrong"
    release.set()
    await drain(a)
    assert sent == [("reply one", "fixture-capability")]


@pytest.mark.asyncio
async def test_new_runs_real_gateway_reset_and_rotates_sqlite_session(harness, monkeypatch):
    from gateway.run import GatewayRunner
    a, store, events, ids, sent = harness
    # External installer is irrelevant to the composed slash/session lifecycle.
    monkeypatch.setattr(GatewayRunner, "_init_startup_checks", lambda self: None)
    runner = GatewayRunner(config=GatewayConfig())
    runner.session_store = store
    from gateway.session import AsyncSessionStore
    runner._async_session_store = AsyncSessionStore(store)
    a.gateway_runner = runner
    runner.adapters[Platform.WEBHOOK] = a
    original = a._message_handler
    async def handler(event):
        if event.get_command() in ("new", "reset"):
            return await runner._handle_reset_command(event)
        return await original(event)
    a._message_handler = handler
    try:
        await post(a, proxy_payload(), "first")
        await drain(a)
        old = ids[-1]
        await post(a, proxy_payload(prompt="/new"), "reset")
        await drain(a)
        await post(a, proxy_payload(), "next")
        await drain(a)
        assert old != ids[-1]
        assert store._db.get_session(old)["ended_at"] is not None
        assert store._db.get_session(ids[-1])["ended_at"] is None
        assert len(sent) == 3
    finally:
        for name in ("_executor", "_housekeeping_executor"):
            pool = getattr(runner, name, None)
            if pool:
                pool.shutdown(wait=True)
