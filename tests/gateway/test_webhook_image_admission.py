"""Process-local receipt ownership, with real ingress and private snapshot I/O."""
import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from gateway.config import PlatformConfig
from gateway.platforms.webhook import WebhookAdapter
import gateway.platforms.webhook_attachments as media


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    home = tmp_path / "receiver"
    root = tmp_path / "shared"
    root.mkdir()
    image = root / "image.png"
    image.write_bytes(b"image bytes")
    monkeypatch.setattr(media, "get_hermes_home", lambda: home)
    route = dict(secret="INSECURE_NO_AUTH", persistent_session=True,
                 attachment_roots=[str(root)], prompt="{prompt}")
    adapter = WebhookAdapter(PlatformConfig(enabled=True, extra={"routes": {"images": route}}))
    events = []
    async def record(event):
        events.append(event)
    adapter.handle_message = record
    payload = dict(prompt="image", chat_guid="conversation", sender="owner",
                   attachments=[dict(path=str(image), mime="image/png")])
    return adapter, payload, events, home, image


async def post(adapter, payload, delivery="stable"):
    body = json.dumps(payload).encode()
    class Request:
        match_info = {"route_name": "images"}
        headers = {"X-Request-ID": delivery}
        method = "POST"
        content_length = len(body)
        async def read(self):
            return body
    return await adapter._handle_webhook(Request())


def snapshots(home):
    return list((home / "cache" / "webhook_attachments").glob("*"))


def unadmitted(adapter, events, home):
    assert not adapter._seen_deliveries
    assert not adapter._pending_deliveries
    assert not adapter._delivery_info
    assert not adapter._background_tasks
    assert not snapshots(home)
    assert not events


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["snapshot", "partial", "resolver", "handler", "schedule", "cancel"])
async def test_failure_aborts_and_identical_retry_admits(fixture, failure):
    adapter, payload, events, home, image = fixture
    real = media._snapshot
    calls = 0
    def broken(*args):
        nonlocal calls
        calls += 1
        if failure == "partial" and calls == 1:
            return real(*args)
        raise OSError("offline storage fault")
    if failure == "partial":
        payload["attachments"] *= 2
    if failure in ("snapshot", "partial"):
        context = patch.object(media, "_snapshot", side_effect=broken)
    elif failure == "resolver":
        context = patch.object(adapter, "_resolve_attachments", side_effect=RuntimeError("interruption"))
    elif failure == "handler":
        def interrupted(event):
            raise RuntimeError("handler construction interrupted")
        context = patch.object(adapter, "handle_message", new=interrupted)
    else:
        error = asyncio.CancelledError() if failure == "cancel" else RuntimeError("no task admitted")
        context = patch("gateway.platforms.webhook.asyncio.create_task", side_effect=error)
    with context:
        if failure == "cancel":
            with pytest.raises(asyncio.CancelledError):
                await post(adapter, payload)
        else:
            assert (await post(adapter, payload)).status == 503
    unadmitted(adapter, events, home)
    response = await post(adapter, payload)
    assert response.status == 202
    assert len(snapshots(home)) == len(payload["attachments"])
    await asyncio.gather(*adapter._background_tasks)
    assert len(events) == 1
    image.unlink()
    response = await post(adapter, payload)
    assert json.loads(response.body)["status"] == "duplicate"
    assert len(events) == 1
    assert all(Path(path).read_bytes() == b"image bytes" for path in events[0].media_urls)


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["success", "failure", "cancel"])
async def test_concurrent_reservation_is_not_a_success_receipt(fixture, outcome):
    adapter, payload, events, home, _ = fixture
    entered, release = asyncio.Event(), asyncio.Event()
    original = adapter._admit_delivery
    async def paused(*args):
        entered.set()
        await release.wait()
        if outcome == "failure":
            raise RuntimeError("admission interrupted")
        return await original(*args)
    with patch.object(adapter, "_admit_delivery", side_effect=paused):
        first = asyncio.create_task(post(adapter, payload))
        await asyncio.wait_for(entered.wait(), 5)
        # Even expiry/pruning cannot turn a live reservation into another owner.
        adapter._prune_seen_deliveries(10**12)
        second = await post(adapter, payload)
        assert second.status == 503
        assert not adapter._seen_deliveries and not snapshots(home) and not events
        if outcome == "cancel":
            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first
        else:
            release.set()
            response = await asyncio.wait_for(first, 5)
            assert response.status == (202 if outcome == "success" else 503)
    assert not adapter._pending_deliveries
    if outcome != "success":
        unadmitted(adapter, events, home)
        assert (await post(adapter, payload)).status == 202
    await asyncio.gather(*adapter._background_tasks)
    assert len(events) == 1 and len(snapshots(home)) == 1
    assert json.loads((await post(adapter, payload)).body)["status"] == "duplicate"


@pytest.mark.asyncio
async def test_simultaneous_image_posts_admit_only_once(fixture):
    adapter, payload, events, home, _ = fixture
    responses = await asyncio.gather(*(post(adapter, payload) for _ in range(8)))
    assert [json.loads(r.body)["status"] for r in responses].count("accepted") == 1
    assert [json.loads(r.body)["status"] for r in responses].count("duplicate") == 7
    await asyncio.gather(*adapter._background_tasks)
    assert len(events) == 1 and len(snapshots(home)) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["roots", "malformed", "count", "missing", "mime"])
async def test_required_batch_rejects_instead_of_silently_filtering(fixture, bad):
    adapter, payload, events, home, image = fixture
    if bad == "roots":
        adapter._routes["images"]["attachment_roots"] = []
    elif bad == "malformed":
        payload["attachments"] = "not a list"
    elif bad == "count":
        payload["attachments"] *= 5
    elif bad == "missing":
        image.unlink()
    else:
        payload["attachments"][0]["mime"] = "video/mp4"
    assert (await post(adapter, payload)).status == 503
    unadmitted(adapter, events, home)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["coalesce", "deliver_only", "cron_job"])
async def test_required_images_cannot_bypass_snapshot_admission(fixture, mode):
    adapter, payload, events, home, _ = fixture
    adapter._routes["images"][mode] = True
    assert (await post(adapter, payload)).status == 503
    unadmitted(adapter, events, home)


@pytest.mark.asyncio
async def test_ordinary_route_retains_best_effort_filtering(fixture):
    adapter, payload, events, _, image = fixture
    adapter._routes["images"]["persistent_session"] = False
    image.unlink()
    assert (await post(adapter, payload)).status == 202
    await asyncio.gather(*adapter._background_tasks)
    assert len(events) == 1 and not events[0].media_urls


@pytest.mark.asyncio
@pytest.mark.parametrize("success", [True, False])
async def test_real_async_delivery_reservation_and_failed_status_retry(fixture, success):
    from gateway.platforms.base import SendResult
    adapter, payload, events, home, _ = fixture
    adapter._routes["images"].update(persistent_session=False, deliver_only=True, deliver="telegram")
    entered, release = asyncio.Event(), asyncio.Event()
    attempts = []
    async def transport(content, delivery):
        attempts.append(delivery)
        entered.set()
        await release.wait()
        return SendResult(success=success or len(attempts) > 1)
    adapter._direct_deliver = transport
    first = asyncio.create_task(post(adapter, payload))
    await asyncio.wait_for(entered.wait(), 5)
    assert (await post(adapter, payload)).status == 503
    assert len(attempts) == 1 and not adapter._seen_deliveries
    release.set()
    assert (await first).status == (200 if success else 502)
    assert not adapter._pending_deliveries
    if not success:
        assert not adapter._seen_deliveries
        assert (await post(adapter, payload)).status == 200
    assert json.loads((await post(adapter, payload)).body)["status"] == "duplicate"
    assert len(attempts) == (1 if success else 2)
    assert not events and not snapshots(home)
