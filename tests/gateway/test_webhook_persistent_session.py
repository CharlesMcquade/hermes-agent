
"""Behavioral tests for persistent_session webhook routes (prototype)."""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from gateway.platforms.webhook import WebhookAdapter


def _adapter():
    a = WebhookAdapter.__new__(WebhookAdapter)
    a.platform = MagicMock()
    a._delivery_info = {}
    a._delivery_info_created = {}
    a._delivery_info_order = __import__("collections").deque()
    a._background_tasks = set()
    a._prune_delivery_info = lambda now: None
    a._captured_source = {}
    def _build_source(**kw):
        a._captured_source.update(kw)
        return kw
    a.build_source = _build_source
    a.handle_message = AsyncMock()
    return a


def _route_config():
    return {"deliver": "log", "persistent_session": True, "prompt": "{prompt}"}


def _spawn(a):
    task = a._spawn_agent_run(
        {"sender": "charles", "chat_guid": "any;-;+15550001111", "chat_identifier": "+15550001111",
         "is_group": False, "prompt": "hello", "message_guid": "m-1"},
        "hello", "d-1", 1000.0, route_config=_route_config(), route_name="verity-imsg",
        profile=None, event_type="message")
    return task


def test_persistent_route_uses_conversation_chat_id_and_sender():
    a = _adapter()
    async def run():
        return _spawn(a)
    asyncio.run(run())
    # source is a kwargs dict captured from our stubbed build_source
    src = a._captured_source
    assert src["chat_id"] == "any;-;+15550001111"
    assert src["chat_type"] == "dm"
    assert src["user_id"] == "charles"
    # delivery info carries the flag
    info = list(a._delivery_info.values())[0]
    assert info["persistent_session"] is True


def test_group_route_isolates_per_sender_with_group_chat_type():
    a = _adapter()
    async def run():
        return a._spawn_agent_run(
            {"sender": "alice", "chat_guid": "any;+;g-uuid", "chat_identifier": "g-uuid",
             "is_group": True, "prompt": "hi", "message_guid": "m-2"},
            "hi", "d-2", 1000.0, route_config=_route_config(), route_name="verity-imsg",
            profile=None, event_type="message")
    asyncio.run(run())
    src = a._captured_source
    assert src["chat_id"] == "any;+;g-uuid"
    assert src["chat_type"] == "group"
    assert src["user_id"] == "alice"


def test_one_shot_route_unchanged_without_flag():
    a = _adapter()
    async def run():
        return a._spawn_agent_run(
            {"sender": "charles", "chat_guid": "any;-;+15550001111", "prompt": "hello"},
            "hello", "d-3", 1000.0, route_config={"deliver": "log", "prompt": "{prompt}"},
            route_name="verity-imsg", profile=None, event_type="message")
    asyncio.run(run())
    src = a._captured_source
    assert src["chat_id"] == "webhook:verity-imsg:d-3"
    assert src["user_id"] == "webhook:verity-imsg"
    assert list(a._delivery_info.values())[0]["persistent_session"] is False


def test_persistent_session_not_ended_on_processing_complete():
    a = _adapter()
    a._end_webhook_session = AsyncMock()
    a.logger = MagicMock()
    evt = MagicMock()
    evt.source.chat_id = "any;-;+15550001111"
    a._delivery_info[evt.source.chat_id] = {"persistent_session": True}
    asyncio.run(a.on_processing_complete(evt, None))
    a._end_webhook_session.assert_not_called()


def test_one_shot_session_still_ended_on_processing_complete():
    a = _adapter()
    a._end_webhook_session = AsyncMock()
    evt = MagicMock()
    evt.source.chat_id = "webhook:verity-imsg:d-1"
    a._delivery_info[evt.source.chat_id] = {"persistent_session": False}
    asyncio.run(a.on_processing_complete(evt, None))
    a._end_webhook_session.assert_awaited_once()
