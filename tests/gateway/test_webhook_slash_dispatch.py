"""Tests: bare gateway slash commands bypass the route prompt (resolved pre-assembly)."""
import asyncio
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from gateway.platforms.webhook import WebhookAdapter  # noqa: E402


class _MinimalAdapter:
    _extract_slash_command = WebhookAdapter._extract_slash_command


def test_extract_bare_command():
    a = _MinimalAdapter()
    assert a._extract_slash_command({"text": "/new"}) == "/new"
    assert a._extract_slash_command({"text": "/new fresh topic"}) == "/new fresh topic"
    assert a._extract_slash_command({"message": "  /reset  "}) == "/reset"


def test_extract_rejects_non_commands():
    a = _MinimalAdapter()
    assert a._extract_slash_command({"text": "hello /new"}) is None
    assert a._extract_slash_command({"text": "please /new now"}) is None
    # Path-looking token is not a command
    assert a._extract_slash_command({"text": "/usr/bin/new"}) is None
    assert a._extract_slash_command({"no_text": 1}) is None
    assert a._extract_slash_command("not-a-dict") is None
