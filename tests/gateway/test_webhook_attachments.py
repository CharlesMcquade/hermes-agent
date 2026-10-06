"""Tests: inbound iMessage image attachments flow into MessageEvent.media_urls."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import gateway.platforms.webhook as wh  # noqa: E402


def _with_home(monkeypatch, tmp_path):
    root = tmp_path / "Library" / "Messages" / "Attachments"
    root.mkdir(parents=True)
    monkeypatch.setattr(wh.Path, "home", staticmethod(lambda: tmp_path))
    return root


def _mk(path, mime):
    return {"path": str(path), "mime": mime}


def test_filters_non_images_and_missing(monkeypatch, tmp_path):
    root = _with_home(monkeypatch, tmp_path)
    real = root / "a.png"; real.write_bytes(b"x")
    missing = root / "gone.png"
    got = wh.WebhookAdapter._resolve_attachments([
        _mk(real, "image/png"), _mk(missing, "image/png"),
        _mk(root / "b.mov", "video/quicktime")])
    assert got == [(str(real.resolve()), "image/png")]


def test_bounds_count(monkeypatch, tmp_path):
    root = _with_home(monkeypatch, tmp_path)
    items = []
    for i in range(10):
        f = root / f"x{i}.jpg"; f.write_bytes(b"x")
        items.append(_mk(f, "image/jpeg"))
    got = wh.WebhookAdapter._resolve_attachments(items)
    assert len(got) == 4


def test_rejects_outside_store_and_bad_shapes(monkeypatch, tmp_path):
    _with_home(monkeypatch, tmp_path)
    outside = tmp_path / "evil.png"; outside.write_bytes(b"x")
    got = wh.WebhookAdapter._resolve_attachments([
        "junk", None, {}, {"path": 1, "mime": "image/png"},
        _mk(outside, "image/png")])
    assert got == []
