"""Behavior tests for ``model_catalog.preferred_providers`` picker ordering."""

from unittest.mock import patch

import pytest


@pytest.fixture
def config_home(tmp_path, monkeypatch):
    home = tmp_path / "hermes"
    home.mkdir()
    (home / ".env").write_text("")
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv("HERMES_MODEL", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    monkeypatch.delenv("HERMES_INFERENCE_PROVIDER", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    # Update recovery walks the worktree's shared Git dir. In this repository that
    # dir lives under the real Hermes home, which trips the test I/O guard; the
    # picker behavior under test does not depend on update recovery.
    from hermes_cli import _early_recovery
    monkeypatch.setattr(_early_recovery, "restore_interrupted_pull", lambda *_args: False)
    return home


def _write_config(home, **top_level):
    import hermes_yaml as yaml

    cfg = {"model": "old-model", "custom_providers": []}
    cfg.update(top_level)
    (home / "config.yaml").write_text(yaml.safe_dump(cfg))


def _capture_provider_labels():
    from hermes_cli.main import select_provider_and_model

    captured = {}

    def _capture_and_cancel(labels, default=0, title=None):
        if "labels" not in captured:
            captured["labels"] = list(labels)

    with patch("hermes_cli.main._prompt_provider_choice", side_effect=_capture_and_cancel), \
            patch("builtins.print"):
        select_provider_and_model()
    return captured.get("labels", [])


def test_cli_picker_preferred_provider_group_is_first(config_home):
    # Copilot is plugin-hidden in a fresh isolated home. Use a visible built-in
    # provider and an alias to exercise CLI ordering without testing plugin setup.
    _write_config(config_home, model_catalog={"preferred_providers": ["claude"]})

    labels = _capture_provider_labels()

    assert labels
    assert labels[0].startswith("Anthropic"), labels[:5]


def test_shared_payload_preferred_provider_outranks_canonical_order(config_home):
    from hermes_cli.inventory import build_models_payload, load_picker_context

    _write_config(config_home, model_catalog={"preferred_providers": ["copilot"]})
    ctx = load_picker_context()
    rows = [
        {"slug": slug, "name": slug, "models": ["model"], "total_models": 1,
         "is_current": False, "is_user_defined": False}
        for slug in ("nous", "anthropic", "copilot")
    ]
    with patch("hermes_cli.model_switch.list_authenticated_providers", return_value=rows), \
            patch("hermes_cli.inventory._local_runtime_row", return_value=None), \
            patch("hermes_cli.inventory._moa_provider_row", return_value=None), \
            patch("hermes_cli.models_validate.drop_unofferable_model_ids"):
        payload = build_models_payload(ctx, canonical_order=True)

    assert payload["providers"][0]["slug"] == "copilot", [r["slug"] for r in payload["providers"]]
