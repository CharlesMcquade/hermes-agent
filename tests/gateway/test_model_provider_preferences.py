"""Gateway model-preference loading and its picker-specific provider path."""

from pathlib import Path
from unittest.mock import patch

from gateway.slash_commands_model import _ModelSwitchContext
from hermes_cli import _early_recovery
from hermes_cli.model_switch_providers import list_picker_providers


def test_configured_preference_reaches_interactive_gateway_picker():
    ctx = _ModelSwitchContext(
        session_key="s", source=None, config_path=Path("unused"), persist_global=False,
    )
    with patch.object(_early_recovery, "restore_interrupted_pull", return_value=False), \
            patch("gateway.run._load_gateway_config", return_value={
                "model_catalog": {"preferred_providers": ["copilot"]}
            }):
        ctx.read_config()
    assert ctx.preferred_provs == ["copilot"]

    rows = [
        {"slug": slug, "name": slug, "models": ["model"], "total_models": 1,
         "is_current": False, "is_user_defined": False}
        for slug in ("nous", "anthropic", "copilot")
    ]
    with patch("hermes_cli.model_switch.list_authenticated_providers", return_value=rows) as list_rows, \
            patch("hermes_cli.models_validate.drop_unofferable_model_ids"), \
            patch("hermes_cli.model_switch_providers._attach_window_model_notes"):
        providers = list_picker_providers(preferred_providers=ctx.preferred_provs)

    assert list_rows.call_args.kwargs["preferred_providers"] == ["copilot"]
    assert providers[0]["slug"] == "copilot", [row["slug"] for row in providers]
