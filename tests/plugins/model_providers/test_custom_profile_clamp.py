"""Tests for CustomProfile reasoning-effort clamping against config-declared lists.

The custom provider profile emits a top-level ``reasoning_effort`` field for
OpenAI-compatible reasoning endpoints (GLM-5.2 on SGLang, vLLM, etc.). When the
provider config declares a ``reasoning_efforts`` list for the model, the
resolved effort must be clamped to the nearest supported level — otherwise an
unsupported value (e.g. ``xhigh``) reaches the endpoint and produces a 400
that silently triggers model fallback.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def custom_profile():
    """Resolve the registered Custom profile via the provider registry."""
    import model_tools  # noqa: F401  — triggers plugin discovery
    import providers

    profile = providers.get_provider_profile("custom")
    assert profile is not None, "custom provider profile must be registered"
    return profile


# Import the helper functions for unit-level tests (after discovery has run).
def _get_helpers():
    import sys
    import providers

    profile = providers.get_provider_profile("custom")
    mod = sys.modules.get(type(profile).__module__)
    assert mod is not None, "custom profile module not found in sys.modules"
    return (
        mod._clamp_effort_to_supported,
        mod._resolve_supported_efforts,
    )


# ─── _clamp_effort_to_supported ───────────────────────────────────────────


class TestClampEffort:
    def test_supported_effort_forwarded_unchanged(self):
        _clamp = _get_helpers()[0]
        assert _clamp("high", ["none", "low", "medium", "high", "max"]) == "high"

    def test_xhigh_clamped_to_max_when_max_supported(self):
        """GLM-5.2 on SGLang: xhigh not in [none,low,medium,high,max] → max."""
        _clamp = _get_helpers()[0]
        assert _clamp("xhigh", ["none", "low", "medium", "high", "max"]) == "max"

    def test_xhigh_clamped_to_high_when_max_not_supported(self):
        _clamp = _get_helpers()[0]
        assert _clamp("xhigh", ["none", "low", "medium", "high"]) == "high"

    def test_max_forwarded_when_supported(self):
        _clamp = _get_helpers()[0]
        assert _clamp("max", ["none", "low", "medium", "high", "max"]) == "max"

    def test_ultra_clamped_to_max(self):
        _clamp = _get_helpers()[0]
        assert _clamp("ultra", ["none", "low", "medium", "high", "max"]) == "max"

    def test_minimal_clamped_to_low(self):
        _clamp = _get_helpers()[0]
        assert _clamp("minimal", ["none", "low", "medium", "high", "max"]) == "low"

    def test_empty_supported_returns_none(self):
        _clamp = _get_helpers()[0]
        assert _clamp("high", []) is None

    def test_unknown_effort_returns_first_supported(self):
        _clamp = _get_helpers()[0]
        assert _clamp("bogus", ["low", "high"]) == "low"

    def test_case_insensitive(self):
        _clamp = _get_helpers()[0]
        assert _clamp("XHigh", ["none", "low", "High", "Max"]) == "max"


# ─── _resolve_supported_efforts ───────────────────────────────────────────


class TestResolveSupportedEfforts:
    def test_returns_none_when_no_config_match(self, monkeypatch):
        _resolve = _get_helpers()[1]
        monkeypatch.setattr(
            "hermes_cli.config.get_compatible_custom_providers",
            lambda: [],
        )
        assert _resolve("GLM-5.2-512K", "http://127.0.0.1:18081/v1") is None

    def test_returns_none_when_model_not_in_provider(self, monkeypatch):
        _resolve = _get_helpers()[1]
        monkeypatch.setattr(
            "hermes_cli.config.get_compatible_custom_providers",
            lambda: [
                {
                    "name": "vllm-cw3e6e",
                    "base_url": "http://127.0.0.1:18081/v1",
                    "models": {
                        "GLM-5.2-512K": {
                            "reasoning_efforts": ["none", "low", "medium", "high", "max"],
                        }
                    },
                }
            ],
        )
        assert _resolve("GLM-5.2-300K", "http://127.0.0.1:18081/v1") is None

    def test_returns_list_when_matched(self, monkeypatch):
        _resolve = _get_helpers()[1]
        monkeypatch.setattr(
            "hermes_cli.config.get_compatible_custom_providers",
            lambda: [
                {
                    "name": "vllm-cw3e6e",
                    "base_url": "http://127.0.0.1:18081/v1",
                    "models": {
                        "GLM-5.2-512K": {
                            "reasoning_efforts": ["none", "low", "medium", "high", "max"],
                        }
                    },
                }
            ],
        )
        result = _resolve("GLM-5.2-512K", "http://127.0.0.1:18081/v1")
        assert result == ["none", "low", "medium", "high", "max"]

    def test_trailing_slash_normalized(self, monkeypatch):
        _resolve = _get_helpers()[1]
        monkeypatch.setattr(
            "hermes_cli.config.get_compatible_custom_providers",
            lambda: [
                {
                    "name": "vllm-cw3e6e",
                    "base_url": "http://127.0.0.1:18081/v1/",
                    "models": {
                        "GLM-5.2-512K": {
                            "reasoning_efforts": ["high", "max"],
                        }
                    },
                }
            ],
        )
        assert _resolve("GLM-5.2-512K", "http://127.0.0.1:18081/v1") == ["high", "max"]

    def test_case_insensitive_model_match(self, monkeypatch):
        _resolve = _get_helpers()[1]
        monkeypatch.setattr(
            "hermes_cli.config.get_compatible_custom_providers",
            lambda: [
                {
                    "name": "vllm-cw3e6e",
                    "base_url": "http://127.0.0.1:18081/v1",
                    "models": {
                        "glm-5.2-512k": {
                            "reasoning_efforts": ["high", "max"],
                        }
                    },
                }
            ],
        )
        assert _resolve("GLM-5.2-512K", "http://127.0.0.1:18081/v1") == ["high", "max"]


# ─── CustomProfile.build_api_kwargs_extras integration ────────────────────


class TestCustomProfileClampIntegration:
    """End-to-end: build_api_kwargs_extras clamps xhigh → max for GLM on SGLang."""

    def test_xhigh_clamped_to_max_for_glm_on_sglang(self, custom_profile, monkeypatch):
        monkeypatch.setattr(
            "hermes_cli.config.get_compatible_custom_providers",
            lambda: [
                {
                    "name": "vllm-cw3e6e",
                    "base_url": "http://127.0.0.1:18081/v1",
                    "models": {
                        "GLM-5.2-512K": {
                            "reasoning_efforts": ["none", "low", "medium", "high", "max"],
                        }
                    },
                }
            ],
        )
        extra_body, top_level = custom_profile.build_api_kwargs_extras(
            reasoning_config={"enabled": True, "effort": "xhigh"},
            model="GLM-5.2-512K",
            base_url="http://127.0.0.1:18081/v1",
        )
        assert top_level["reasoning_effort"] == "max"
        assert "think" not in extra_body

    def test_max_forwarded_unchanged_when_supported(self, custom_profile, monkeypatch):
        monkeypatch.setattr(
            "hermes_cli.config.get_compatible_custom_providers",
            lambda: [
                {
                    "name": "vllm-cw3e6e",
                    "base_url": "http://127.0.0.1:18081/v1",
                    "models": {
                        "GLM-5.2-512K": {
                            "reasoning_efforts": ["none", "low", "medium", "high", "max"],
                        }
                    },
                }
            ],
        )
        _, top_level = custom_profile.build_api_kwargs_extras(
            reasoning_config={"enabled": True, "effort": "max"},
            model="GLM-5.2-512K",
            base_url="http://127.0.0.1:18081/v1",
        )
        assert top_level["reasoning_effort"] == "max"

    def test_no_clamp_when_no_config_entry(self, custom_profile, monkeypatch):
        """When the model isn't in config, pass through verbatim (existing behavior)."""
        monkeypatch.setattr(
            "hermes_cli.config.get_compatible_custom_providers",
            lambda: [],
        )
        _, top_level = custom_profile.build_api_kwargs_extras(
            reasoning_config={"enabled": True, "effort": "xhigh"},
            model="some-unknown-model",
            base_url="http://example.test/v1",
        )
        assert top_level["reasoning_effort"] == "xhigh"

    def test_disabled_reasoning_emits_none(self, custom_profile, monkeypatch):
        monkeypatch.setattr(
            "hermes_cli.config.get_compatible_custom_providers",
            lambda: [
                {
                    "name": "vllm-cw3e6e",
                    "base_url": "http://127.0.0.1:18081/v1",
                    "models": {
                        "GLM-5.2-512K": {
                            "reasoning_efforts": ["none", "low", "medium", "high", "max"],
                        }
                    },
                }
            ],
        )
        extra_body, top_level = custom_profile.build_api_kwargs_extras(
            reasoning_config={"enabled": False, "effort": "xhigh"},
            model="GLM-5.2-512K",
            base_url="http://127.0.0.1:18081/v1",
        )
        assert top_level["reasoning_effort"] == "none"
        assert extra_body["think"] is False

    def test_ollama_num_ctx_still_works(self, custom_profile, monkeypatch):
        monkeypatch.setattr(
            "hermes_cli.config.get_compatible_custom_providers",
            lambda: [],
        )
        extra_body, _ = custom_profile.build_api_kwargs_extras(
            reasoning_config={"enabled": True, "effort": "high"},
            ollama_num_ctx=32768,
            model="llama3",
            base_url="http://localhost:11434/v1",
        )
        assert extra_body["options"]["num_ctx"] == 32768
