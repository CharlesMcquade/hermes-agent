"""Custom / Ollama (local) provider profile.

Covers any endpoint registered as provider="custom", including local
Ollama instances and OpenAI-compatible reasoning endpoints (GLM-5.2 on
Volcengine ARK, vLLM, llama.cpp). Key quirks:
  - ollama_num_ctx → extra_body.options.num_ctx (local context window)
  - reasoning_config disabled → top-level reasoning_effort="none"
    (Ollama /v1/chat/completions ignores think=False — ollama#14820)
    + extra_body.think = False for /api/chat and proxies
  - reasoning_config enabled + effort → top-level reasoning_effort
    (the native OpenAI-compatible format GLM/ARK expect; unset omits it
    so the endpoint's server default applies)
  - effort clamped against the model's configured ``reasoning_efforts``
    list so a Hermes-level effort (e.g. ``xhigh``) never reaches an
    endpoint whose SGLang/vLLM build rejects it (GLM-5.2 on SGLang
    accepts none/low/medium/high/max — not xhigh — and 400s otherwise,
    silently triggering fallback).
"""

from typing import Any

from providers import register_provider
from providers.base import ProviderProfile

# Ordered reasoning-effort ladder (weakest → strongest). Used to find the
# nearest supported level when the requested one isn't accepted by the
# endpoint.
_EFFORT_LADDER: tuple[str, ...] = (
    "none",
    "minimal",
    "low",
    "medium",
    "high",
    "xhigh",
    "max",
    "ultra",
)


def _clamp_effort_to_supported(requested: str, supported: list[str]) -> str | None:
    """Clamp a Hermes reasoning effort to the nearest supported wire value.

    If ``requested`` is already in ``supported``, return it unchanged.
    Otherwise walk the ordered ladder: first try the next *stronger* level
    (e.g. ``xhigh`` → ``max`` when the endpoint caps at ``max``), then the
    next *weaker* level (``xhigh`` → ``high`` when the endpoint caps at
    ``high``). Returns ``None`` when no supported level can be found.
    """
    requested = (requested or "").strip().lower()
    supported_lower = [str(s).strip().lower() for s in (supported or [])]
    if not supported_lower:
        return None
    if requested in supported_lower:
        return requested

    try:
        idx = _EFFORT_LADDER.index(requested)
    except ValueError:
        return supported_lower[0]

    # Walk outward from the requested position: stronger first, then weaker.
    for offset in range(1, len(_EFFORT_LADDER)):
        for candidate_idx in (idx + offset, idx - offset):
            if 0 <= candidate_idx < len(_EFFORT_LADDER):
                candidate = _EFFORT_LADDER[candidate_idx]
                if candidate in supported_lower:
                    return candidate
    return supported_lower[0]


def _resolve_supported_efforts(model: str | None, base_url: str | None) -> list[str] | None:
    """Look up the model's ``reasoning_efforts`` from config.yaml providers.

    Matches the custom-provider entry whose ``base_url`` matches (normalized,
    trailing-slash-insensitive) and whose ``models`` dict contains ``model``.
    Returns the list of effort strings, or ``None`` when no config entry
    declares a ``reasoning_efforts`` list for this model.
    """
    if not model or not base_url:
        return None
    try:
        from hermes_cli.config import get_compatible_custom_providers

        providers = get_compatible_custom_providers()
    except Exception:
        return None

    norm_target = str(base_url).strip().rstrip("/").lower()
    model_lower = str(model).strip().lower()

    for entry in providers:
        entry_url = str(entry.get("base_url", "") or "").strip().rstrip("/").lower()
        if entry_url != norm_target:
            continue
        models = entry.get("models")
        if not isinstance(models, dict):
            continue
        # Exact match first, then case-insensitive match.
        mcfg = models.get(model)
        if mcfg is None:
            for mname, mc in models.items():
                if str(mname).strip().lower() == model_lower:
                    mcfg = mc
                    break
        if not isinstance(mcfg, dict):
            continue
        efforts = mcfg.get("reasoning_efforts")
        if isinstance(efforts, list) and efforts:
            return [str(e).strip().lower() for e in efforts if str(e).strip()]
    return None


class CustomProfile(ProviderProfile):
    """Custom/Ollama local provider — think=false and num_ctx support."""

    def build_api_kwargs_extras(
        self,
        *,
        reasoning_config: dict | None = None,
        ollama_num_ctx: int | None = None,
        model: str | None = None,
        base_url: str | None = None,
        **ctx: Any,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        extra_body: dict[str, Any] = {}
        top_level: dict[str, Any] = {}

        # Ollama context window
        if ollama_num_ctx:
            options = extra_body.get("options", {})
            options["num_ctx"] = ollama_num_ctx
            extra_body["options"] = options

        # Reasoning / thinking control for custom OpenAI-compatible endpoints
        # (GLM-5.2 on Volcengine ARK, vLLM, Ollama, llama.cpp, …).
        #
        #   - disabled  → extra_body.think = False (Ollama's thinking-off flag)
        #   - enabled + effort set → TOP-LEVEL reasoning_effort string, the
        #     format GLM-5.2/ARK and other OpenAI-compatible reasoning APIs
        #     expect (GLM documents "high" and "max"; "max" is its default).
        #   - enabled + no effort  → omit both, so the endpoint applies its own
        #     server-side default (do NOT force a level the user didn't pick).
        #
        # We deliberately do NOT emit ``think=True`` on enable: it is an
        # Ollama-only flag and thinking is already server-default-on for these
        # backends, so forcing it risks a 400 on GLM/vLLM endpoints that don't
        # recognize it. Mirrors the DeepSeek/Zai profile precedent.
        #
        # Clamping: when the provider config declares a ``reasoning_efforts``
        # list for this model (e.g. GLM-5.2-512K on SGLang: [none, low, medium,
        # high, max]), clamp the resolved effort to the nearest supported level
        # before emitting it. This prevents a session-level ``xhigh`` override
        # from reaching an SGLang endpoint that rejects it with a 400, silently
        # triggering model fallback. (CopilotProfile does the same with its
        # live catalog; CustomProfile uses the config-declared list.)
        if reasoning_config and isinstance(reasoning_config, dict):
            _effort = (reasoning_config.get("effort") or "").strip().lower()
            _enabled = reasoning_config.get("enabled", True)
            if _effort == "none" or _enabled is False:
                # Ollama's /v1/chat/completions silently ignores
                # extra_body.think (only /api/chat honours it — ollama#14820)
                # but respects the top-level reasoning_effort field, so both
                # are needed to actually stop a thinking-capable model from
                # reasoning (#25758). Endpoints that recognize neither simply
                # ignore them.
                top_level["reasoning_effort"] = "none"
                extra_body["think"] = False
            elif _effort:
                # Prefer the model's configured wire vocabulary when present;
                # custom SGLang/vLLM endpoints can be stricter than the widest
                # OpenAI-compatible set (for example, GLM rejects ``xhigh``).
                _supported = _resolve_supported_efforts(model, base_url)
                if _supported is not None:
                    _clamped = _clamp_effort_to_supported(_effort, _supported)
                    if _clamped is not None:
                        _effort = _clamped

                # Otherwise clamp the internal ladder onto the widest
                # OpenAI-compatible wire vocabulary (shared upstream policy).
                from agent.reasoning_effort import (
                    OPENAI_COMPAT_WIRE_EFFORTS,
                    clamp_effort,
                )

                top_level["reasoning_effort"] = clamp_effort(
                    _effort,
                    _supported or OPENAI_COMPAT_WIRE_EFFORTS,
                )

        return extra_body, top_level

    def fetch_models(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = 8.0,
    ) -> list[str] | None:
        """Custom/Ollama: base_url is user-configured; fetch if set."""
        if not (base_url or self.base_url):
            return None
        return super().fetch_models(api_key=api_key, base_url=base_url, timeout=timeout)


custom = CustomProfile(
    name="custom",
    aliases=(
        "ollama",
        "local",
        "vllm",
        "llamacpp",
        "llama.cpp",
        "llama-cpp",
    ),
    env_vars=(),  # No fixed key — custom endpoint
    base_url="",  # User-configured
    # Without this, no max_tokens is sent and Ollama falls back to its internal
    # num_predict=128, truncating responses after a few tokens (#39281). This is
    # only a floor used when the user hasn't set model.max_tokens — they can
    # override per-model — so we set it generously rather than lowballing it.
    default_max_tokens=65536,
)

register_provider(custom)
