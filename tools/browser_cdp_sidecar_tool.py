#!/usr/bin/env python3
"""CDP through Verity Sidecar's authenticated WebUI-tab relay.

Unlike browser_cdp_remote, this does not require Chrome --remote-debugging-port.
Unlike the earlier browser_cdp_extension gateway version, this does not require
/api/ws. The extension long-polls the live WebUI over the same signed-in browser
session used by the WebUI itself.

Important: the relay registry is in-memory in the WebUI process. This tool is
intended for agents running inside that WebUI process. If invoked from a
separate CLI/gateway process, it may import the module but see no connected
relays.
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from tools.registry import registry, tool_error

logger = logging.getLogger(__name__)

CDP_DOCS_URL = "https://chromedevtools.github.io/devtools-protocol/"
WEBUI_REPO = Path.home() / "hermes-webui"


def _sidecar_bridge():
    try:
        import api.sidecar_cdp as sidecar_cdp  # type: ignore
        return sidecar_cdp
    except Exception:
        if WEBUI_REPO.exists() and str(WEBUI_REPO) not in sys.path:
            sys.path.insert(0, str(WEBUI_REPO))
        try:
            import api.sidecar_cdp as sidecar_cdp  # type: ignore
            return sidecar_cdp
        except Exception as exc:
            raise RuntimeError(
                "Could not import api.sidecar_cdp. The WebUI sidecar CDP module "
                "is not available in this process; restart the WebUI after staging "
                "the sidecar relay code."
            ) from exc


def _redact_cdp_output(value: Any) -> Any:
    try:
        from agent.redact import redact_sensitive_text
    except Exception:
        redact_sensitive_text = None  # type: ignore
    if isinstance(value, str):
        if redact_sensitive_text:
            return redact_sensitive_text(value, force=True)
        return value
    if isinstance(value, list):
        return [_redact_cdp_output(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_cdp_output(item) for item in value)
    if isinstance(value, dict):
        return {key: _redact_cdp_output(item) for key, item in value.items()}
    return value


def browser_cdp_sidecar(
    method: str,
    params: Optional[Dict[str, Any]] = None,
    target: Optional[Dict[str, Any]] = None,
    timeout: float = 30.0,
    relay_id: Optional[str] = None,
) -> str:
    """Send a CDP command through Verity Sidecar's authenticated WebUI relay."""
    method = str(method or "").strip()
    if not method:
        return tool_error("'method' is required", cdp_docs=CDP_DOCS_URL)
    call_params = params or {}
    if not isinstance(call_params, dict):
        return tool_error(f"'params' must be an object/dict, got {type(call_params).__name__}")
    safe_timeout = float(timeout) if timeout else 30.0
    safe_timeout = max(1.0, min(safe_timeout, 300.0))

    try:
        bridge = _sidecar_bridge()
    except RuntimeError as exc:
        return tool_error(str(exc), method=method)

    try:
        if method == "cdp.listRelays":
            return json.dumps({"success": True, "relays": bridge.list_relays()}, ensure_ascii=False)
        if method == "cdp.listTabs":
            result = bridge.send_command(
                method="__listTabs__",
                params={},
                target={"active": True},
                timeout=safe_timeout,
                relay_id=relay_id,
            )
        elif method == "cdp.detach":
            result = bridge.send_command(
                method="__detach__",
                params=call_params,
                target={"active": True},
                timeout=safe_timeout,
                relay_id=relay_id,
            )
        else:
            result = bridge.send_command(
                method=method,
                params=call_params,
                target=target or {"active": True},
                timeout=safe_timeout,
                relay_id=relay_id,
            )
    except RuntimeError as exc:
        return tool_error(str(exc), method=method, relays=getattr(bridge, "list_relays", lambda: [])())
    except Exception as exc:
        logger.exception("browser_cdp_sidecar unexpected error")
        return tool_error(f"Unexpected error: {type(exc).__name__}: {exc}", method=method)

    return json.dumps(
        {
            "success": True,
            "method": method,
            "result": _redact_cdp_output(result),
        },
        ensure_ascii=False,
    )


BROWSER_CDP_SIDECAR_SCHEMA: Dict[str, Any] = {
    "name": "browser_cdp_sidecar",
    "description": (
        "Send Chrome DevTools Protocol (CDP) commands through Verity Sidecar's "
        "authenticated WebUI-tab relay. This uses the browser extension's "
        "chrome.debugger permission and the same signed-in WebUI auth channel; "
        "it does not require --remote-debugging-port or /api/ws.\n\n"
        "Use method='cdp.listRelays' to see connected sidecars and "
        "method='cdp.listTabs' to list browser tabs.\n\n"
        f"CDP reference: {CDP_DOCS_URL}"
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "method": {
                "type": "string",
                "description": "CDP method name (e.g. Runtime.evaluate, Page.navigate). Special: cdp.listRelays, cdp.listTabs, cdp.detach.",
            },
            "params": {
                "type": "object",
                "description": "CDP method parameters.",
                "properties": {},
                "additionalProperties": True,
            },
            "target": {
                "type": "object",
                "description": "Tab target: {tabId:N}, {active:true}, {url:'partial'}, or {index:N}.",
                "properties": {},
                "additionalProperties": True,
            },
            "timeout": {"type": "number", "description": "Timeout in seconds (default 30, max 300).", "default": 30},
            "relay_id": {"type": "string", "description": "Optional relay id if multiple sidecars are connected."},
        },
        "required": ["method"],
    },
}


def _check() -> bool:
    return True


registry.register(
    name="browser_cdp_sidecar",
    toolset="browser-cdp",
    schema=BROWSER_CDP_SIDECAR_SCHEMA,
    handler=lambda args, **kw: browser_cdp_sidecar(
        method=args.get("method", ""),
        params=args.get("params"),
        target=args.get("target"),
        timeout=args.get("timeout", 30.0),
        relay_id=args.get("relay_id"),
    ),
    check_fn=_check,
    emoji="🧩",
)
