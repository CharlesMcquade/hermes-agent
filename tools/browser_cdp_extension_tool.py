#!/usr/bin/env python3
"""
Browser control via connected browser extension's chrome.debugger API.

This tool sends CDP commands through a browser extension connected to the
Hermes gateway WebSocket. Unlike ``browser_cdp`` (which needs
``--remote-debugging-port`` and network-accessible CDP), this tool works
through the extension's native ``chrome.debugger`` permission — no flags,
no portproxy, no custom user-data-dir.

The extension must:
1. Be installed with the ``debugger`` permission
2. Be connected to this Hermes gateway via WebSocket (Local or Remote mode)
3. Have sent a ``cdp.register`` JSON-RPC request to register itself

Once registered, this tool pushes ``cdp.command`` JSON-RPC requests to the
extension, which executes them via ``chrome.debugger.sendCommand`` and
returns the result.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from tools.registry import registry, tool_error

logger = logging.getLogger(__name__)

CDP_DOCS_URL = "https://chromedevtools.github.io/devtools-protocol/"


def browser_cdp_extension(
    method: str,
    params: Optional[Dict[str, Any]] = None,
    target: Optional[Dict[str, Any]] = None,
    timeout: float = 30.0,
    relay_id: Optional[str] = None,
) -> str:
    """Send a CDP command to a browser extension's chrome.debugger.

    Args:
        method: CDP method name, e.g. ``"Runtime.evaluate"``, ``"Page.navigate"``.
        params: CDP method parameters as a dict.
        target: Tab targeting — one of:
            ``{"tabId": <number>}`` — specific Chrome tab ID
            ``{"active": true}`` — active tab in focused window (default)
            ``{"url": "partial-url"}`` — find tab by URL contains match
            ``{"index": <number>}`` — tab index in current window
        timeout: Seconds to wait for the extension to respond.
        relay_id: Optional relay ID (auto-selects if only one extension connected).

    Returns:
        JSON string with the CDP result, or error.
    """
    if not method or not isinstance(method, str):
        return tool_error(
            "'method' is required (e.g. 'Runtime.evaluate', 'Page.navigate')",
            cdp_docs=CDP_DOCS_URL,
        )

    try:
        from tui_gateway.cdp_relay import cdp_relay_registry
    except ImportError:
        return tool_error(
            "CDP relay registry is not available. The tui_gateway.cdp_relay "
            "module failed to import. This likely means the Hermes gateway "
            "was not restarted after the CDP relay code was added.",
            cdp_docs=CDP_DOCS_URL,
        )

    # Check if any relays are connected
    relays = cdp_relay_registry.list_relays()
    if not relays:
        return tool_error(
            "No browser extension with CDP relay is connected. Install the "
            "Hermes browser extension (with debugger permission) and connect "
            "it to this gateway. The extension must send cdp.register after "
            "connecting. Check that the gateway WebSocket (/api/ws) is enabled "
            "and the extension is in Local or Remote API mode.",
            cdp_docs=CDP_DOCS_URL,
        )

    call_params: Dict[str, Any] = params or {}
    if not isinstance(call_params, dict):
        return tool_error(
            f"'params' must be an object/dict, got {type(call_params).__name__}"
        )

    safe_timeout = float(timeout) if timeout else 30.0
    safe_timeout = max(1.0, min(safe_timeout, 300.0))

    # Special case: cdp.listTabs returns the Chrome tab list (not a CDP method)
    if method == "cdp.listTabs":
        try:
            result = cdp_relay_registry.send_command(
                method="__listTabs__",
                params={},
                target={"active": True},
                timeout=safe_timeout,
                relay_id=relay_id,
            )
        except RuntimeError as exc:
            return tool_error(str(exc), method=method)
        return json.dumps({"success": True, "method": "cdp.listTabs", "result": result}, ensure_ascii=False)

    # Special case: cdp.detach cleans up debugger attachments
    if method == "cdp.detach":
        try:
            result = cdp_relay_registry.send_command(
                method="__detach__",
                params=call_params,
                target={"active": True},
                timeout=safe_timeout,
                relay_id=relay_id,
            )
        except RuntimeError as exc:
            return tool_error(str(exc), method=method)
        return json.dumps({"success": True, "method": "cdp.detach", "result": result}, ensure_ascii=False)

    try:
        result = cdp_relay_registry.send_command(
            method=method,
            params=call_params,
            target=target or {"active": True},
            timeout=safe_timeout,
            relay_id=relay_id,
        )
    except RuntimeError as exc:
        return tool_error(str(exc), method=method)
    except Exception as exc:
        logger.exception("browser_cdp_extension unexpected error")
        return tool_error(
            f"Unexpected error: {type(exc).__name__}: {exc}",
            method=method,
        )

    payload: Dict[str, Any] = {
        "success": True,
        "method": method,
        "result": result,
    }
    return json.dumps(payload, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

BROWSER_CDP_EXTENSION_SCHEMA: Dict[str, Any] = {
    "name": "browser_cdp_extension",
    "description": (
        "Send a Chrome DevTools Protocol (CDP) command to a browser tab "
        "through a connected browser extension's chrome.debugger API. "
        "This does NOT require --remote-debugging-port — the extension "
        "uses its native debugger permission.\n\n"
        "The extension must be connected to the Hermes gateway WebSocket "
        "and have registered as a CDP relay. Use 'cdp.listTabs' (via "
        "browser_cdp_extension with method='cdp.listTabs') to list tabs, "
        "then use tab IDs for targeting.\n\n"
        f"**CDP method reference:** {CDP_DOCS_URL}\n\n"
        "**Common patterns:**\n"
        "- List tabs: method='cdp.listTabs' (special — returns Chrome tab list)\n"
        "- Evaluate JS: method='Runtime.evaluate', "
        "params={'expression': 'document.title', 'returnByValue': true}, "
        "target={'active': true}\n"
        "- Navigate: method='Page.navigate', params={'url': 'https://...'}, "
        "target={'tabId': 123}\n"
        "- Screenshot: method='Page.captureScreenshot', target={'active': true}\n\n"
        "**Targeting:**\n"
        "- {tabId: N} — specific tab (from cdp.listTabs)\n"
        "- {active: true} — active tab (default)\n"
        "- {url: 'youtube'} — first tab whose URL contains the string\n"
        "- {index: 0} — tab at this index in the current window"
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "method": {
                "type": "string",
                "description": (
                    "CDP method name (e.g. 'Runtime.evaluate', 'Page.navigate', "
                    "'Page.captureScreenshot'). Use 'cdp.listTabs' to list "
                    "available tabs."
                ),
            },
            "params": {
                "type": "object",
                "description": (
                    "CDP method parameters. Omit or pass {} for methods "
                    "that take no parameters."
                ),
                "properties": {},
                "additionalProperties": True,
            },
            "target": {
                "type": "object",
                "description": (
                    "Tab targeting. {tabId: N} for a specific tab, "
                    "{active: true} for the active tab (default), "
                    "{url: 'partial'} to find by URL, "
                    "{index: N} for tab index."
                ),
                "properties": {},
                "additionalProperties": True,
            },
            "timeout": {
                "type": "number",
                "description": "Timeout in seconds (default 30, max 300).",
                "default": 30,
            },
            "relay_id": {
                "type": "string",
                "description": (
                    "Optional relay ID when multiple extensions are connected. "
                    "Auto-selects if omitted."
                ),
            },
        },
        "required": ["method"],
    },
}


def _browser_cdp_extension_check() -> bool:
    """Availability check — always available (fails gracefully at call time
    if no extension is connected)."""
    return True


registry.register(
    name="browser_cdp_extension",
    toolset="browser-cdp",
    schema=BROWSER_CDP_EXTENSION_SCHEMA,
    handler=lambda args, **kw: browser_cdp_extension(
        method=args.get("method", ""),
        params=args.get("params"),
        target=args.get("target"),
        timeout=args.get("timeout", 30.0),
        relay_id=args.get("relay_id"),
    ),
    check_fn=_browser_cdp_extension_check,
    emoji="🔌",
)
