"""Browser-extension CDP relay registration and discovery.

Handlers: ``tui_gateway/cdp_relay_methods.py``; relay row producer:
``tui_gateway/cdp_relay.py::CdpRelayRegistry.list_relays``.
"""

from __future__ import annotations

from typing import Literal

from .base import Params, Result
from .registry import method


class CdpRegisterParams(Params):
    pass


class CdpRegisterResult(Result):
    relay_id: str
    status: Literal["registered"]


method("cdp.register", params=CdpRegisterParams, result=CdpRegisterResult,
       doc="Register this WebSocket transport as a CDP relay extension.")


class CdpListRelaysParams(Params):
    pass


class CdpRelayRow(Result):
    relay_id: str
    peer: str
    registered_at: float
    last_activity: float


class CdpListRelaysResult(Result):
    relays: list[CdpRelayRow]


method("cdp.listRelays", params=CdpListRelaysParams, result=CdpListRelaysResult,
       doc="List currently connected CDP relay extensions.")
