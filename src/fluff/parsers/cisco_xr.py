"""Cisco IOS-XR adapter.

IOS-XR is used on carrier-grade routers: ASR 9K, NCS series, CRS.
The CLI is superficially similar to IOS but uses a distinct structure:
- Configuration is committed explicitly (commit / show run committed)
- There is no "enable" mode; users have task-based authorization
- Many commands use different syntax (e.g. "router ospf" vs "router ospf 1")
- Interface naming uses long form: GigabitEthernet0/0/0/0
"""

from __future__ import annotations

import re
from pathlib import Path

from fluff.parsers.cisco_like import CiscoLikeConfig


class CiscoXRConfig(CiscoLikeConfig):
    _SYNTAX = "ios"  # ciscoconfparse2 uses ios syntax for XR flat format

    def __init__(self, path: Path, text: str) -> None:
        super().__init__(vendor="cisco", profile="cisco_xr", path=path, text=text)

    def get_hostname(self) -> str | None:
        # XR format: "hostname <name>" (same as IOS)
        m = re.search(r"(?m)^hostname\s+(\S+)", self.text, re.IGNORECASE)
        if m:
            return m.group(1)
        return super().get_hostname()


def load(path: Path) -> CiscoXRConfig:
    return CiscoXRConfig(path=path, text=path.read_text(encoding="utf-8", errors="replace"))
