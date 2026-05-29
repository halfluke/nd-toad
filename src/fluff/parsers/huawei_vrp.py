"""Huawei VRP (Versatile Routing Platform) adapter.

VRP is used on Huawei NE, CE, AR, and S series devices.
Notable syntax features:
- Blocks are delimited by '#' comments at the top level
- sysname is the hostname keyword
- aaa, user-interface, snmp-agent are common config blocks
- "undo" is the negation prefix (instead of "no")
- Interface names use full form: GigabitEthernet0/0/0
"""

from __future__ import annotations

import re
from pathlib import Path

from fluff.parsers.base import TextBasedConfig


class HuaweiVRPConfig(TextBasedConfig):
    def __init__(self, path: Path, text: str) -> None:
        super().__init__(vendor="huawei", profile="huawei_vrp", path=path, text=text)

    def get_hostname(self) -> str | None:
        # VRP format: "sysname <name>"
        m = re.search(r"(?m)^sysname\s+(\S+)", self.text, re.IGNORECASE)
        if m:
            return m.group(1)
        return None


def load(path: Path) -> HuaweiVRPConfig:
    return HuaweiVRPConfig(path=path, text=path.read_text(encoding="utf-8", errors="replace"))
