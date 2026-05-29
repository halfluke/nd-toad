"""
Fortinet FortiOS adapter (Family C).

FortiOS configs use a nested ``config … / set … / end`` structure that maps
well to hier_config's FORTINET_FORTIOS platform.  We use hier_config for
``find_blocks`` and TextBasedConfig regex for YAML probes.
"""

from __future__ import annotations

import re
from pathlib import Path

from fluff.parsers.base import TextBasedConfig


class FortiOSConfig(TextBasedConfig):
    def __init__(self, path: Path, text: str) -> None:
        super().__init__(vendor="fortinet", profile="fortios", path=path, text=text)
        self._hc = None

    def _get_hc(self):
        if self._hc is None:
            try:
                from hier_config import get_hconfig, Platform
                self._hc = get_hconfig(Platform.FORTINET_FORTIOS, self.text)
            except Exception:
                self._hc = False
        return self._hc if self._hc is not False else None

    def get_hostname(self) -> str | None:
        # "set hostname <name>" under "config system global"
        m = re.search(r"(?m)^\s+set hostname\s+[\"']?(\S+)[\"']?", self.text, re.IGNORECASE)
        if m:
            return m.group(1).strip("\"'")
        return None


def load(path: Path) -> FortiOSConfig:
    return FortiOSConfig(path=path, text=path.read_text(encoding="utf-8", errors="replace"))
