"""HPE Aruba / ProCurve adapter (Family A — IOS-like CLI)."""

from __future__ import annotations

import re
from pathlib import Path

from fluff.parsers.cisco_like import CiscoLikeConfig


class HPEArubaConfig(CiscoLikeConfig):
    _SYNTAX = "ios"  # ProCurve/AOS-CX uses a broadly IOS-compatible CLI

    def __init__(self, path: Path, text: str) -> None:
        super().__init__(vendor="hpe", profile="hpe_aruba", path=path, text=text)

    def get_hostname(self) -> str | None:
        for line in self._lines:
            m = re.match(r"^\s*hostname\s+['\"]?([^'\"]+)['\"]?", line, re.IGNORECASE)
            if m:
                return m.group(1).strip()
        return None


def load(path: Path) -> HPEArubaConfig:
    return HPEArubaConfig(path=path, text=path.read_text(encoding="utf-8", errors="replace"))
