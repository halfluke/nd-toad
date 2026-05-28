"""Cisco ASA adapter (Family A)."""

from __future__ import annotations

import re
from pathlib import Path

from fluff.parsers.cisco_like import CiscoLikeConfig


class CiscoASAConfig(CiscoLikeConfig):
    _SYNTAX = "asa"

    def __init__(self, path: Path, text: str) -> None:
        super().__init__(vendor="cisco", profile="cisco_asa", path=path, text=text)

    def get_hostname(self) -> str | None:
        # ASA uses "hostname <name>" like IOS; also check "hostname" in show output
        for line in self._lines:
            m = re.match(r"^\s*hostname\s+(\S+)", line, re.IGNORECASE)
            if m:
                return m.group(1)
        return None


def load(path: Path) -> CiscoASAConfig:
    return CiscoASAConfig(path=path, text=path.read_text(encoding="utf-8", errors="replace"))
