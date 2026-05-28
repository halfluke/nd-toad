"""Arista EOS adapter (Family A — IOS-like syntax)."""

from __future__ import annotations

import re
from pathlib import Path

from fluff.parsers.cisco_like import CiscoLikeConfig


class AristaEOSConfig(CiscoLikeConfig):
    _SYNTAX = "ios"  # EOS uses IOS-compatible syntax

    def __init__(self, path: Path, text: str) -> None:
        super().__init__(vendor="arista", profile="arista_eos", path=path, text=text)

    def get_hostname(self) -> str | None:
        # EOS: "! device: HOSTNAME, EOS-4.x"
        for line in self._lines:
            m = re.match(r"^!\s*device:\s*(\S+),", line, re.IGNORECASE)
            if m:
                return m.group(1)
        return super().get_hostname()


def load(path: Path) -> AristaEOSConfig:
    return AristaEOSConfig(path=path, text=path.read_text(encoding="utf-8", errors="replace"))
