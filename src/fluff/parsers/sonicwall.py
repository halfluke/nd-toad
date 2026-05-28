"""
SonicWall SonicOS adapter (Family E).

Accepted formats:
  - Text config export (``prefs`` / ``access-rule`` line blocks, SonicOS 7.x CLI)
  - XML `.exp` backup (parsed as raw text for regex probes)
"""

from __future__ import annotations

import re
from pathlib import Path

from fluff.parsers.base import TextBasedConfig


class SonicWallConfig(TextBasedConfig):
    def __init__(self, path: Path, text: str) -> None:
        super().__init__(vendor="sonicwall", profile="sonicwall", path=path, text=text)

    def get_hostname(self) -> str | None:
        m = re.search(r"(?m)^(prefs |sysinfo )?hostname\s+['\"]?([^'\";\n]+)", self.text, re.IGNORECASE)
        if m:
            return m.group(2).strip()
        m = re.search(r"<DeviceName>([^<]+)</DeviceName>", self.text, re.IGNORECASE)
        return m.group(1).strip() if m else None


def load(path: Path) -> SonicWallConfig:
    return SonicWallConfig(path=path, text=path.read_text(encoding="utf-8", errors="replace"))
