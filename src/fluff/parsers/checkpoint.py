"""
Check Point adapter (Family E).

Accepted formats:
  - CLISH / Gaia config export (line-oriented commands: ``add``, ``set``)
  - Object dump text from SmartConsole (legacy ``:name (…)`` syntax)

The two formats are detected at load time and both reduce to the same
TextBasedConfig; regex probes work on raw text in both cases.
"""

from __future__ import annotations

import re
from pathlib import Path

from fluff.parsers.base import TextBasedConfig


class CheckPointConfig(TextBasedConfig):
    def __init__(self, path: Path, text: str) -> None:
        super().__init__(vendor="checkpoint", profile="checkpoint", path=path, text=text)
        # Detect format for informational purposes
        self.is_clish = bool(re.search(r"(?m)^(add|set) (host|network|service|access-rule)", text))
        self.is_object_dump = bool(re.search(r"(?m)^:\S+ \(", text))

    def get_hostname(self) -> str | None:
        m = re.search(r"(?m)^set hostname\s+(\S+)", self.text, re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r"(?m)^:name \(([^)]+)\)", self.text)
        if m:
            return m.group(1).strip()
        return None


def load(path: Path) -> CheckPointConfig:
    return CheckPointConfig(path=path, text=path.read_text(encoding="utf-8", errors="replace"))
