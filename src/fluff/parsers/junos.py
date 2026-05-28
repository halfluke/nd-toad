"""
Juniper JunOS adapter (Family B).

Primary input: ``show configuration | display set`` (flat set-statement format).
Curly-brace hierarchical format is also handled by TextBasedConfig's indent parser.
"""

from __future__ import annotations

import re
from pathlib import Path

from fluff.parsers.base import TextBasedConfig


class JunOSConfig(TextBasedConfig):
    def __init__(self, path: Path, text: str) -> None:
        super().__init__(vendor="juniper", profile="junos", path=path, text=text)
        # Detect format
        self._is_set_format = bool(re.search(r"(?m)^set ", self.text))

    def get_hostname(self) -> str | None:
        # set format: "set system host-name <name>"
        m = re.search(r"(?m)^set system host-name\s+(\S+)", self.text, re.IGNORECASE)
        if m:
            return m.group(1)
        # curly format: "host-name <name>;" inside system { … }
        m = re.search(r"(?m)^\s+host-name\s+(\S+);", self.text, re.IGNORECASE)
        if m:
            return m.group(1)
        return None


def load(path: Path) -> JunOSConfig:
    return JunOSConfig(path=path, text=path.read_text(encoding="utf-8", errors="replace"))
