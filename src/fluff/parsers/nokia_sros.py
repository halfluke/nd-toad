"""
Nokia SR OS adapter (Family E).

Supported input formats:
  1. Classic CLI  — ``admin save`` output with ``# TiMOS-…`` header and
     indented ``configure … / exit`` block tree.
  2. MD-CLI flat  — ``/configure system name "R1"`` per-line style, produced
     by ``admin save flat`` or containerlab startup-config files.

TextBasedConfig regex probes work on raw text for both formats.
"""

from __future__ import annotations

import re
from pathlib import Path

from fluff.parsers.base import TextBasedConfig


def _is_mdcli_flat(text: str) -> bool:
    """Return True if the config uses the MD-CLI flat /configure prefix style."""
    return bool(re.search(r"(?m)^/configure system\b", text))


class NokiaSROSConfig(TextBasedConfig):
    def __init__(self, path: Path, text: str) -> None:
        super().__init__(vendor="nokia", profile="nokia_sros", path=path, text=text)
        self.is_mdcli_flat = _is_mdcli_flat(text)

    def get_hostname(self) -> str | None:
        # MD-CLI flat: /configure system name "R1"
        m = re.search(r'(?m)^/configure system name\s+"([^"]+)"', self.text)
        if m:
            return m.group(1)
        # Classic CLI: indented name "R1" inside system block
        m = re.search(r'(?m)^\s+name\s+"([^"]+)"', self.text)
        if m:
            return m.group(1)
        # Fallback: unquoted name
        m = re.search(r"(?m)^\s+name\s+(\S+)", self.text)
        return m.group(1).strip("\"'") if m else None


def load(path: Path) -> NokiaSROSConfig:
    return NokiaSROSConfig(path=path, text=path.read_text(encoding="utf-8", errors="replace"))
