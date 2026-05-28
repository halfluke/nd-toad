"""Cisco NX-OS adapter (Family A)."""

from __future__ import annotations

from pathlib import Path

from fluff.parsers.cisco_like import CiscoLikeConfig


class CiscoNXOSConfig(CiscoLikeConfig):
    _SYNTAX = "nxos"

    def __init__(self, path: Path, text: str) -> None:
        super().__init__(vendor="cisco", profile="cisco_nxos", path=path, text=text)


def load(path: Path) -> CiscoNXOSConfig:
    return CiscoNXOSConfig(path=path, text=path.read_text(encoding="utf-8", errors="replace"))
