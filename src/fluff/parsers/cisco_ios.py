"""Cisco IOS / IOS-XE adapter (Family A reference implementation)."""

from __future__ import annotations

from pathlib import Path

from fluff.parsers.cisco_like import CiscoLikeConfig


class CiscoIOSConfig(CiscoLikeConfig):
    _SYNTAX = "ios"

    def __init__(self, path: Path, text: str) -> None:
        super().__init__(vendor="cisco", profile="cisco_ios", path=path, text=text)


def load(path: Path) -> CiscoIOSConfig:
    return CiscoIOSConfig(path=path, text=path.read_text(encoding="utf-8", errors="replace"))
