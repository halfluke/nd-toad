"""Cisco IOS-XE adapter.

IOS-XE is the dominant OS on Cat 9K, ISR 4K, ASR 1K, and modern enterprise
edge/core routers.  The configuration syntax is nearly identical to classic
IOS; this adapter subclasses CiscoIOSConfig and overrides only the profile
name so that the separate cisco_xe.yaml check file is loaded.
"""

from __future__ import annotations

from pathlib import Path

from fluff.parsers.cisco_like import CiscoLikeConfig


class CiscoXEConfig(CiscoLikeConfig):
    _SYNTAX = "ios"

    def __init__(self, path: Path, text: str) -> None:
        super().__init__(vendor="cisco", profile="cisco_xe", path=path, text=text)


def load(path: Path) -> CiscoXEConfig:
    return CiscoXEConfig(path=path, text=path.read_text(encoding="utf-8", errors="replace"))
