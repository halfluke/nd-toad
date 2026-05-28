"""
Cisco FTD dual-format adapter (Family A + E).

FTD configs arrive in two shapes:
  - ASA-shaped CLI  → delegate to cisco_asa adapter (most FDM-managed devices)
  - FMC JSON export → parse as JSON policy objects

Detection happens at load() time based on file content.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from fluff.parsers.base import ConfigLine, ConfigBlock, TextBasedConfig
from fluff.parsers.cisco_asa import CiscoASAConfig


class FTDASAConfig(CiscoASAConfig):
    """FTD device managed via FDM (ASA-shaped config)."""

    def __init__(self, path: Path, text: str) -> None:
        super().__init__(path=path, text=text)
        # Override profile so checks/vendors/cisco_ftd.yaml is loaded
        self.profile = "cisco_ftd"


class FTDFMCConfig(TextBasedConfig):
    """FTD device managed via FMC — JSON policy export."""

    def __init__(self, path: Path, text: str, data: dict) -> None:
        super().__init__(vendor="cisco", profile="cisco_ftd", path=path, text=text)
        self._data = data

    def get_hostname(self) -> str | None:
        # FMC JSON has device name at top level
        return self._data.get("name") or self._data.get("deviceName")


def load(path: Path) -> FTDASAConfig | FTDFMCConfig:
    text = path.read_text(encoding="utf-8", errors="replace")

    # Check for FMC JSON format
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return FTDFMCConfig(path=path, text=text, data=data)
        except json.JSONDecodeError:
            pass

    # Treat as ASA-shaped CLI
    return FTDASAConfig(path=path, text=text)
