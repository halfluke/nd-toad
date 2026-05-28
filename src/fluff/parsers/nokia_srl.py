"""
Nokia SR Linux adapter (Family E).

Supports two input formats:
- JSON config export via gNMI or ``info flat | as json``
- Flat CLI set format produced by ``info flat`` in CLI mode (``set / ...`` lines)

YAML probes work on the raw text (JSON or flat CLI) via regex.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from fluff.parsers.base import TextBasedConfig


class NokiaSRLConfig(TextBasedConfig):
    def __init__(self, path: Path, text: str, data: dict | list | None) -> None:
        if data is not None:
            # Re-serialize pretty-printed so regex probes work consistently
            pretty = json.dumps(data, indent=2)
        else:
            # Flat CLI set format — use raw text directly
            pretty = text
        super().__init__(vendor="nokia", profile="nokia_srl", path=path, text=pretty)
        self._data = data

    def get_hostname(self) -> str | None:
        # JSON format
        if self._data and isinstance(self._data, dict):
            try:
                return self._data["system"]["name"]["host-name"]
            except (KeyError, TypeError):
                pass
            try:
                return self._data["srl_nokia-system:system"]["srl_nokia-system-name:name"]["host-name"]
            except (KeyError, TypeError):
                pass
            m = re.search(r'"host-name"\s*:\s*"([^"]+)"', self.text)
            return m.group(1) if m else None
        # Flat CLI format: set / system name host-name <name>
        m = re.search(r"(?m)^set / system name host-name\s+(\S+)", self.text)
        if m:
            return m.group(1)
        m = re.search(r"(?m)^set / system information description\s+(.+)$", self.text)
        return m.group(1).strip() if m else None


def _is_flat_cli(text: str) -> bool:
    """Return True if the text looks like SR Linux flat CLI set format."""
    return bool(re.search(r"(?m)^set / (interface|network-instance|system|routing-policy|acl)\b", text))


def load(path: Path) -> NokiaSRLConfig:
    text = path.read_text(encoding="utf-8", errors="replace")
    if _is_flat_cli(text):
        return NokiaSRLConfig(path=path, text=text, data=None)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = {}
    return NokiaSRLConfig(path=path, text=text, data=data)
