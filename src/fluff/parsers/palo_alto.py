"""
Palo Alto Networks PAN-OS adapter (Family D — XML config export).

Input: full device XML export (``scp`` from firewall or Panorama push).
XPath references use the PAN-OS 11.x config schema.
"""

from __future__ import annotations

import re
from pathlib import Path

from fluff.parsers.base import TextBasedConfig
from fluff.parsers.xml_utils import parse_xml, xpath, text_of


class PaloAltoConfig(TextBasedConfig):
    def __init__(self, path: Path, text: str) -> None:
        super().__init__(vendor="palo_alto", profile="palo_alto", path=path, text=text)
        self._root = None
        self._parse_error: str | None = None

    def _get_root(self):
        if self._root is None and self._parse_error is None:
            try:
                self._root = parse_xml(self.text)
            except Exception as exc:
                self._parse_error = str(exc)
        return self._root

    def get_hostname(self) -> str | None:
        root = self._get_root()
        if root is not None:
            nodes = xpath(root, ".//deviceconfig/system/hostname")
            if nodes:
                return text_of(nodes[0])
        # Fallback: regex on raw text
        m = re.search(r"<hostname>([^<]+)</hostname>", self.text)
        return m.group(1).strip() if m else None


def load(path: Path) -> PaloAltoConfig:
    return PaloAltoConfig(path=path, text=path.read_text(encoding="utf-8", errors="replace"))
