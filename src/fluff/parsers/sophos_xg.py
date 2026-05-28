"""
Sophos XG / XGS SFOS adapter (Family D — XML configuration export).

Supported input formats
-----------------------
1. **Entities.xml** (most common offline format)
   Extracted from the unencrypted .tar produced by:
   System → Backup & firmware → Import export
   Root element: ``<Configuration APIVersion="NNNN.N" IPS_CAT_VER="N">``
   Individual objects are direct children: ``<AdminSettings>``, ``<FirewallRule>``, etc.

2. **Legacy / alternate XML roots** seen in community posts and older firmware:
   ``<XGFirewallConf>`` or ``<XGConfiguration>`` (not produced by current firmware)

3. **API GET response** (less common for offline analysis):
   ``<Response>`` root with nested entity data.

Note on the *encrypted* Backup:
   System → Backup & firmware → Backup produces an AES-256 encrypted archive.
   That format is NOT parseable offline; only Import-Export yields plain XML.

XML tag names are confirmed from the official Sophos open-source repositories:
  - sophos/sophos-firewall-sdk (Apache 2.0)
  - sophos/sophosfirewall-ansible (GPL-3.0)
"""

from __future__ import annotations

import re
from pathlib import Path

from fluff.parsers.base import TextBasedConfig
from fluff.parsers.xml_utils import parse_xml, xpath, text_of


class SophosXGConfig(TextBasedConfig):
    def __init__(self, path: Path, text: str) -> None:
        super().__init__(vendor="sophos", profile="sophos_xg", path=path, text=text)
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
            # Entities.xml: <AdminSettings><HostnameSettings><HostName>
            for xpath_expr in (
                ".//AdminSettings/HostnameSettings/HostName",
                ".//HostnameSettings/HostName",
                # Legacy roots
                ".//Administration/HostName",
                ".//DeviceName",
            ):
                nodes = xpath(root, xpath_expr)
                if nodes:
                    return text_of(nodes[0])
        # Regex fallback for any format
        for pattern in (
            r"<HostName>([^<]+)</HostName>",
            r"<DeviceName>([^<]+)</DeviceName>",
            r"<HostNameDesc>([^<]+)</HostNameDesc>",
        ):
            m = re.search(pattern, self.text, re.IGNORECASE)
            if m:
                return m.group(1).strip()
        return None


def load(path: Path) -> SophosXGConfig:
    return SophosXGConfig(path=path, text=path.read_text(encoding="utf-8", errors="replace"))
