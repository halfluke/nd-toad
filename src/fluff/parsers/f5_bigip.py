"""F5 BIG-IP adapter.

BIG-IP configuration is exported as TMSH (Traffic Management Shell) commands
or as a flat UCS/SCF archive.  The primary format for compliance auditing is
the SCF (Single Configuration File) or the output of ``tmsh list`` / ``tmsh show``.

TMSH syntax key features:
- Object blocks use C-style braces: ``ltm virtual <name> { ... }``
- Nested objects are indented with 4 spaces
- Strings are quoted with double-quotes or left bare
- Booleans are ``enabled`` / ``disabled``
- IP addresses appear inline: ``destination 10.0.0.1:443``
"""

from __future__ import annotations

import re
from pathlib import Path

from fluff.parsers.base import TextBasedConfig


class F5BigIPConfig(TextBasedConfig):
    def __init__(self, path: Path, text: str) -> None:
        super().__init__(vendor="f5", profile="f5_bigip", path=path, text=text)

    def get_hostname(self) -> str | None:
        # TMSH: sys global-settings { hostname <name> }
        m = re.search(r"hostname\s+(\S+)", self.text, re.IGNORECASE)
        if m and "." in m.group(1):  # prefer FQDN-like hostnames
            return m.group(1)
        if m:
            return m.group(1)
        return None


def load(path: Path) -> F5BigIPConfig:
    return F5BigIPConfig(path=path, text=path.read_text(encoding="utf-8", errors="replace"))
