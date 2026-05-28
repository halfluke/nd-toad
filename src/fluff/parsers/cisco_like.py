"""
Shared Family-A adapter backed by ciscoconfparse2.

Vendor-specific subclasses (cisco_ios, cisco_asa, …) override only what they
need; the base provides full ParsedConfig semantics.
"""

from __future__ import annotations

import re
from pathlib import Path

from fluff.parsers.base import ConfigBlock, ConfigLine, TextBasedConfig


class CiscoLikeConfig(TextBasedConfig):
    """
    ParsedConfig implementation for IOS-family devices using ciscoconfparse2.

    ciscoconfparse2 is used for the structured ``find_blocks`` override;
    ``find_lines`` and all YAML probe regex scanning work on raw text.
    """

    _SYNTAX = "ios"  # override in subclasses (asa, nxos, …)

    def __init__(self, *, vendor: str, profile: str, path: Path, text: str) -> None:
        super().__init__(vendor=vendor, profile=profile, path=path, text=text)
        self._ccp = None  # lazy-load

    def _get_ccp(self):
        if self._ccp is None:
            try:
                from ciscoconfparse2 import CiscoConfParse
                self._ccp = CiscoConfParse(
                    self.text.splitlines(),
                    syntax=self._SYNTAX,
                )
            except Exception:
                self._ccp = False  # sentinel: library unavailable/broken
        return self._ccp if self._ccp is not False else None

    def find_blocks(self, parent_pattern: str) -> list[ConfigBlock]:
        """
        Use ciscoconfparse2 when available for accurate parent/child parsing,
        falling back to the indent-based implementation in TextBasedConfig.
        """
        ccp = self._get_ccp()
        if ccp is None:
            return super().find_blocks(parent_pattern)

        try:
            parent_objs = ccp.find_objects(parent_pattern)
        except Exception:
            return super().find_blocks(parent_pattern)

        blocks: list[ConfigBlock] = []
        for obj in parent_objs:
            header = ConfigLine(text=obj.text, linenum=obj.linenum)
            children: list[ConfigLine | ConfigBlock] = []
            for child in obj.all_children:
                children.append(ConfigLine(text=child.text, linenum=child.linenum))
            blocks.append(ConfigBlock(header=header, children=children))
        return blocks

    def get_hostname(self) -> str | None:
        ccp = self._get_ccp()
        if ccp:
            try:
                objs = ccp.find_objects(r"^hostname ")
                if objs:
                    m = re.match(r"^hostname\s+(\S+)", objs[0].text)
                    if m:
                        return m.group(1)
            except Exception:
                pass
        return super().get_hostname()
