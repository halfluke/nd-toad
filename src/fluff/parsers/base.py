"""ParsedConfig protocol and shared data structures for all vendor adapters."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable


@dataclass
class ConfigLine:
    text: str
    linenum: int


@dataclass
class ConfigBlock:
    """A parent line plus all its indented children."""

    header: ConfigLine
    children: list[ConfigLine | "ConfigBlock"]

    def all_text_lines(self) -> list[str]:
        """Flatten all text lines within this block."""
        lines = [self.header.text]
        for child in self.children:
            if isinstance(child, ConfigBlock):
                lines.extend(child.all_text_lines())
            else:
                lines.append(child.text)
        return lines


@runtime_checkable
class ParsedConfig(Protocol):
    """Minimal interface every vendor adapter must satisfy."""

    vendor: str   # e.g. "cisco", "juniper", "fortinet"
    profile: str  # e.g. "cisco_ios", "palo_alto"
    raw_path: Path
    text: str     # full raw config text

    def find_lines(self, pattern: str) -> list[ConfigLine]:
        """Return all lines whose text matches *pattern* (re.IGNORECASE | re.MULTILINE)."""
        ...

    def find_blocks(self, parent_pattern: str) -> list[ConfigBlock]:
        """Return all top-level blocks whose header matches *parent_pattern*."""
        ...

    def get_hostname(self) -> str | None:
        """Best-effort extraction of the device hostname."""
        ...


class TextBasedConfig:
    """
    Lightweight ParsedConfig backed by plain-text regex matching.

    Adequate for most YAML probe types.  Vendor-specific adapters may subclass
    and override find_blocks() using a library parser (ciscoconfparse2, etc.).
    """

    def __init__(self, *, vendor: str, profile: str, path: Path, text: str) -> None:
        self.vendor = vendor
        self.profile = profile
        self.raw_path = path
        self.text = text
        self._lines: list[str] = text.splitlines()

    def find_lines(self, pattern: str) -> list[ConfigLine]:
        rx = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        results: list[ConfigLine] = []
        for i, line in enumerate(self._lines, start=1):
            if rx.search(line):
                results.append(ConfigLine(text=line, linenum=i))
        return results

    def find_blocks(self, parent_pattern: str) -> list[ConfigBlock]:
        """
        Indent-based block extraction.  Works for IOS/EOS/NX-OS/FortiOS/JunOS-set.
        A block starts at a line matching *parent_pattern* and includes all
        immediately following lines with deeper indentation.
        """
        rx = re.compile(parent_pattern, re.IGNORECASE)
        blocks: list[ConfigBlock] = []
        lines = self._lines
        i = 0
        while i < len(lines):
            line = lines[i]
            if rx.search(line):
                header = ConfigLine(text=line, linenum=i + 1)
                children: list[ConfigLine | ConfigBlock] = []
                parent_indent = len(line) - len(line.lstrip())
                j = i + 1
                while j < len(lines):
                    child_line = lines[j]
                    if not child_line.strip():
                        j += 1
                        continue
                    child_indent = len(child_line) - len(child_line.lstrip())
                    if child_indent <= parent_indent:
                        break
                    children.append(ConfigLine(text=child_line, linenum=j + 1))
                    j += 1
                blocks.append(ConfigBlock(header=header, children=children))
                i = j
            else:
                i += 1
        return blocks

    def get_hostname(self) -> str | None:
        for line in self._lines:
            m = re.match(r"^\s*hostname\s+(\S+)", line, re.IGNORECASE)
            if m:
                return m.group(1)
        return None
