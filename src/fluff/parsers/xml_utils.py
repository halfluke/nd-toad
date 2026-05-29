"""
Shared XML parsing utilities for Palo Alto and Sophos XG adapters.

Provides a thin wrapper around lxml (preferred) with stdlib ElementTree fallback.
"""

from __future__ import annotations


try:
    from lxml import etree as ET

    _LXML = True
except ImportError:
    import xml.etree.ElementTree as ET  # type: ignore[no-redef]

    _LXML = False


def parse_xml(text: str):
    """Parse XML string and return the root element."""
    if _LXML:
        return ET.fromstring(text.encode("utf-8"))
    return ET.fromstring(text)


def xpath(root, expression: str, namespaces: dict | None = None) -> list:
    """Run XPath on *root*, returning a list of matching elements or text values."""
    if _LXML:
        return root.xpath(expression, namespaces=namespaces or {})
    # stdlib ElementTree has limited XPath — strip namespace predicates
    try:
        return root.findall(expression)
    except Exception:
        return []


def text_of(element) -> str:
    """Return stripped text content of an element, or empty string."""
    if element is None:
        return ""
    t = element.text
    return t.strip() if t else ""


def attr(element, name: str, default: str = "") -> str:
    if element is None:
        return default
    return element.get(name, default)
