"""
Python hook: detect management-plane ACL / access-class configuration.

Checks whether management access is restricted by a source-IP filter.
Called from vendor YAML files via:

  probe:
    type: hook
    module: fluff.hooks.mgmt_acl
    func: check_<profile>
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from fluff.engine.models import Status
from fluff.engine.probe import ProbeResult

if TYPE_CHECKING:
    from fluff.parsers.base import ParsedConfig


def _pass(evidence: list[str]) -> ProbeResult:
    return ProbeResult(status=Status.PASS, evidence=evidence)


def _fail(reason: str) -> ProbeResult:
    return ProbeResult(status=Status.FAIL, evidence=[reason])


# ------------------------------------------------------------------ IOS family

def check_cisco_ios(config: "ParsedConfig") -> ProbeResult:
    """
    Verify that all VTY lines have an 'access-class … in' restriction.
    Also confirms the referenced ACL actually exists in the config.
    """
    vty_blocks = config.find_blocks(r"^line vty")
    if not vty_blocks:
        return _fail("No 'line vty' blocks found in config.")

    acl_names: list[str] = []
    for block in vty_blocks:
        block_text = "\n".join(block.all_text_lines())
        m = re.search(r"access-class\s+(\S+)\s+in", block_text, re.IGNORECASE)
        if not m:
            header = block.header.text.strip()
            return _fail(f"No 'access-class … in' on '{header}'")
        acl_names.append(m.group(1))

    # Verify referenced ACL(s) exist
    missing = []
    for acl_name in set(acl_names):
        if not re.search(
            rf"(?m)^\s*(ip\s+access-list|access-list)\s+\S+\s+{re.escape(acl_name)}|"
            rf"^\s*ip\s+access-list\s+(standard|extended)\s+{re.escape(acl_name)}",
            config.text,
            re.IGNORECASE,
        ):
            if not re.search(
                rf"(?m)^\s*access-list\s+{re.escape(acl_name)}\s+",
                config.text,
                re.IGNORECASE,
            ):
                missing.append(acl_name)

    if missing:
        return _fail(f"ACL(s) referenced in access-class but not defined: {', '.join(missing)}")

    return _pass([f"VTY access-class: {', '.join(set(acl_names))}"])


def check_cisco_nxos(config: "ParsedConfig") -> ProbeResult:
    return check_cisco_ios(config)


def check_arista_eos(config: "ParsedConfig") -> ProbeResult:
    """EOS uses 'management ssh' block with 'ip access-group'."""
    m = re.search(r"(?m)^\s*ip access-group\s+(\S+)\s+in", config.text, re.IGNORECASE)
    if m:
        return _pass([f"Management access-group: {m.group(1)}"])
    return _fail("No 'ip access-group … in' found under management configuration.")


def check_ios_http_access_class(config: "ParsedConfig") -> ProbeResult:
    """
    Require 'ip http access-class' only when HTTP/HTTPS management IS running.
    If neither 'ip http server' nor 'ip http secure-server' is configured, the
    check is N/A — flagging the missing access-class would be a false positive
    on router/switch configs where HTTP management is fully disabled.
    """
    has_server = re.search(
        r"(?m)^\s*ip\s+http\s+(server|secure-server)\b", config.text, re.IGNORECASE
    )
    if not has_server:
        return _pass(["HTTP/HTTPS management not configured — access-class not required"])

    m = re.search(r"(?m)^\s*ip\s+http\s+access-class\s+(\S+)", config.text, re.IGNORECASE)
    if m:
        return _pass([f"HTTP management restricted via access-class: {m.group(1)}"])
    return _fail(
        "HTTP/HTTPS management is running ('ip http server' or 'ip http secure-server' found) "
        "but no 'ip http access-class' restriction is configured."
    )


def check_junos(config: "ParsedConfig") -> ProbeResult:
    """JunOS RE filter is the management-plane protection mechanism."""
    m = re.search(r"(?m)^\s*set\s+interfaces\s+lo0\s+unit\s+0\s+family\s+inet\s+filter\s+input\s+(\S+)", config.text)
    if m:
        return _pass([f"RE protection filter on lo0: {m.group(1)}"])
    return _fail("No loopback (lo0) input filter found — Routing Engine is unprotected.")
