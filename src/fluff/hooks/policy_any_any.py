"""
Python hook: detect any-to-any permit rules across parser families.

Used when a simple regex cannot reliably distinguish true any-any rules
from partial matches.  Called from vendor YAML files via:

  probe:
    type: hook
    module: fluff.hooks.policy_any_any
    func: check_<profile>
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from fluff.engine.models import Status
from fluff.engine.probe import ProbeResult

if TYPE_CHECKING:
    from fluff.parsers.base import ParsedConfig


def _fail(evidence: list[str]) -> ProbeResult:
    return ProbeResult(status=Status.FAIL, evidence=evidence)


def _pass() -> ProbeResult:
    return ProbeResult(status=Status.PASS, evidence=[])


# ------------------------------------------------------------------ IOS family

def check_cisco_ios(config: "ParsedConfig") -> ProbeResult:
    """Detect 'permit ip any any' style ACL entries in IOS config."""
    pattern = re.compile(r"^\s*permit\s+ip\s+any\s+any", re.IGNORECASE | re.MULTILINE)
    matches = [m.group(0).strip() for m in pattern.finditer(config.text)]
    return _fail(matches) if matches else _pass()


def check_cisco_asa(config: "ParsedConfig") -> ProbeResult:
    """Detect any-any permit in ASA extended ACLs."""
    pattern = re.compile(
        r"^\s*permit\s+(ip|tcp|udp|icmp)\s+any\s+any",
        re.IGNORECASE | re.MULTILINE,
    )
    matches = [m.group(0).strip() for m in pattern.finditer(config.text)]
    return _fail(matches) if matches else _pass()


def check_cisco_nxos(config: "ParsedConfig") -> ProbeResult:
    return check_cisco_ios(config)


def check_arista_eos(config: "ParsedConfig") -> ProbeResult:
    return check_cisco_ios(config)


def check_hpe_aruba(config: "ParsedConfig") -> ProbeResult:
    pattern = re.compile(
        r"^\s*permit\s+(ip|tcp|udp|any)\s+any\s+any",
        re.IGNORECASE | re.MULTILINE,
    )
    matches = [m.group(0).strip() for m in pattern.finditer(config.text)]
    return _fail(matches) if matches else _pass()


# ------------------------------------------------------------------ FortiOS

def check_fortios(config: "ParsedConfig") -> ProbeResult:
    """
    Detect FortiOS policies where both srcaddr and dstaddr are 'all'.
    These map to permit any-any semantics.
    """
    evidence: list[str] = []
    # Look for policy blocks where both srcaddr and dstaddr are "all"
    policy_blocks = config.find_blocks(r"^\s+edit\s+\d+")
    for block in policy_blocks:
        lines = block.all_text_lines()
        block_text = "\n".join(lines)
        if re.search(r'set srcaddr "all"', block_text) and re.search(r'set dstaddr "all"', block_text):
            action_m = re.search(r'set action (\S+)', block_text)
            action = action_m.group(1) if action_m else "unknown"
            if action in ("accept", "unknown"):
                edit_m = re.search(r"edit\s+(\d+)", block_text)
                policy_id = edit_m.group(1) if edit_m else "?"
                evidence.append(f"Policy {policy_id}: srcaddr=all dstaddr=all action={action}")
    return _fail(evidence) if evidence else _pass()


# ------------------------------------------------------------------ Junos

def check_junos(config: "ParsedConfig") -> ProbeResult:
    """Detect JunOS firewall filter terms with bare 'then accept' (no match conditions)."""
    evidence: list[str] = []
    # In set format, a bare 'then accept' without preceding match is suspect
    # We flag terms that have only a 'then accept' and no from clause
    term_pattern = re.compile(
        r"^set\s+firewall\s+family\s+\S+\s+filter\s+(\S+)\s+term\s+(\S+)\s+then\s+accept",
        re.IGNORECASE | re.MULTILINE,
    )
    from_pattern = re.compile(
        r"^set\s+firewall\s+family\s+\S+\s+filter\s+\S+\s+term\s+\S+\s+from\s+",
        re.IGNORECASE | re.MULTILINE,
    )
    accept_terms = {(m.group(1), m.group(2)) for m in term_pattern.finditer(config.text)}
    # Terms that have 'from' conditions are fine
    from_terms: set[tuple[str, str]] = set()
    for m in from_pattern.finditer(config.text):
        # Extract filter name and term name from full set line
        full = m.group(0)
        parts = full.split()
        try:
            filter_idx = parts.index("filter") + 1
            term_idx = parts.index("term") + 1
            from_terms.add((parts[filter_idx], parts[term_idx]))
        except (ValueError, IndexError):
            pass
    bare = accept_terms - from_terms
    for filter_name, term_name in sorted(bare):
        evidence.append(f"filter {filter_name} term {term_name}: then accept (no from conditions)")
    return _fail(evidence) if evidence else _pass()


# ------------------------------------------------------------------ Palo Alto

def check_palo_alto(config: "ParsedConfig") -> ProbeResult:
    """Detect PAN-OS rules where source=any AND destination=any."""
    evidence: list[str] = []
    # Match rule blocks in XML text
    rule_pattern = re.compile(
        r'<entry name="([^"]+)">(.*?)</entry>',
        re.DOTALL | re.IGNORECASE,
    )
    for m in rule_pattern.finditer(config.text):
        rule_name = m.group(1)
        rule_body = m.group(2)
        src_any = bool(re.search(r"<source>.*?<member>any</member>.*?</source>", rule_body, re.DOTALL))
        dst_any = bool(re.search(r"<destination>.*?<member>any</member>.*?</destination>", rule_body, re.DOTALL))
        action_allow = bool(re.search(r"<action>allow</action>", rule_body))
        if src_any and dst_any and action_allow:
            evidence.append(f"Rule '{rule_name}': source=any destination=any action=allow")
    return _fail(evidence) if evidence else _pass()
