"""
Python hook: PAN-OS security policy checks.

Checks that cannot be expressed with simple regex against the raw XML text,
e.g. distinguishing allow rules with any-any from deny/drop any-any catch-alls.

Called from palo_alto.yaml via:

  probe:
    type: hook
    module: fluff.hooks.panos_policy
    func: check_<name>
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


def check_any_any_allow(config: "ParsedConfig") -> ProbeResult:
    """
    Flag security rules that have source=any, destination=any AND action=allow.

    A deny/drop rule with any-any (catch-all deny at the bottom of the rulebase)
    is perfectly acceptable — only allow rules with any-any are a violation.

    Decryption rules with any-any source/destination are also excluded because
    they are not security permit rules.
    """
    text = config.text

    # Find the <security><rules> section — decryption/NAT/QoS rules live elsewhere.
    sec_match = re.search(r"<security>\s*<rules>(.*?)</rules>\s*</security>", text, re.DOTALL)
    if not sec_match:
        return _pass(["No <security><rules> section found — no security rules defined."])

    rules_section = sec_match.group(1)

    # Split into individual rule entries
    entries = re.findall(r"<entry\b[^>]*>.*?</entry>", rules_section, re.DOTALL)
    if not entries:
        return _pass(["Security rules section is empty."])

    violations: list[str] = []
    for entry in entries:
        name_m = re.search(r'<entry\s+name="([^"]+)"', entry)
        name = name_m.group(1) if name_m else "<unnamed>"

        # Check source = any
        src_any = bool(re.search(r"<source>[\s\S]*?<member>any</member>[\s\S]*?</source>", entry))
        # Check destination = any
        dst_any = bool(re.search(r"<destination>[\s\S]*?<member>any</member>[\s\S]*?</destination>", entry))

        if not (src_any and dst_any):
            continue  # Not an any-any rule

        # Determine action — default is "allow" if not explicitly set
        action_m = re.search(r"<action>(\w[\w-]*)</action>", entry)
        action = action_m.group(1).lower() if action_m else "allow"

        if action in ("deny", "drop", "reset-client", "reset-server", "reset-both"):
            continue  # Deny/drop any-any is acceptable (catch-all rule)

        violations.append(f"Rule '{name}' permits any→any (action={action})")

    if violations:
        return _fail("; ".join(violations))

    return _pass(["No security rules with any-any allow found."])
