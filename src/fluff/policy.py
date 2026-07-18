"""
Optional policy overlays: exemptions and severity overrides.

Loaded from YAML or JSON::

    exemptions:
      - check_id: IOS-SVC-001
        hostname: lab-r1          # optional; omit to match all hosts
        reason: Accepted risk until Q3
      - generic_id: SVC-005
        reason: Not used in this environment

    severity_overrides:
      IOS-SVC-001: high           # by check_id
      SVC-002: critical           # by generic_id
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from fluff.engine.models import Finding, Severity, Status


@dataclass
class Exemption:
    check_id: str | None = None
    generic_id: str | None = None
    hostname: str | None = None
    reason: str = ""


@dataclass
class Policy:
    exemptions: list[Exemption] = field(default_factory=list)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)


def load_policy(path: Path) -> Policy:
    """Load a policy file (``.yaml`` / ``.yml`` / ``.json``)."""
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix == ".json":
        data = json.loads(text) or {}
    elif suffix in (".yaml", ".yml"):
        data = yaml.safe_load(text) or {}
    else:
        # Try YAML first, then JSON
        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError:
            data = json.loads(text) or {}

    if not isinstance(data, dict):
        raise ValueError(f"Policy file must be a mapping, got {type(data).__name__}")

    return Policy(
        exemptions=_parse_exemptions(data.get("exemptions", [])),
        severity_overrides=_parse_severity_overrides(data.get("severity_overrides", {})),
    )


def apply_policy(findings: list[Finding], hostname: str | None, policy: Policy) -> list[Finding]:
    """Apply severity overrides then exemptions. Returns the same list (mutated)."""
    if not policy.severity_overrides and not policy.exemptions:
        return findings

    for finding in findings:
        override = _severity_for(finding, policy.severity_overrides)
        if override is not None:
            finding.severity = override

        match = _matching_exemption(finding, hostname, policy.exemptions)
        if match is not None and finding.status == Status.FAIL:
            finding.status = Status.EXEMPT
            finding.exemption_reason = match.reason or "Exempted by policy"

    return findings


def _parse_exemptions(raw: Any) -> list[Exemption]:
    if not raw:
        return []
    if not isinstance(raw, list):
        raise ValueError("'exemptions' must be a list")

    out: list[Exemption] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"exemptions[{i}] must be a mapping")
        check_id = item.get("check_id")
        generic_id = item.get("generic_id")
        if not check_id and not generic_id:
            raise ValueError(f"exemptions[{i}] needs check_id or generic_id")
        out.append(
            Exemption(
                check_id=str(check_id) if check_id else None,
                generic_id=str(generic_id) if generic_id else None,
                hostname=str(item["hostname"]) if item.get("hostname") else None,
                reason=str(item.get("reason", "")),
            )
        )
    return out


def _parse_severity_overrides(raw: Any) -> dict[str, Severity]:
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("'severity_overrides' must be a mapping of id → severity")

    valid = {s.value: s for s in Severity}
    out: dict[str, Severity] = {}
    for key, value in raw.items():
        sev = str(value).lower()
        if sev not in valid:
            raise ValueError(
                f"Invalid severity {value!r} for {key!r}; "
                f"expected one of: {', '.join(valid)}"
            )
        out[str(key)] = valid[sev]
    return out


def _severity_for(finding: Finding, overrides: dict[str, Severity]) -> Severity | None:
    if finding.check_id in overrides:
        return overrides[finding.check_id]
    if finding.generic_id in overrides:
        return overrides[finding.generic_id]
    return None


def _matching_exemption(
    finding: Finding,
    hostname: str | None,
    exemptions: list[Exemption],
) -> Exemption | None:
    host = (hostname or "").strip().lower()
    for ex in exemptions:
        if ex.check_id and ex.check_id != finding.check_id:
            continue
        if ex.generic_id and ex.generic_id != finding.generic_id:
            continue
        if not ex.check_id and not ex.generic_id:
            continue
        if ex.hostname is not None and ex.hostname.strip().lower() != host:
            continue
        return ex
    return None
