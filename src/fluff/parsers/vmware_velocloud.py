"""VMware VeloCloud SD-WAN adapter.

Input: a combined JSON file produced by ``tools/velo_collector.py``
       (``combined/<edgeName>_combined.json``).

The combined record has the structure::

    {
      "edgeName":           "EDGE-01",
      "softwareVersion":    "5.4.0.0",
      "modelNumber":        "virtual",
      "activationState":    "ACTIVATED",
      "profileConfig":      {...},   # device-settings at profile level
      "profileFirewall":    {...},   # firewall module at profile level
      "edgeConfig":         {...},   # device-settings overrides at edge level
      "firewallConfig":     {...},   # firewall module at edge level
      "wanConfig":          {...},   # WAN module
      "controlPlaneConfig": {...}
    }

The effective device-settings config is computed by deep-merging
``profileConfig`` with ``edgeConfig`` (edge values take precedence).
That merged result, plus the firewall and WAN modules, are all flattened
to a dot-notation text representation so the existing
``required_regex``/``forbidden_regex`` probe infrastructure works unchanged.

If a ``findings/methodology_coverage.json`` file exists in the sibling
``../findings/`` directory (i.e. the velo_collector.py output tree), the
parser also emits ``vco_check.<KEY>.affected = True/False`` lines for each
check that velo_collector.py assessed authoritatively.  These lines are
used by YAML checks that rely on the collector's deep-JSON analysis
(firewall rule ordering, segment isolation, business policy logic, etc.).

Example flat lines emitted::

    edge.name = EDGE-01
    edge.softwareVersion = 5.4.0.0
    edge.activationState = ACTIVATED
    effective.ntp.enabled = True
    effective.ntp.servers.0.ip = 10.0.0.1
    effective.snmp.snmpv2c.enabled = False
    effective.snmp.snmpv3.enabled = True
    effective.tacacs.serverIp = 10.1.1.1
    effective.bfd.enabled = True
    effective.dns.servers.0 = 8.8.8.8
    effective.routedInterfaces.0.name = GE1
    effective.routedInterfaces.0.encryptOverlay = True
    effective.segments.0.syslog.enabled = True
    firewall.stateful_firewall_enabled = True
    firewall.services.ssh.enabled = False
    firewall.services.console.enabled = False
    firewall.services.usb.disabled = True
    firewall.services.snmp.enabled = False
    firewall.firewall_logging_enabled = True
    firewall.syslog_forwarding = True
    wan.links.0.encryptOverlay = True
    vco_check.FW_DefaultDeny.status = fail
    vco_check.FW_DefaultDeny.affected = True
    vco_check.NET_SegmentIsolation.status = pass
    vco_check.NET_SegmentIsolation.affected = False
    certs.0.serialNumber = abc123
    dsmod.segments.0.name = Global Segment
    qos.segments.0.name = Global Segment
"""

from __future__ import annotations

import json
import logging
from copy import deepcopy
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Mapping: velo_collector.py XLSX title  →  sanitised flat-text key
# Only titles that nd-toad delegates entirely to the collector are included
# (i.e. checks whose automationTier is "automated" in _AUTOMATION_TIER_BY_TITLE
# inside velo_collector.py and whose logic cannot be replicated with a simple
# regex on the combined JSON).
# ---------------------------------------------------------------------------
_VCO_TITLE_TO_KEY: dict[str, str] = {
    # Original 10 automated-but-complex checks
    "[FW] Edge Local Access Restrictions": "FW_EdgeAccess",
    "[FW] Default Deny":                   "FW_DefaultDeny",
    "[FW] Rule Scope":                     "FW_RuleScope",
    "[FW] NAT Exposure":                   "FW_NATExposure",
    "[System] Edge Versions":              "SYS_EdgeVersions",
    "[System] Patch Levels":               "SYS_PatchLevels",
    "[System] Inactive Edge Review":       "SYS_InactiveEdge",
    "[Net] Segment Isolation":             "NET_SegmentIsolation",
    "[Net] Default Segment Behaviour":     "NET_DefaultSegment",
    "[Net] Business Policy Override":      "NET_BusinessPolicy",
    # Newly automated in velo_final (velo_collector.py ≥ this release)
    "[Net] Edge-to-Edge Communication":    "NET_EdgeToEdge",
    "[VPN] Encryption Strength":           "VPN_EncryptionStrength",
    "[VPN] Certificate Validation":        "VPN_CertValidation",
    "[VPN] Key Rotation":                  "VPN_KeyRotation",
    "[Mgmt] Dormant User Account Review":  "MGMT_DormantUsers",
}

from fluff.parsers.base import TextBasedConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_coverage_lines(combined_path: Path, edge_name: str) -> list[str]:
    """Return ``vco_check.*`` flat lines from methodology_coverage.json.

    Looks for ``../findings/methodology_coverage.json`` relative to the
    combined JSON directory (i.e. the sibling ``findings/`` folder that
    velo_collector.py writes alongside ``combined/``).

    For each check mapped in ``_VCO_TITLE_TO_KEY``:
    - ``vco_check.<KEY>.status = <pass|fail|partial>``
    - ``vco_check.<KEY>.affected = True``  if the edge appears in
      ``edgesAffected`` or the status is not ``pass``
    - ``vco_check.<KEY>.affected = False`` if the edge is not affected

    Returns an empty list if the coverage file is not found.
    """
    coverage_path = combined_path.parent.parent / "findings" / "methodology_coverage.json"
    if not coverage_path.exists():
        log.debug("VeloCloud: no methodology_coverage.json found at %s", coverage_path)
        return []

    try:
        entries: list[dict] = json.loads(coverage_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("VeloCloud: could not load %s: %s", coverage_path, exc)
        return []

    lines: list[str] = []
    for entry in entries:
        title = entry.get("title", "")
        key = _VCO_TITLE_TO_KEY.get(title)
        if key is None:
            continue
        status = str(entry.get("status", "unknown")).lower()
        affected_edges: list[str] = entry.get("edgesAffected") or []
        if status == "pass":
            affected = False
        elif status in ("assisted", "not_run"):
            # "assisted" = partial-tier with findings → needs human review (conservative)
            # "not_run"  = events/deep flag not used → unknown, treat conservatively
            affected = True
        elif edge_name and edge_name in affected_edges:
            affected = True
        elif affected_edges:
            # Other edges are affected but not this one → pass for this edge
            affected = False
        else:
            # fail/partial with empty edgesAffected = enterprise-level finding
            # (edgeName was "(enterprise)" so filtered out by the collector).
            # Conservative: flag as affected on every edge.
            affected = status != "pass"
        lines.append(f"vco_check.{key}.status = {status}")
        lines.append(f"vco_check.{key}.affected = {affected}")
    return lines


def _deep_merge(base: dict, override: dict) -> dict:
    """Return a new dict that is *base* updated recursively by *override*."""
    result = deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = deepcopy(v)
    return result


def _flatten(obj: Any, prefix: str = "", out: list[str] | None = None) -> list[str]:
    """Recursively flatten *obj* to ``prefix.key = value`` strings."""
    if out is None:
        out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            child = f"{prefix}.{k}" if prefix else str(k)
            _flatten(v, child, out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _flatten(v, f"{prefix}.{i}", out)
    elif obj is not None:
        out.append(f"{prefix} = {obj}")
    return out


def _to_flat_text(record: dict, coverage_lines: list[str] | None = None) -> str:
    """Convert a combined edge record to flat-text for regex matching."""
    lines: list[str] = []

    # Top-level edge metadata
    for key in ("edgeName", "softwareVersion", "modelNumber", "activationState",
                "edgeLogicalId", "profileName"):
        val = record.get(key)
        if val is not None:
            lines.append(f"edge.{key} = {val}")

    # Effective device-settings (profile merged with edge override)
    profile_cfg = record.get("profileConfig") or {}
    edge_cfg    = record.get("edgeConfig") or {}
    effective   = _deep_merge(profile_cfg, edge_cfg) if profile_cfg else deepcopy(edge_cfg)
    lines.extend(_flatten(effective, "effective"))

    # Firewall module (edge-level takes precedence, else profile-level)
    fw = record.get("firewallConfig") or record.get("profileFirewall") or {}
    lines.extend(_flatten(fw, "firewall"))

    # WAN module
    wan = record.get("wanConfig") or {}
    lines.extend(_flatten(wan, "wan"))

    # Control-plane module
    cp = record.get("controlPlaneConfig") or {}
    lines.extend(_flatten(cp, "controlPlane"))

    # Device-settings portal module (richer than APIv2 deviceSettings)
    dsmod = record.get("deviceSettingsModule") or {}
    if dsmod:
        lines.extend(_flatten(dsmod, "dsmod"))

    # QoS/business-policy module
    qos = record.get("qosConfig") or {}
    if qos:
        lines.extend(_flatten(qos, "qos"))

    # Edge certificates (sanitised; emitted as certs.<n>.field = value)
    certs = record.get("edgeCertificates") or []
    if certs:
        lines.extend(_flatten(certs, "certs"))

    # Authoritative collector results (vco_check.* lines)
    if coverage_lines:
        lines.extend(coverage_lines)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# ParsedConfig adapter
# ---------------------------------------------------------------------------

class VeloCloudConfig(TextBasedConfig):
    """ParsedConfig adapter for a VeloCloud combined edge JSON file."""

    def __init__(self, path: Path, record: dict) -> None:
        edge_name = record.get("edgeName") or ""
        coverage_lines = _load_coverage_lines(path, edge_name)
        flat_text = _to_flat_text(record, coverage_lines)
        super().__init__(
            vendor="vmware",
            profile="vmware_velocloud",
            path=path,
            text=flat_text,
        )
        self._record = record

    def get_hostname(self) -> str | None:
        return self._record.get("edgeName")


def load(path: Path) -> VeloCloudConfig:
    """Load a combined edge JSON file and return a VeloCloudConfig."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        record = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"VeloCloud parser: {path} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(record, dict):
        raise ValueError(
            f"VeloCloud parser: expected a JSON object at the top level, got {type(record).__name__}"
        )
    return VeloCloudConfig(path=path, record=record)
