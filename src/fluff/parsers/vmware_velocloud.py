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
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from fluff.parsers.base import TextBasedConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def _to_flat_text(record: dict) -> str:
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

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# ParsedConfig adapter
# ---------------------------------------------------------------------------

class VeloCloudConfig(TextBasedConfig):
    """ParsedConfig adapter for a VeloCloud combined edge JSON file."""

    def __init__(self, path: Path, record: dict) -> None:
        flat_text = _to_flat_text(record)
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
