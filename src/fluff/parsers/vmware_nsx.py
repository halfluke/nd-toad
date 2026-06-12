"""VMware NSX 4.x adapter.

Input: an NSX bundle JSON produced by ``tools/nsx_collector.py``.

The bundle contains responses from key NSX REST API endpoints::

    {
      "_nd_toad_profile":     "vmware_nsx",
      "_nsx_manager_host":    "nsx.example.com",
      "_collected_at":        "2025-01-01T00:00:00+00:00",
      "ssh_service":          {...},   # GET /api/v1/node/services/ssh
      "ntp_service":          {...},   # GET /api/v1/node/ntp-service
      "cluster":              {...},   # GET /api/v1/cluster
      "auth_policy":          {...},   # GET /api/v1/authentication-policy
      "snmp_service":         {...},   # GET /api/v1/node/services/snmp
      "node_version":         {...},   # GET /api/v1/node/version
      "global_config":        {...},   # GET /api/v1/configs/central-config
      "syslog":               {...},   # GET /api/v1/node/services/syslog
      "users":                {...},   # GET /api/v1/aaa/users
      "certificates":         {...},   # GET /api/v1/trust-management/certificates
      "http_service":         {...}    # GET /api/v1/node/services/http
    }

All sections are flattened to dot-notation text for regex matching::

    _nd_toad_profile = vmware_nsx
    _nsx_manager_host = nsx.example.com
    ssh_service.service_properties.start_on_boot = False
    ssh_service.service_properties.running = False
    ntp_service.server.0.server = pool.ntp.org
    cluster.cluster_id = abc123
    cluster.cluster_nodes.0.fqdn = nsx01.example.com
    auth_policy.api_failed_auth_lockout_period = 900
    auth_policy.api_max_auth_failures = 3
    auth_policy.minimum_password_length = 15
    auth_policy.cli_failed_auth_lockout_period = 900
    auth_policy.cli_max_auth_failures = 3
    global_config.fips_enabled = True
    global_config.tls_cert_cipher_suites = ...
    snmp_service.service_properties.running = False
    node_version.product_version = 4.2.1.0
    syslog.service_properties.running = True
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fluff.parsers.base import TextBasedConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def _to_flat_text(bundle: dict) -> str:
    """Convert an NSX bundle dict to flat dot-notation text."""
    lines: list[str] = []

    # Always emit the marker and metadata first (used by fingerprinting)
    for key in ("_nd_toad_profile", "_nsx_manager_host", "_collected_at"):
        val = bundle.get(key)
        if val is not None:
            lines.append(f"{key} = {val}")

    # All other sections (API endpoint snapshots)
    for key, val in bundle.items():
        if key.startswith("_"):
            continue
        lines.extend(_flatten(val, key))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# ParsedConfig adapter
# ---------------------------------------------------------------------------

class VmwareNSXConfig(TextBasedConfig):
    """ParsedConfig adapter for a VMware NSX bundle JSON file."""

    def __init__(self, path: Path, bundle: dict) -> None:
        flat_text = _to_flat_text(bundle)
        super().__init__(
            vendor="vmware",
            profile="vmware_nsx",
            path=path,
            text=flat_text,
        )
        self._bundle = bundle

    def get_hostname(self) -> str | None:
        # Try product FQDN from cluster nodes, then fall back to manager host
        cluster = self._bundle.get("cluster") or {}
        nodes = cluster.get("cluster_nodes") or []
        if nodes and isinstance(nodes[0], dict):
            fqdn = nodes[0].get("fqdn")
            if fqdn:
                return fqdn
        return self._bundle.get("_nsx_manager_host")


def load(path: Path) -> VmwareNSXConfig:
    """Load an NSX bundle JSON file and return a VmwareNSXConfig."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        bundle = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"NSX parser: {path} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(bundle, dict):
        raise ValueError(
            f"NSX parser: expected a JSON object at the top level, "
            f"got {type(bundle).__name__}"
        )
    return VmwareNSXConfig(path=path, bundle=bundle)
