#!/usr/bin/env python3
"""
nsx_collector.py — VMware NSX 4.x configuration bundle collector for nd-toad
═══════════════════════════════════════════════════════════════════════════════
Connects to an NSX Manager via its REST API and exports key configuration
endpoints into a single JSON bundle file suitable for audit by nd-toad.

Architecture:
  NSX REST API (JSON over HTTPS) → per-endpoint snapshots → nsx_bundle.json

Endpoints collected:
  /api/v1/node/services/ssh        — SSH service state
  /api/v1/node/ntp-service         — NTP configuration
  /api/v1/cluster                  — Cluster node count and state
  /api/v1/authentication-policy    — Login lockout, session timeout, password policy
  /api/v1/node/services/snmp       — SNMP service state
  /api/v1/node/version             — Manager software version
  /api/v1/configs/central-config   — TLS, FIPS, and global settings
  /api/v1/node/services/syslog     — Syslog service configuration
  /api/v1/aaa/users                — Local user accounts
  /api/v1/trust-management/certificates — Installed certificates
  /api/v1/node/services/http       — HTTPD/API service settings

Required environment variables:
  NSX_HOSTNAME     Hostname or IP of the NSX Manager (e.g. nsx.example.com)
  NSX_USERNAME     Local administrator username (default: admin)
  NSX_PASSWORD     Administrator password

Optional:
  NSX_VERIFY_TLS   true/false  (default: false — self-signed certs common)
  NSX_OUTPUT       Output JSON file path (default: nsx_bundle.json)
  NSX_TIMEOUT      HTTP timeout in seconds (default: 30)

Usage:
  export NSX_HOSTNAME=nsx.example.com
  export NSX_USERNAME=admin
  export NSX_PASSWORD='YOUR_PASSWORD_HERE'
  python3 tools/nsx_collector.py

  # Then audit:
  nd-toad audit --vendor vmware_nsx nsx_bundle.json
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3

# ─────────────────────────────────────────────────────────────────────────────
# Configuration — read from environment
# ─────────────────────────────────────────────────────────────────────────────
NSX_HOSTNAME  = os.getenv("NSX_HOSTNAME", "").strip()
NSX_USERNAME  = os.getenv("NSX_USERNAME", "admin").strip()
NSX_PASSWORD  = os.getenv("NSX_PASSWORD", "").strip()
VERIFY_TLS    = os.getenv("NSX_VERIFY_TLS", "false").strip().lower() in {"1", "true", "yes", "on"}
OUTPUT_PATH   = os.getenv("NSX_OUTPUT", "nsx_bundle.json").strip()
TIMEOUT       = int(os.getenv("NSX_TIMEOUT", "30"))

# Suppress insecure-request warnings when TLS verification is disabled
if not VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
# API endpoints to collect
# ─────────────────────────────────────────────────────────────────────────────
ENDPOINTS: dict[str, str] = {
    "ssh_service":    "/api/v1/node/services/ssh",
    "ntp_service":    "/api/v1/node/ntp-service",
    "cluster":        "/api/v1/cluster",
    "auth_policy":    "/api/v1/authentication-policy",
    "snmp_service":   "/api/v1/node/services/snmp",
    "node_version":   "/api/v1/node/version",
    "global_config":  "/api/v1/configs/central-config",
    "syslog":         "/api/v1/node/services/syslog",
    "users":          "/api/v1/aaa/users",
    "certificates":   "/api/v1/trust-management/certificates",
    "http_service":   "/api/v1/node/services/http",
}


def _session(username: str, password: str) -> requests.Session:
    s = requests.Session()
    s.auth = (username, password)
    s.headers.update({
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    s.verify = VERIFY_TLS
    return s


def _get(session: requests.Session, base_url: str, path: str) -> dict | None:
    url = f"{base_url}{path}"
    try:
        resp = session.get(url, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        print(f"  [WARN] {path} → HTTP {status}: {exc}", file=sys.stderr)
        return {"_error": f"HTTP {status}", "_path": path}
    except requests.exceptions.RequestException as exc:
        print(f"  [WARN] {path} → {exc}", file=sys.stderr)
        return {"_error": str(exc), "_path": path}


def collect(hostname: str, username: str, password: str) -> dict:
    """Collect all endpoint snapshots and return the bundle dict."""
    base_url = f"https://{hostname}"
    session  = _session(username, password)

    bundle: dict = {
        "_nd_toad_profile":     "vmware_nsx",
        "_nsx_manager_host":    hostname,
        "_collected_at":        datetime.now(timezone.utc).isoformat(),
    }

    for key, path in ENDPOINTS.items():
        print(f"  Collecting {path} ...", flush=True)
        data = _get(session, base_url, path)
        bundle[key] = data

    return bundle


def main() -> None:
    if not NSX_HOSTNAME:
        print("ERROR: NSX_HOSTNAME is not set.", file=sys.stderr)
        sys.exit(1)
    if not NSX_PASSWORD:
        print("ERROR: NSX_PASSWORD is not set.", file=sys.stderr)
        sys.exit(1)

    print(f"[nsx_collector] Connecting to https://{NSX_HOSTNAME} ...", flush=True)
    bundle = collect(NSX_HOSTNAME, NSX_USERNAME, NSX_PASSWORD)

    out_path = Path(OUTPUT_PATH)
    out_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(f"\n[nsx_collector] Bundle saved → {out_path.resolve()}")
    print(f"  Endpoints collected: {len(ENDPOINTS)}")
    print(f"\nNext step:")
    print(f"  nd-toad audit --vendor vmware_nsx {out_path}")


if __name__ == "__main__":
    main()
