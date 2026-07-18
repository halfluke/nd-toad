"""Helpers for loading and looking up check definitions (used by explain CLI)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from fluff.detect.models import PROFILES

CHECKS_DIR = Path(__file__).parent / "checks"


def load_vendor_checks(profile: str) -> list[dict[str, Any]]:
    path = CHECKS_DIR / "vendors" / f"{profile}.yaml"
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data.get("checks", [])


def find_checks(
    check_id: str,
    *,
    vendor: str | None = None,
) -> list[tuple[str, dict[str, Any]]]:
    """
    Find checks by profile-specific id or generic_id.

    Returns a list of ``(profile, check_dict)`` matches.
    """
    profiles = [vendor] if vendor else list(PROFILES)
    matches: list[tuple[str, dict[str, Any]]] = []
    needle = check_id.strip()

    for profile in profiles:
        if profile not in PROFILES:
            continue
        for check in load_vendor_checks(profile):
            if check.get("id") == needle or check.get("generic_id") == needle:
                matches.append((profile, check))
    return matches


def probe_summary(probe: dict[str, Any] | None) -> str:
    """Human-readable one-line summary of a probe definition."""
    if not probe:
        return "manual (no probe)"
    ptype = probe.get("type", "manual")
    if ptype in ("forbidden_regex", "required_regex"):
        pattern = probe.get("pattern", "")
        scope = probe.get("scope")
        base = f"{ptype}: {pattern}"
        return f"{base} (scope: {scope})" if scope else base
    if ptype == "hook":
        module = probe.get("module") or probe.get("name") or "?"
        func = probe.get("func")
        return f"hook: {module}.{func}" if func else f"hook: {module}"
    if ptype == "manual_fp_risk":
        reason = probe.get("reason", "")
        return f"manual_fp_risk: {reason}" if reason else "manual_fp_risk"
    if ptype == "not_applicable":
        return "not_applicable"
    return str(ptype)
