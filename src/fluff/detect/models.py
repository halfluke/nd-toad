"""Vendor/profile detection models."""

from __future__ import annotations

from dataclasses import dataclass, field

# Canonical ordered list of all 14 supported profiles
PROFILES: list[str] = [
    "cisco_ios",
    "cisco_asa",
    "cisco_nxos",
    "cisco_ftd",
    "arista_eos",
    "hpe_aruba",
    "fortios",
    "junos",
    "palo_alto",
    "checkpoint",
    "sophos_xg",
    "sonicwall",
    "nokia_sros",
    "nokia_srl",
]

PROFILE_VENDOR: dict[str, str] = {
    "cisco_ios": "cisco",
    "cisco_asa": "cisco",
    "cisco_nxos": "cisco",
    "cisco_ftd": "cisco",
    "arista_eos": "arista",
    "hpe_aruba": "hpe",
    "fortios": "fortinet",
    "junos": "juniper",
    "palo_alto": "palo_alto",
    "checkpoint": "checkpoint",
    "sophos_xg": "sophos",
    "sonicwall": "sonicwall",
    "nokia_sros": "nokia",
    "nokia_srl": "nokia",
}


@dataclass
class DetectionResult:
    profile: str
    vendor: str
    confidence: float          # 0.0–1.0
    signals: list[str] = field(default_factory=list)  # human-readable matched fingerprints
