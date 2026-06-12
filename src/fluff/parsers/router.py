"""
AdapterRouter: maps a profile string to the correct parser ``load()`` function
and returns a ParsedConfig instance.
"""

from __future__ import annotations

from pathlib import Path

from fluff.parsers.base import ParsedConfig

# Lazy import map — avoids importing every parser at startup
_LOADERS: dict[str, str] = {
    "cisco_ios":   "fluff.parsers.cisco_ios",
    "cisco_asa":   "fluff.parsers.cisco_asa",
    "cisco_nxos":  "fluff.parsers.cisco_nxos",
    "cisco_ftd":   "fluff.parsers.cisco_ftd",
    "cisco_xe":    "fluff.parsers.cisco_xe",
    "cisco_xr":    "fluff.parsers.cisco_xr",
    "arista_eos":  "fluff.parsers.arista_eos",
    "hpe_aruba":   "fluff.parsers.hpe_aruba",
    "fortios":     "fluff.parsers.fortios",
    "junos":       "fluff.parsers.junos",
    "palo_alto":   "fluff.parsers.palo_alto",
    "checkpoint":  "fluff.parsers.checkpoint",
    "sophos_xg":   "fluff.parsers.sophos_xg",
    "sonicwall":   "fluff.parsers.sonicwall",
    "nokia_sros":  "fluff.parsers.nokia_sros",
    "nokia_srl":   "fluff.parsers.nokia_srl",
    "huawei_vrp":      "fluff.parsers.huawei_vrp",
    "f5_bigip":        "fluff.parsers.f5_bigip",
    "vmware_velocloud": "fluff.parsers.vmware_velocloud",
    "vmware_nsx":      "fluff.parsers.vmware_nsx",
}


def load_config(path: Path, profile: str) -> ParsedConfig:
    """
    Load *path* using the adapter for *profile*.

    Raises ValueError for unknown profiles.
    """
    module_name = _LOADERS.get(profile)
    if module_name is None:
        raise ValueError(
            f"Unknown profile {profile!r}. "
            f"Supported profiles: {sorted(_LOADERS)}"
        )
    import importlib
    module = importlib.import_module(module_name)
    return module.load(path)
