"""
Score-based vendor fingerprinting for all 14 supported profiles.

Each profile has a list of (pattern, weight, description) tuples.
The profile with the highest accumulated score wins, provided it exceeds
MIN_CONFIDENCE.  Ties are broken by ordering in PROFILE_SIGNALS.

Call ``detect(text)`` to get a DetectionResult, or ``detect_from_file(path)``
for the common case of reading from a file.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from fluff.detect.models import DetectionResult, PROFILE_VENDOR

# (regex, weight, human label)
_Signal = tuple[str, float, str]

PROFILE_SIGNALS: dict[str, list[_Signal]] = {
    # ------------------------------------------------------------------ Cisco
    "cisco_ios": [
        (r"(?m)^(Current configuration|Building configuration)", 3.0, "IOS config header"),
        (r"(?m)^version \d+\.\d+(?![A-Z]\d)", 2.0, "IOS version line"),
        (r"(?m)^(no )?ip routing", 1.5, "ip routing command"),
        (r"(?m)^(no )?service password-encryption", 1.0, "service password-encryption"),
        (r"(?m)^line (vty|con|aux) ", 2.0, "line vty/con/aux block"),
        # GigabitEthernet/FastEthernet/Serial/Loopback only — 'Vlan' excluded to avoid
        # matching AOS-CX 'interface vlan 10' which also uses lowercase 'vlan' on same line
        (r"(?m)^interface (GigabitEthernet|FastEthernet|Serial|Loopback)\d", 1.5, "IOS interface"),
        (r"(?m)^interface Vlan\d", 1.5, "IOS SVI interface"),
        (r"(?m)^ip ssh version", 1.0, "ip ssh version"),
        (r"(?m)^hostname ", 0.5, "hostname line"),
        (r"(?m)^!RANCID-CONTENT-TYPE: cisco\b", 3.0, "RANCID cisco tag"),
        (r"(?m)^aaa new-model\b", 1.5, "aaa new-model (IOS)"),
        (r"(?m)^aaa (accounting|authentication|authorization) ", 1.0, "IOS aaa command"),
        (r"(?m)^ip access-list (extended|standard) ", 1.5, "IOS named ACL"),
        (r"(?m)^authentication (mac-move|command bounce)", 1.5, "IOS 802.1X authentication"),
        # negative: exclude ASA/NX-OS/AOS-CX
        (r"(?m)^ASA Version", -10.0, "ASA Version header (not IOS)"),
        (r"(?m)^(feature|vpc domain)", -5.0, "NX-OS feature command (not IOS)"),
        (r"(?m)^Cisco Nexus", -10.0, "NX-OS Nexus header"),
        (r"(?m)^access-list \S+ extended (permit|deny)", -3.0, "ASA-style ACL (not IOS)"),
        (r"(?m)^ssh \S+ \S+ (inside|outside|mgmt|dmz)\b", -2.0, "ASA SSH interface binding (not IOS)"),
        (r"(?m)^!Version ArubaOS-CX", -10.0, "AOS-CX version header (not IOS)"),
        (r"(?m)^!export-password:", -5.0, "AOS-CX export comment (not IOS)"),
    ],
    "cisco_asa": [
        (r"(?m)^ASA Version", 5.0, "ASA Version header"),
        (r"(?m)^(no )?names\b", 1.5, "ASA names command"),
        (r"(?m)^access-list \S+ extended", 2.0, "ASA extended ACL"),
        (r"(?m)^object-group (network|service|protocol)", 2.0, "ASA object-group"),
        (r"(?m)^nat \(", 2.0, "ASA nat statement"),
        (r"(?m)^crypto (ikev1|ikev2|ipsec|map)", 1.0, "ASA crypto"),
        (r"(?m)^(no )?same-security-traffic", 1.5, "ASA same-security-traffic"),
        (r"(?m)^hostname ", 0.5, "hostname line"),
        (r"(?m)^: Saved", 1.0, "ASA Saved comment"),
        (r"(?m)^ssh \S+ \S+ (inside|outside|mgmt|dmz)\b", 2.0, "ASA SSH interface binding"),
        (r"(?m)^(no )?ssh stricthostkeycheck\b", 2.0, "ASA ssh stricthostkeycheck"),
        (r"(?m)^ssh key-exchange group ", 2.0, "ASA SSH key-exchange"),
        (r"(?m)^aaa authentication include .+ (inside|outside|dmz)\b", 2.0, "ASA aaa interface binding"),
    ],
    "cisco_nxos": [
        (r"(?m)^!Command: show running-config", 2.0, "NX-OS show running header"),
        (r"(?m)^Cisco Nexus", 4.0, "NX-OS Nexus header"),
        (r"(?m)^feature \w+", 3.0, "NX-OS feature command"),
        (r"(?m)^vpc domain", 2.0, "NX-OS vPC domain"),
        (r"(?m)^vlan \d+", 1.0, "vlan block"),
        (r"(?m)^interface (Ethernet|mgmt)\d", 1.5, "NX-OS interface style"),
        (r"(?m)^hostname ", 0.5, "hostname line"),
        (r"(?m)^nxos ", 1.0, "nxos version line"),
    ],
    "cisco_ftd": [
        (r"(?m)^# ?(Firepower|FTD|FDM)", 4.0, "FTD header comment"),
        (r"(?m)^policy-map type inspect", 2.0, "FTD policy-map inspect"),
        (r"(?m)^class-map type inspect", 2.0, "FTD class-map inspect"),
        (r"(?m)^(ASA Version|NGFW Version)", 2.0, "ASA-mode FTD version"),
        (r'"type"\s*:\s*"(FirewallPolicy|AccessControlPolicy)"', 4.0, "FMC JSON policy type"),
        (r'"FTD"', 2.0, "FMC JSON FTD reference"),
        (r'"accessRules"', 2.0, "FMC JSON accessRules"),
    ],
    # ---------------------------------------------------------------- Arista
    "arista_eos": [
        (r"(?m)^! device: .+ EOS", 5.0, "EOS device header"),
        (r"(?m)^! image version:", 2.0, "EOS image version comment"),
        (r"(?m)^daemon TerminAttr", 2.0, "EOS TerminAttr daemon"),
        (r"(?m)^management (api|console|ssh|telnet)", 2.0, "EOS management block"),
        (r"(?m)^interface (Ethernet|Management)\d", 1.5, "Arista interface (EOS-style)"),
        (r"(?m)^hostname ", 0.5, "hostname line"),
        (r"(?m)^spanning-tree mode (mstp|rstp|rapid-pvst)", 0.5, "spanning-tree"),
        (r"(?m)^!RANCID-CONTENT-TYPE: arista\b", 4.0, "RANCID arista tag"),
        (r"(?m)^switchport default mode routed\b", 2.0, "EOS switchport default routed"),
        (r"(?m)^boot system flash .+\.swi\b", 1.5, "EOS boot flash .swi"),
        (r"(?m)^\s+no bgp bestpath as-path multipath-relax\b", 2.0, "EOS BGP bestpath knob"),
        (r"(?m)^ip access-list \S+\s*\n\s+\d+ (permit|deny)", 1.5, "EOS numbered ACL entries"),
        # negative: GigabitEthernet/FastEthernet/Serial are IOS, not Arista
        (r"(?m)^interface (GigabitEthernet|FastEthernet|Serial)\d", -3.0, "classic IOS interface (not Arista)"),
        (r"(?m)^(ASA Version|feature \w+|Cisco Nexus)", -5.0, "ASA/NX-OS (not Arista)"),
    ],
    # --------------------------------------------------------------- HPE Aruba
    "hpe_aruba": [
        # AOS-CX format (!Version ArubaOS-CX header + export comment)
        (r"(?m)^!Version ArubaOS-CX", 5.0, "AOS-CX version header"),
        (r"(?m)^!export-password:", 3.0, "AOS-CX export-password comment"),
        (r"(?m)^\s*ssh server vrf (default|mgmt)\b", 2.0, "AOS-CX ssh server vrf"),
        (r"(?m)^\s*https-server vrf (default|mgmt)\b", 2.0, "AOS-CX https-server vrf"),
        (r"(?m)^\s*ntp vrf (mgmt|default)\b", 1.5, "AOS-CX ntp vrf binding"),
        # AOS-S / ProCurve format
        (r"(?m)^; J\d{4}[A-Z]", 3.0, "ProCurve product code"),
        (r"(?m)^(Running configuration|Startup configuration):", 2.0, "ProCurve config header"),
        (r"(?m)^spanning-tree \d+ priority", 1.5, "ProCurve STP priority"),
        (r"(?m)^vlan \d+\s+name", 1.5, "Aruba/ProCurve VLAN name"),
        (r"(?m)^ip (authorized-managers|source-interface)", 2.0, "ProCurve mgmt IP cmd"),
        (r"(?m)^crypto key generate (ssh|rsa)", 1.5, "ProCurve crypto key"),
        # Shared
        (r"(?m)^\s*aaa authentication", 1.0, "aaa authentication"),
    ],
    # --------------------------------------------------------------- Fortinet
    "fortios": [
        (r"(?m)^config (system|firewall|router|user|vpn|log|waf)", 4.0, "FortiOS config block"),
        (r"(?m)^\s+set \w+ .+", 1.5, "FortiOS set command"),
        (r"(?m)^\s+next\s*$", 2.0, "FortiOS next keyword"),
        (r"(?m)^end\s*$", 0.5, "FortiOS end keyword"),
        (r"(?m)^#config-version=FGVM", 3.0, "FortiGate VM config version"),
        (r"(?m)^#conf_file_ver=", 2.0, "FortiOS conf_file_ver"),
        (r"(?m)^config system global", 3.0, "FortiOS system global"),
    ],
    # --------------------------------------------------------------- Juniper
    "junos": [
        (r"(?m)^set (system|interfaces|routing-options|policy-options|firewall|security)", 4.0, "JunOS set statement"),
        (r"(?m)^set system host-name", 3.0, "JunOS set host-name"),
        (r"(?m)^set version ", 2.0, "JunOS set version"),
        (r"(?m)^## Last commit:", 2.0, "JunOS commit comment"),
        (r"(?m)^\{master\}", 2.0, "JunOS master RE prompt"),
        (r"(?m)^set security zones", 2.0, "JunOS security zones"),
        # curly-brace format
        (r"(?m)^system \{", 3.0, "JunOS curly system block"),
        (r"(?m)^(interfaces|routing-options|security|protocols) \{", 2.0, "JunOS top-level curly block"),
        (r"(?m)^version \d+\.\d+[A-Z]\d", 2.0, "JunOS alpha-release version"),
    ],
    # -------------------------------------------------------------- Palo Alto
    "palo_alto": [
        (r"<config\s+version=", 5.0, "PAN-OS XML config version"),
        (r"<devices>.*?<entry name=", 3.0, "PAN-OS devices entry"),
        (r"<vsys>.*?<entry", 2.0, "PAN-OS vsys"),
        (r"<address>.*?<entry name=", 2.0, "PAN-OS address object"),
        (r"<rulebase>", 3.0, "PAN-OS rulebase"),
        (r"<GlobalProtect>|<global-protect>", 2.0, "GlobalProtect config"),
        (r"<panorama>|<Panorama>", 1.0, "Panorama reference"),
    ],
    # ------------------------------------------------------------ Check Point
    "checkpoint": [
        # Gaia OS "show configuration" format (most common offline export)
        (r"(?m)^# Configuration of\s+\S+", 5.0, "Gaia show configuration header"),
        (r"(?m)^# Language version: \d+\.\d+", 4.0, "Gaia language version comment"),
        (r"(?m)^set hostname\s+\S+", 3.0, "Gaia set hostname"),
        (r"(?m)^set (timezone|password-controls|ntp active|snmp agent|ssh enable|role_manager)", 2.0, "Gaia system command"),
        (r"(?m)^set interface \S+ (ipv4-address|state|type)", 2.0, "Gaia interface config"),
        (r"(?m)^add (user|ntp|allowed-client|route|arp)\s+", 2.0, "Gaia add command"),
        # Management API CLISH format (SmartConsole/mgmt_cli)
        (r"(?m)^(add |set |show )(host|network|service|access-role|gateway) ", 2.0, "CLISH mgmt-API command"),
        (r"(?m)^add access-rule", 2.0, "CLISH access-rule"),
        # Legacy object dump format
        (r"(?m)^:.*\(", 3.0, "Check Point object syntax :name ("),
        (r"(?m)^:(name|type|ipaddr|netmask|color|comments) \(", 2.0, "Check Point attribute"),
        (r"(?m)^/\* Object Dump", 2.0, "Check Point object dump header"),
        (r"(?m)^# Policy Name:", 2.0, "Check Point policy header"),
        (r"(?m)^\$fw_version", 2.0, "Check Point fw_version"),
    ],
    # -------------------------------------------------------------- Sophos XG
    "sophos_xg": [
        # Entities.xml / Import-Export root (confirmed: community.sophos.com, alfonsrv cookiecutter)
        (r'<Configuration\s+APIVersion="\d{4}\.\d+"', 5.0, "Sophos Entities.xml Configuration root"),
        # Legacy / alternative root tags seen in community posts
        (r"<XGFirewallConf|<XGConfiguration", 4.0, "Sophos XG legacy XML root"),
        # Confirmed XML tags from sophos/sophos-firewall-sdk and sophos/sophosfirewall-ansible
        (r"<FirewallRule\b", 3.0, "Sophos FirewallRule entity"),
        (r"<AdminSettings\b", 3.0, "Sophos AdminSettings entity"),
        (r"<SyslogServers\b", 2.0, "Sophos SyslogServers entity"),
        (r"<SNMPAgent\b|<SNMPv3User\b", 2.0, "Sophos SNMP entity"),
        (r"<WebAdminSettings\b|<LoginSecurity\b", 2.0, "Sophos WebAdmin/LoginSecurity"),
        (r"<IPHost\b|<IPHostGroup\b", 1.5, "Sophos IPHost entity"),
        (r"<Zone\b.*<Type>(LAN|WAN|DMZ|VPN)", 1.5, "Sophos Zone entity"),
        (r"<Time\b.*<NTPServerList|<NTPServerList\b", 1.5, "Sophos Time/NTP config"),
        (r"<NetworkPolicy\b|<IntrusionPrevention\b", 1.5, "Sophos NetworkPolicy"),
        (r'version="XG', 2.0, "Sophos XG version attribute"),
        (r"<VLAN\b.*<Interface\b|<VLAN\s+transactionid", 1.5, "Sophos VLAN entity"),
    ],
    # ---------------------------------------------------------------- SonicWall
    "sonicwall": [
        # E-CLI export format ("export current-config cli")
        (r"(?m)^firmware-version SonicOS", 5.0, "SonicWall E-CLI firmware-version header"),
        (r"(?m)^access-rule from\s+\S+\s+to\s+\S+", 3.0, "SonicWall E-CLI access-rule"),
        (r"(?m)^address-object (ipv4|ipv6|mac|fqdn)\s+", 2.0, "SonicWall E-CLI address-object"),
        (r"(?m)^management (http|https|ssh|ping|snmp)\b", 2.0, "SonicWall E-CLI management"),
        (r"(?m)^no management (http|telnet)\b", 2.5, "SonicWall E-CLI disable-http"),
        (r"(?m)^syslog server\b", 1.5, "SonicWall E-CLI syslog"),
        (r"(?m)^ntp server\b", 1.5, "SonicWall E-CLI ntp server"),
        (r"(?m)^service-object\b", 1.5, "SonicWall E-CLI service-object"),
        # Older/XML format
        (r"(?m)^<SonicwallConfig|<SonicWALL", 5.0, "SonicWall XML root"),
        (r"(?m)^prefs ", 3.0, "SonicWall prefs line"),
        (r"(?m)^(no )?sysinfo serialnumber", 2.0, "SonicWall sysinfo"),
    ],
    # ------------------------------------------------------------ Nokia SR OS
    "nokia_sros": [
        # Classic CLI format (TiMOS header + configure/exit blocks)
        (r"(?m)^(# TiMOS|# Nokia)", 5.0, "SR OS TiMOS/Nokia header"),
        (r"(?m)^\s*configure\s*\{", 2.0, "SR OS configure block"),
        (r"(?m)^(configure|admin|debug|show) (system|router|service|port)", 2.0, "SR OS CLI command"),
        (r"(?m)^(exit all|exit)\s*$", 1.0, "SR OS exit"),
        (r"(?m)^\s+router \S+ \{", 1.5, "SR OS router block"),
        (r"(?m)^\s+log \{", 1.0, "SR OS log block"),
        (r"(?m)^# Generated by SR OS", 3.0, "SR OS generated header"),
        # MD-CLI flat format (/configure prefix on every line)
        (r"(?m)^/configure system\b", 5.0, "SR OS MD-CLI flat: /configure system"),
        (r"(?m)^/configure router\b", 3.0, "SR OS MD-CLI flat: /configure router"),
        (r"(?m)^/configure (service|port|lag)\b", 2.0, "SR OS MD-CLI flat: service/port/lag"),
        # Negative: exclude SR Linux flat CLI (uses "set /" not "/configure")
        (r"(?m)^set / (interface|network-instance)\b", -5.0, "SR Linux set / (not SR OS)"),
    ],
    # ------------------------------------------------------------ Nokia SR Linux
    "nokia_srl": [
        # JSON config export format
        (r'"srl_nokia"', 4.0, "SRL Nokia JSON vendor"),
        (r'"system".*?"information"', 2.0, "SRL system information JSON"),
        (r'"network-instance"', 3.0, "SRL network-instance JSON"),
        (r'"interface".*?"subinterface"', 2.0, "SRL interface JSON"),
        (r'"acl".*?"ipv[46]-filter"', 2.0, "SRL ACL filter JSON"),
        (r'"routing-policy"', 1.5, "SRL routing-policy JSON"),
        (r'"openconfig-system:', 1.0, "SRL OpenConfig namespace"),
        # Flat CLI set format (learned from learn-srlinux and srl-labs)
        (r"(?m)^set / (interface|network-instance|system|routing-policy|acl)\b", 4.0, "SRL flat CLI set /"),
        (r"(?m)^set / network-instance\b", 3.0, "SRL flat CLI network-instance"),
        (r"(?m)^set / interface system0\b", 3.0, "SRL flat CLI system0 loopback"),
    ],
}

MIN_CONFIDENCE = 0.3
MINIMUM_SCORE = 2.0


def detect(text: str) -> DetectionResult | None:
    """
    Detect vendor/profile from raw config text.

    Returns the best-matching DetectionResult, or None if no profile
    reaches the minimum threshold.
    """
    scores: dict[str, float] = {}
    signals_matched: dict[str, list[str]] = {}

    for profile, signals in PROFILE_SIGNALS.items():
        total = 0.0
        matched: list[str] = []
        for pattern, weight, label in signals:
            flags = re.IGNORECASE | re.DOTALL if weight > 0 else re.IGNORECASE | re.DOTALL
            if re.search(pattern, text, flags):
                total += weight
                if weight > 0:
                    matched.append(label)
        scores[profile] = total
        signals_matched[profile] = matched

    if not scores:
        return None

    best_profile = max(scores, key=lambda p: scores[p])
    best_score = scores[best_profile]

    if best_score < MINIMUM_SCORE:
        return None

    # Normalize to 0–1 by treating the max possible score as 10.0
    max_possible = sum(w for _, w, _ in PROFILE_SIGNALS[best_profile] if w > 0) or 10.0
    confidence = min(best_score / max_possible, 1.0)

    return DetectionResult(
        profile=best_profile,
        vendor=PROFILE_VENDOR[best_profile],
        confidence=round(confidence, 3),
        signals=signals_matched[best_profile],
    )


def detect_from_file(path: Path) -> DetectionResult | None:
    """Read file and detect vendor profile."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return detect(text)
