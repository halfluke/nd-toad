```
                   ( ) ( )
  [RTR]-----+       \\ //       +-----[FW]
            |       (o o)       |
  [SW]------+------( /||\ )-----+------[AP]
            |       \    /      |
  [ASA]-----+        \__/       +-----[SRX]
         nd-goat — Network Device Goat Auditing Tool
```

# ND-GOAT — Network Device Goat Auditing Tool

Offline network device configuration security auditor with **CIS Level 1 mapping** across 14 vendor/platform profiles.

ND-GOAT reads static config files — no live device access, no API keys, no agents — and produces structured security findings mapped to CIS benchmark controls. Each finding has a `pass / fail / manual / not_applicable` status, severity, evidence (the offending config lines), and remediation guidance.

---

## Supported platforms

| Profile | Vendor | Input format | Reference benchmark / guide |
|---------|--------|-------------|---------------------------|
| `cisco_ios` | Cisco | `show running-config` plain text | [CIS Cisco IOS 17.x v2.0.0](https://www.cisecurity.org/benchmark/cisco) |
| `cisco_asa` | Cisco | `show running-config` plain text | [CIS Cisco ASA 9.x Firewall v1.1.0](https://www.cisecurity.org/benchmark/cisco) |
| `cisco_nxos` | Cisco | `show running-config` plain text | [CIS Cisco NX-OS v1.2.0](https://www.cisecurity.org/benchmark/cisco) |
| `cisco_ftd` | Cisco | ASA-shaped CLI plain text | [CIS Cisco Firepower Threat Defense v1.0.0](https://www.cisecurity.org/benchmark/cisco) |
| `arista_eos` | Arista | `show running-config` plain text | [DISA Arista MLS EOS 4.X STIG](https://public.cyber.mil/stigs/downloads/) ¹ |
| `hpe_aruba` | HPE | `show running-config` plain text | [HPE AOS-CX Hardening Guide 10.14](https://arubanetworking.hpe.com/techdocs/AOS-CX/10.14/PDF/hardening.pdf) ¹ |
| `fortios` | Fortinet | Full config `.conf` text (GUI Backup → Full Config) | [CIS FortiGate 7.4.x v1.0.1](https://www.cisecurity.org/benchmark/fortinet) |
| `junos` | Juniper | Set format **or** curly-brace format plain text | [CIS Juniper OS v2.1.0](https://www.cisecurity.org/benchmark/juniper/) |
| `palo_alto` | Palo Alto | Named config snapshot `.xml` (Device → Export) | [CIS Palo Alto Firewall 11 v1.2.0](https://www.cisecurity.org/benchmark/palo_alto_networks) |
| `checkpoint` | Check Point | Gaia OS `show configuration` plain text ⚠ OS layer only | [CIS Check Point Firewall v1.1.0](https://www.cisecurity.org/benchmark/checkpoint_firewall) |
| `sophos_xg` | Sophos | `Entities.xml` from Import-Export `.tar` ⚠ not Backup | [CIS Sophos Firewall v21/v22 v1.0.0](https://www.cisecurity.org/benchmark/sophos) |
| `sonicwall` | SonicWall | E-CLI text (`export current-config cli`) ⚠ not `.exp` | [SonicWall Firewall Best Practices KB](https://www.sonicwall.com/support/knowledge-base/best-practices-for-administrator-managing-sonicwall-firewall-appliances/kA1VN0000000Jyv0AE) ¹ |
| `nokia_sros` | Nokia | Classic CLI **or** MD-CLI flat text (`admin save`) | [Nokia SR OS Security — System Management Guide](https://documentation.nokia.com/sr/24-7/7x50-shared/system-management/security-system-management.html) ¹ |
| `nokia_srl` | Nokia | JSON export **or** flat CLI set format (`info flat`) | [Nokia SR Linux Security — Configuration Basics Guide](https://documentation.nokia.com/srlinux/22-6/SR_Linux_Book_Files/Configuration_Basics_Guide/configb-security.html) ¹ |

> ¹ No dedicated CIS benchmark available for this platform. Checks are based on the linked official vendor hardening documentation and generic network device hardening best practices.
>
> Benchmark versions shown were the latest available in **May 2026**. CIS publishes updates monthly — visit the linked page before each audit to confirm you are working from the current version. PDFs are freely downloadable **without registration** from [downloads.cisecurity.org](https://downloads.cisecurity.org/#/).

**186 security checks** across all 14 profiles — 159 automated probes + 27 manual-only entries. CIS L1 controls that cannot be reliably automated from a static config file are emitted as `status: manual` for human review.

---

## Supported input formats

This section explains precisely **which export or copy-paste format** each vendor requires, how to obtain it, and what the tool cannot parse. This is the most common source of confusion when onboarding a new device.

> **General rule:** The tool works on plain-text or XML/JSON files you can open in a text editor. It does **not** support encrypted archives, proprietary binary formats, or live device connections.

### Cisco IOS / IOS-XE (`cisco_ios`)

| | |
|---|---|
| **Accepted format** | Plain-text CLI output |
| **How to obtain** | `show running-config` from privilege EXEC; capture terminal output to a `.txt` file |
| **First-line indicator** | `Building configuration...` or `Current configuration : XXXX bytes` |
| **Also accepted** | RANCID-style files with `!RANCID-CONTENT-TYPE: cisco` header |
| **Not supported** | Encrypted `service password-encryption` passwords are parsed as-is; binary NVRAM images |

### Cisco ASA (`cisco_asa`)

| | |
|---|---|
| **Accepted format** | Plain-text CLI output |
| **How to obtain** | `show running-config` in EXEC mode; or File → Save Running Configuration to TFTP/Flash from ASDM |
| **First-line indicator** | `ASA Version X.Y(Z)` or `: Saved` |
| **Not supported** | ASDM `.cfg` binary packages |

### Cisco NX-OS (`cisco_nxos`)

| | |
|---|---|
| **Accepted format** | Plain-text CLI output |
| **How to obtain** | `show running-config` from EXEC; capture output |
| **First-line indicator** | `!Command: show running-config` or `Cisco Nexus` header, `feature` stanzas |
| **Not supported** | Binary checkpoint files |

### Cisco FTD (`cisco_ftd`)

| | |
|---|---|
| **Accepted format** | ASA-shaped CLI text (FTD in platform mode) |
| **How to obtain** | `show running-config` via FTD SSH / console; or export from FMC as text |
| **First-line indicator** | `NGFW Version` or `FTD` in header, or classic ASA header |
| **Note** | Full FTD security intelligence, ACP policies, and intrusion rules are stored in FMC and not available in the static CLI export — those checks are `status: manual` |

### Arista EOS (`arista_eos`)

| | |
|---|---|
| **Accepted format** | Plain-text CLI output |
| **How to obtain** | `show running-config` from EXEC; or RANCID/NAPALM captures |
| **First-line indicator** | `! device: ` hostname line, or `!RANCID-CONTENT-TYPE: arista`, or `Arista` in version string |
| **Also accepted** | Multi-line `!` comment style native to EOS |

### HPE Aruba AOS-CX (`hpe_aruba`)

| | |
|---|---|
| **Accepted format** | Plain-text CLI output |
| **How to obtain** | `show running-config` from EXEC mode |
| **First-line indicator** | `; ArubaOS-CX` version comment or `Current configuration:` |
| **Not supported** | AOS (legacy) switch configs; these use a different syntax and are not supported |

### Fortinet FortiGate (`fortios`)

| | |
|---|---|
| **Accepted format** | FortiOS full configuration text (`.conf`) |
| **How to obtain** | System → Backup → **Full Config** from GUI (downloads as plain text); or CLI: `execute backup config tftp <file> <server>` |
| **First-line indicator** | `#config-version=` header or `config system global` at top level |
| **Format** | Hierarchical `config … / edit … / set … / end` blocks |
| **Not supported** | Encrypted backups (encrypted with a passphrase in the GUI produce a Base64-wrapped binary); FortiManager policy packages |

### Juniper JunOS (`junos`)

| | |
|---|---|
| **Accepted formats** | Two formats are both supported: |
| **1. Set format** (preferred) | `show configuration \| display set` — one command per line: `set system services ssh` |
| **2. Curly-brace format** | `show configuration` — hierarchical blocks with `{ }` |
| **How to obtain** | SSH to the device and run either command; pipe output to a file |
| **First-line indicator** | Set format: lines starting with `set system` or `set interfaces`; curly format: `## Last commit:` header and `{` blocks |
| **Not supported** | Encrypted private keys embedded in the config; JunOS Space / NSM policy objects |

### Palo Alto Networks (`palo_alto`)

| | |
|---|---|
| **Accepted format** | XML configuration export |
| **How to obtain** | Device → Setup → Operations → **Export named configuration snapshot** (downloads `running-config.xml`); or CLI: `scp export configuration from running-config.xml to user@host:path` |
| **First-line indicator** | `<config version="X.Y.Z" urldb="paloaltonetworks">` XML root |
| **Not supported** | Panorama `.panos` templates (different XML namespace); binary device state bundles (`.tgz`) |

### Check Point Gaia (`checkpoint`)

| | |
|---|---|
| **Accepted formats** | Two formats are both supported: |
| **1. Gaia OS `show configuration`** (primary) | OS-level export: interfaces, routing, users, SSH, SNMP, NTP, password policy |
| **2. Legacy SmartConsole object dump** | `objects.C` / `rulebases_5_0.fws` text dumps from R77 and older |
| **How to obtain — Gaia format** | SSH to the gateway in CLISH: `show configuration` (interactive), or from Expert mode: `clish -c "show configuration" > /var/log/config.txt` |
| **First-line indicator** | `# Configuration of <hostname>` / `# Language version: 10.0v1` header |
| **⚠ Important limitation** | The Gaia `show configuration` output contains **only the OS layer**: interfaces, users, routing, SSH, SNMP, NTP, password controls. The **firewall policy** (security rules, NAT, objects, application control) is stored in the SmartConsole management server database — it is **not** present in any offline text export. Checks for firewall policy items (`CP-POLICY-*`) are always `status: manual`. |
| **Not supported** | Full system snapshots (`.tgz`); SmartConsole `.tar.gz` database exports; encrypted config bundles |

### Sophos XG / XGS SFOS (`sophos_xg`)

| | |
|---|---|
| **Accepted format** | `Entities.xml` extracted from the Import-Export `.tar` archive |
| **How to obtain** | System → Backup & firmware → **Import export** → Export → download `.tar` → extract with `tar -xf API-XXXXX.tar` → use `Entities.xml` |
| **First-line indicator** | `<Configuration APIVersion="NNNN.N" IPS_CAT_VER="N">` XML root |
| **⚠ Important limitation** | The **Import-Export** produces plain XML. The **Backup** (System → Backup & firmware → Backup) produces an AES-256 encrypted `.tar.gz` that is **not parseable offline** — do not use backup files, use Import-Export only. |
| **Not supported** | Encrypted backup archives; Sophos Central cloud-managed policy bundles |

### SonicWall SonicOS (`sonicwall`)

| | |
|---|---|
| **Accepted formats** | Two formats are both supported: |
| **1. E-CLI text export** (preferred) | Hierarchical CLI commands: `address-object / zone / exit`, `access-rule from X to Y / action / exit` |
| **2. SonicOS legacy prefs** | Older `prefs hostname …` / `access-list` flat format from SonicOS 5.x and earlier |
| **How to obtain — E-CLI format** | SSH to the device: `no cli pager` then `show current-config`; or export to FTP: `export current-config cli ftp ftp://user:pass@server/config.txt` |
| **First-line indicator** | E-CLI: `firmware-version SonicOS X.Y.Z-…` header; legacy: `prefs ` prefix lines |
| **⚠ Important limitation** | The standard GUI **Export Settings** button produces a `.exp` file which is Base64-encoded and then URL-encoded — it is NOT the same as the E-CLI text export. That `.exp` format is a proprietary binary blob and is not supported. Use `export current-config cli` instead. |
| **Not supported** | `.exp` binary/encoded backup files; SonicWall Management System (GMS/NSM) policy bundles |

### Nokia SR OS (`nokia_sros`)

| | |
|---|---|
| **Accepted formats** | Two formats are both supported: |
| **1. Classic CLI** | Indented `configure / exit` block tree with `# TiMOS-…` header |
| **2. MD-CLI flat** | Per-line `/configure system name "R1"` style produced by `admin save flat` or containerlab startup configs |
| **How to obtain** | `admin save` (classic) or `admin save flat` (MD-CLI); or collect via NETCONF/YANG |
| **First-line indicator** | Classic: `# TiMOS-…` or `# Nokia SR OS` header; MD-CLI: lines starting with `/configure ` |

### Nokia SR Linux (`nokia_srl`)

| | |
|---|---|
| **Accepted formats** | Two formats are both supported: |
| **1. JSON export** (primary) | Full JSON config produced by `info flat \| as json` or gNMI `GetRequest` |
| **2. Flat CLI set format** | Per-line `set / system name "host"` style from `info flat` CLI mode |
| **How to obtain** | `info flat \| as json > config.json` in SR Linux CLI; or gNMI/gRPC JSON export |
| **First-line indicator** | JSON: `{"srl_nokia-system:system": …}` or `{"system": …}` top-level keys; flat CLI: `set / system` prefix lines |

---

### Summary matrix

| Profile | Accepted file types | Key command / export path | Encrypted backup parseable? |
|---------|--------------------|--------------------------|-----------------------------|
| `cisco_ios` | `.txt` `.conf` | `show running-config` | — |
| `cisco_asa` | `.txt` `.conf` | `show running-config` | — |
| `cisco_nxos` | `.txt` `.conf` | `show running-config` | — |
| `cisco_ftd` | `.txt` `.conf` | `show running-config` | — |
| `arista_eos` | `.txt` `.conf` | `show running-config` | — |
| `hpe_aruba` | `.txt` `.conf` | `show running-config` | — |
| `fortios` | `.conf` `.txt` | GUI: Backup → Full Config | **No** — passphrase-encrypted backup |
| `junos` | `.txt` `.conf` | `show config \| display set` | — |
| `palo_alto` | `.xml` | Device → Export named config snapshot | — |
| `checkpoint` | `.txt` `.conf` | `clish -c "show configuration"` | **No** — snapshot `.tgz` not supported |
| `sophos_xg` | `.xml` (Entities.xml only) | Backup & firmware → Import export | **No** — use Import-Export, not Backup |
| `sonicwall` | `.txt` `.conf` | `export current-config cli ftp …` | **No** — `.exp` files not supported |
| `nokia_sros` | `.txt` `.conf` | `admin save` / `admin save flat` | — |
| `nokia_srl` | `.json` `.txt` | `info flat \| as json` | — |

---

## Installation

**Requirements:** Python 3.11+

```bash
# From the project directory
pip install -e .

# With dev/test dependencies
pip install -e ".[dev]"
```

The `nd-goat` command is registered as a console script and available immediately after install.

---

## Quick start

```bash
# Auto-detect vendor and audit a single config file
nd-goat audit -i router.conf

# Force vendor profile (skip auto-detection)
nd-goat audit -i asa-backup.txt --vendor cisco_asa

# Batch audit an entire directory
nd-goat audit --dir ./network-configs/

# Save JSON report to file
nd-goat audit -i firewall.conf --output report.json

# Save CSV report to file (one row per check, great for spreadsheets)
nd-goat audit -i firewall.conf --csv report.csv

# Batch audit a directory and save all findings in one CSV
nd-goat audit --dir ./network-configs/ --csv all-findings.csv

# Print JSON to stdout (pipe-friendly)
nd-goat audit -i firewall.conf --json

# Print CSV to stdout
nd-goat audit -i firewall.conf --csv-stdout

# See what vendor a file is detected as (without running checks)
nd-goat detect mystery-config.txt

# List all supported vendor profiles
nd-goat vendors
```

---

## Running against sample files

The repository ships a `samples/` directory containing **67 real and synthetic configuration files** covering all 14 supported profiles. These are ready to use immediately after installation — no device access needed.

### Audit all samples at once

```bash
# Table output per file (shows failures and manual checks)
nd-goat audit --dir samples/

# JSON output — one record per file, written to stdout
nd-goat audit --dir samples/ --json
```

The `--json` flag switches the output from the rich terminal table to machine-readable JSON.
You can pipe that JSON into any tool you like — `jq`, a SIEM, a script, etc.
The snippet below is just one example using a short Python one-liner to print a compact score per file:

```bash
nd-goat audit --dir samples/ --json | python3 -c "
import json, sys
data = json.load(sys.stdin)
if isinstance(data, dict): data = [data]
for r in data:
    s = r['summary']
    score = round(s['passed'] / max(s['passed'] + s['failed'], 1) * 100)
    print(f\"{s['profile']:20s}  {s['input_file'].split('/')[-1]:45s}  \"\
          f\"pass={s['passed']:3d} fail={s['failed']:3d}  score={score}%\")
"
```

### Audit samples for one vendor

```bash
nd-goat audit --dir samples/cisco_ios/
nd-goat audit --dir samples/palo_alto/
nd-goat audit --dir samples/junos/
```

### Audit a single sample with full details

```bash
# Rich table (default) — failures highlighted in red, manual items shown
nd-goat audit -i samples/cisco_ios/sample_01.ios

# Show passing checks as well
nd-goat audit -i samples/cisco_ios/sample_01.ios --show-pass

# JSON output — save to a file or pipe to jq / any other processor
nd-goat audit --json -i samples/palo_alto/iron_skillet_panos_full.xml > result.json

# Optional: extract only failing checks with a Python one-liner
nd-goat audit --json -i samples/palo_alto/iron_skillet_panos_full.xml | \
  python3 -c "
import json, sys
r = json.load(sys.stdin)
for f in r['findings']:
    if f['status'] == 'fail':
        print(f\"{f['check_id']}  {f['severity']:8s}  {f['title']}\")
        for e in f.get('evidence', []):
            print(f'    {e}')
"

# Detect only — no checks, just fingerprint
nd-goat detect samples/nokia_sros/buraglio_vsr1.cfg
```

### Expected results from the sample set

70 config files across 14 profiles are included. The table below shows notable individual files.

| Profile | File(s) | Expected findings |
|---------|---------|-------------------|
| `cisco_ftd` | `ftd72_lina_running_config.conf` | 1 fail (default SNMP community) — intentional |
| `cisco_nxos` | `cisco_devnet_n9k_sandbox.conf` | 8 fails — real DevNet sandbox with telnet enabled, no password strength, no AAA login |
| `hpe_aruba` (AOS-CX) | `aos_cx_running_config.conf` | 1 fail (SNMP community `public`) — intentional |
| `hpe_aruba` (AOS-S) | `aos_s_procurve_running_config.conf` | All pass — reference hardened config |
| `checkpoint` | `gaia_r81_show_configuration.conf` | All pass — reference hardened Gaia config |
| `sonicwall` | `sonicos7_ecli_export.conf` | All pass — reference hardened E-CLI config |
| `sophos_xg` | `sophos_xg_backup_structure.xml` | All pass — reference hardened `Entities.xml` |
| `palo_alto` | `iron_skillet_panos91_full.xml` | 4 fails (no MOTD, no source-IP restrict, no ext-auth, no SNMP) — day-one template with placeholder values |
| `palo_alto` | `iron_skillet_panos100_full.xml` | 4 fails (same as above) — day-one template |
| `fortios` | `azure_vpn_fortigate_full.conf` | 7 fails — Azure VPN template focused on VPN, not hardening |
| `cisco_ios` (lab) | `batfish_*`, `sample_*.ios` | High fail rate — Batfish lab snippets, not hardened |
| `junos` | all 18 files | High fail rate — lab/community configs |
| `nokia_sros` | `buraglio_*`, `hellt_*`, `karneliuk_*` | 0–11% — bare lab configs; telnet default-on, no AAA/syslog |
| `nokia_srl` | `learn_srlinux_*` | All MGMT checks fail — routing-only lab configs |

The high failure count on Batfish/lab samples is expected and correct: they are minimal routing-lab configs that intentionally omit hardening like NTP, AAA, banners, and logging. Only the synthetic and Iron Skillet files represent hardened baselines.

### Licence status of the bundled samples

| Category | Files | Source | Licence |
|----------|-------|--------|---------|
| **Synthetic** | `checkpoint/`, `cisco_ftd/`, `hpe_aruba/`, `sonicwall/`, `sophos_xg/` | Written for this project, based on vendor docs | Public domain / CC0 |
| **Batfish project** | `batfish_*` in `cisco_ios/`, `cisco_asa/`, `arista_eos/`, `junos/` | [batfish/batfish](https://github.com/batfish/batfish) test fixtures | Apache 2.0 |
| **Iron Skillet** | `palo_alto/iron_skillet_panos_full.xml`, `iron_skillet_panos91_full.xml`, `iron_skillet_panos100_full.xml` | [PaloAltoNetworks/iron-skillet](https://github.com/PaloAltoNetworks/iron-skillet) (branches panos_v8.x, panos_v9.1, panos_v10.0) | Apache 2.0 |
| **CiscoDevNet** | `cisco_nxos/cisco_devnet_n9k_sandbox.conf` | [CiscoDevNet/netconf-examples](https://github.com/CiscoDevNet/netconf-examples) | Apache 2.0 |
| **Community GitHub** | `nokia_sros/buraglio_*`, `nokia_sros/hellt_*`, `nokia_sros/karneliuk_*`, `nokia_srl/learn_srlinux_*`, `fortios/`, `palo_alto/mastering_pan_ch7.xml`, `cisco_ios/sample_*.ios`, `cisco_asa/sample_01.asa`, `cisco_nxos/sample_01.nxos` | Public GitHub repositories (see `samples/SOURCES.md`) | MIT / Apache 2.0 / permissive per repo |
| **Public pastes** | `junos/pastebin_*` | Publicly posted on Pastebin by their authors | Public post, no explicit licence |

> **If you publish a fork:** review `samples/SOURCES.md` for specific origins before including community samples. The synthetic files are unrestricted. All files are anonymized configurations with no real credentials.

See [`samples/SOURCES.md`](samples/SOURCES.md) for per-file origin and attribution.

---

## CLI reference

### `nd-goat audit`

```
Usage: nd-goat audit [OPTIONS]

  Audit one config file or a directory of configs.

Options:
  -i, --input PATH                Config file to audit.
  -d, --dir PATH                  Directory of config files to audit (batch mode).
  -v, --vendor TEXT               Force vendor profile (skip auto-detect).
  -o, --output PATH               Write JSON report to this file.
      --csv PATH                  Write CSV report to this file (one row per finding).
  -j, --json                      Print JSON report to stdout.
      --csv-stdout                Print CSV report to stdout.
  --show-pass                     Include passing checks in table output.
  --show-manual / --hide-manual   Show or hide manual checks in table.
                                  [default: show-manual]
  --help                          Show this message and exit.
```

### `nd-goat detect`

```
Usage: nd-goat detect FILE

  Detect the vendor/profile of a config file without running checks.
```

### `nd-goat vendors`

```
Usage: nd-goat vendors

  List all supported vendor profiles.
```

---

## Output formats

| Flag | Format | Best for |
|------|--------|----------|
| *(none)* | Rich terminal table | Interactive review |
| `--json` / `--output file.json` | JSON (one object or array) | Scripting, SIEM ingestion |
| `--csv-stdout` / `--csv file.csv` | CSV, one row per finding | Spreadsheet analysis, ticket tracking |

### CSV columns

| Column | Description |
|--------|-------------|
| `file` | Basename of the audited config file |
| `profile` | Vendor profile (e.g. `cisco_ios`) |
| `hostname` | Detected hostname (blank if not found) |
| `compliance_pct` | Pass % for automated checks on that file |
| `check_id` | Check identifier, e.g. `IOS-MGMT-001` |
| `generic_id` | Cross-vendor ID, e.g. `MGMT-001` |
| `status` | `pass` / `fail` / `manual` / `not_applicable` |
| `severity` | `critical` / `high` / `medium` / `low` / `info` |
| `title` | Short check title |
| `cis_controls` | Semicolon-separated CIS benchmark references |
| `evidence` | Offending config lines joined with ` \| ` |
| `remediation` | Guidance text |

When using `--dir`, all findings from every file are written into **one sheet**, so you can filter by `file`, `profile`, or `status` in Excel / LibreOffice Calc.

---

## Example output

### Console (Rich table)

```
bad_telnet.conf → detected cisco_ios (confidence 52%, signals: IOS version line, ...)
──────────────────────── cisco_ios — INSECURE-RTR-01 ────────────────────────────

  ID              Status    Sev       Title                          CIS Controls
 ────────────────────────────────────────────────────────────────────────────────
  IOS-MGMT-003    fail      critical  Telnet must not be permitted   Cisco 3.1.1
                                      on VTY lines
  IOS-MGMT-004    fail      high      SSH version 2 must be          Cisco 3.1.2
                                      configured
  IOS-AUTH-001    fail      critical  enable secret must be          Cisco 1.2.1
                                      configured (not enable password)
  IOS-SNMP-001    fail      critical  Default SNMP community strings Cisco 4.1.1
                                      must not be used
  ...

  13 passed  17 failed  7 manual  0 n/a  — compliance score: 43.3%

  ✗ IOS-MGMT-003: Telnet must not be permitted on VTY lines
      transport input telnet
      → Under each 'line vty' block: transport input ssh
```

### JSON output

`nd-goat audit -i good.conf --json` produces:

```json
{
  "summary": {
    "profile": "cisco_ios",
    "hostname": "CORE-RTR-01",
    "input_file": "good.conf",
    "total": 37,
    "passed": 30,
    "failed": 0,
    "manual": 7,
    "not_applicable": 0,
    "compliance_score": 100.0
  },
  "findings": [
    {
      "check_id": "IOS-MGMT-003",
      "generic_id": "MGMT-001",
      "title": "Telnet must not be permitted on VTY lines",
      "description": "Telnet transmits credentials and data in cleartext...",
      "vendor": "cisco",
      "profile": "cisco_ios",
      "status": "fail",
      "severity": "critical",
      "cis": [
        { "benchmark": "CIS Cisco IOS 17", "control": "3.1.1", "level": 1 }
      ],
      "evidence": ["transport input telnet"],
      "remediation": "Under each 'line vty' block: transport input ssh"
    }
  ],
  "cis_summary": {
    "CIS Cisco IOS 17 — 3.1.1": {
      "status": "fail",
      "findings": ["IOS-MGMT-003"]
    }
  }
}
```

Batch mode (`--dir`) produces a JSON array with one report object per successfully detected file.

---

## How detection works

Vendor fingerprinting uses a **score-based signal system**. Each profile has a set of weighted regex patterns; the profile with the highest accumulated score wins (minimum threshold enforced).

For example, `cisco_ios` scores from: `Building configuration` (3.0 pts), `version X.Y` (2.0 pts), `line vty/con/aux` (2.0 pts), and so on. Competing profiles include negative signals (e.g., `ASA Version` deducts from `cisco_ios`).

If detection fails or is ambiguous, force the profile with `--vendor <profile>`.

---

## How checks work

### Check types

**`forbidden_regex`** — fails when the pattern IS found in the config. Used for things that must not exist (telnet, default SNMP communities, `permit ip any any`).

**`required_regex`** — fails when the pattern is NOT found. Used for things that must be present (`aaa new-model`, `ntp server`, `logging host`).

**`hook`** — delegates to a Python function in `src/fluff/hooks/` for logic too complex for regex (e.g., checking that every VTY block individually has `access-class`, or detecting any-any rules by correlating source and destination address fields in FortiOS policy blocks).

**`manual`** — always emits `status: manual`. Used directly in YAML for controls where even partial automation would mislead.

### Probe YAML format

Each `src/fluff/checks/vendors/<profile>.yaml` defines checks:

```yaml
- id: IOS-MGMT-003
  generic_id: MGMT-001          # cross-vendor stable ID
  title: "Telnet must not be permitted on VTY lines"
  severity: critical             # critical | high | medium | low | info
  cis:
    - benchmark: "CIS Cisco IOS 17"
      control: "3.1.1"
      level: 1
  probe:
    type: forbidden_regex
    pattern: '(?m)^\s*transport\s+input\s+(telnet|all)\b'
    # Optional: scope: "^line vty"  → narrow search to VTY blocks only
  remediation: "Under each 'line vty' block: transport input ssh"
```

### CIS catalog (manual entries)

`src/fluff/checks/cis_catalog.yaml` lists CIS L1 controls per profile that cannot be automated. These are emitted with `status: manual` in every audit run, ensuring the report is a complete L1 checklist — not just the automatable portion.

---

## Finding status values

| Status | Meaning |
|--------|---------|
| `pass` | Automated check passed |
| `fail` | Automated check failed — evidence provided |
| `manual` | Cannot be automated; human review required |
| `not_applicable` | Control does not apply to this device/config |

The **compliance score** in the summary covers only automated checks (`pass / fail`). Manual entries are counted separately.

---

## Generic check IDs

Cross-vendor stable IDs allow tooling to correlate findings across different platforms:

| ID | Topic |
|----|-------|
| `MGMT-001` | Telnet disabled |
| `MGMT-002` | HTTP management disabled or restricted |
| `MGMT-003` | SSH v2 as primary transport |
| `MGMT-004` | Management access restricted by source IP |
| `MGMT-005` | Session idle timeout configured |
| `AAA-001` | Centralised AAA enabled |
| `AAA-002` | Login banner configured |
| `AUTH-001` | Strong credential storage for privileged accounts |
| `AUTH-002` | Password complexity enforced |
| `SNMP-001` | No default SNMP community strings |
| `SNMP-002` | SNMP access restricted by ACL |
| `LOG-001` | Remote syslog configured |
| `LOG-002` | Log timestamps enabled |
| `TIME-001` | NTP server configured |
| `TIME-002` | NTP authentication enabled |
| `POLICY-001` | No any-to-any permit rules |
| `POLICY-002` | Management plane filtered |

---

## Project structure

```
nd_goat/
├── pyproject.toml
├── README.md
├── PLAN.md                         ← phase 1 design plan
├── docs/
│   └── input-formats.md            ← exact input format per profile
└── src/fluff/
    ├── cli.py                      ← nd-goat audit / detect / vendors
    ├── detect/
    │   ├── fingerprints.py         ← score-based detection (14 profiles)
    │   └── models.py               ← DetectionResult, PROFILES
    ├── parsers/
    │   ├── base.py                 ← ParsedConfig protocol + TextBasedConfig
    │   ├── router.py               ← load_config(path, profile) dispatcher
    │   ├── cisco_like.py           ← shared Family A ciscoconfparse2 adapter
    │   ├── cisco_ios.py            ← Cisco IOS / IOS-XE
    │   ├── cisco_asa.py            ← Cisco ASA
    │   ├── cisco_nxos.py           ← Cisco NX-OS
    │   ├── cisco_ftd.py            ← Cisco FTD (dual: ASA-CLI + FMC JSON)
    │   ├── arista_eos.py           ← Arista EOS
    │   ├── hpe_aruba.py            ← HPE Aruba / ProCurve
    │   ├── fortios.py              ← Fortinet FortiOS
    │   ├── junos.py                ← Juniper JunOS (set format)
    │   ├── xml_utils.py            ← shared XML helpers (lxml + stdlib fallback)
    │   ├── palo_alto.py            ← Palo Alto PAN-OS (XML)
    │   ├── sophos_xg.py            ← Sophos XG (XML)
    │   ├── checkpoint.py           ← Check Point (CLISH / object dump)
    │   ├── sonicwall.py            ← SonicWall SonicOS
    │   ├── nokia_sros.py           ← Nokia SR OS
    │   └── nokia_srl.py            ← Nokia SR Linux (JSON)
    ├── engine/
    │   ├── models.py               ← Finding, Status, Severity, CISRef, AuditResult
    │   ├── probe.py                ← forbidden_regex | required_regex | hook dispatch
    │   └── runner.py               ← audit() — load YAML → run probes → merge catalog
    ├── checks/
    │   ├── generic.yaml            ← generic check ID registry (documentation)
    │   ├── cis_catalog.yaml        ← manual-only L1 controls per profile
    │   └── vendors/                ← one YAML per profile (14 files, 186 total checks)
    │       ├── cisco_ios.yaml      ← 30 automated checks
    │       ├── cisco_asa.yaml      ← 16 automated checks
    │       ├── cisco_nxos.yaml     ← 14 automated checks
    │       └── ...
    ├── hooks/
    │   ├── policy_any_any.py       ← any-to-any detection (IOS/ASA/FortiOS/Junos/PAN)
    │   └── mgmt_acl.py             ← VTY access-class / RE filter / mgmt ACL checks
    └── report/
        └── json_report.py          ← render() + write_json()

tests/
├── conftest.py
├── test_detect.py                  ← 21 detection tests (all 14 profiles + edge cases)
├── test_engine.py                  ← 19 engine/runner tests
├── test_parsers.py                 ← 17 parser adapter tests
├── test_report.py                  ← 6 JSON report tests
└── fixtures/
    ├── cisco_ios/
    │   ├── good.conf               ← all automated checks pass (score 100%)
    │   ├── bad_telnet.conf         ← telnet, default SNMP, missing hardening
    │   └── bad_any_any.conf        ← permit ip any any
    ├── cisco_asa/{good,bad_telnet}.conf
    ├── cisco_nxos/good.conf
    ├── cisco_ftd/good.conf
    ├── arista_eos/good.conf
    ├── hpe_aruba/good.conf
    ├── fortios/good.conf
    ├── junos/good.conf
    ├── palo_alto/good.conf
    ├── checkpoint/good.conf
    ├── sophos_xg/good.conf
    ├── sonicwall/good.conf
    ├── nokia_sros/good.conf
    └── nokia_srl/good.conf
```

---

## Development

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=fluff --cov-report=term-missing   # internal package is still named 'fluff'

# Run a specific test file
pytest tests/test_detect.py -v

# Audit your own configs
nd-goat audit -i /path/to/your/router.conf
nd-goat audit --dir /path/to/configs/ --output report.json
```

---

## Adding a new check

1. Open `src/fluff/checks/vendors/<profile>.yaml`
2. Add a new entry following the existing format:

```yaml
- id: IOS-NEW-001
  generic_id: MGMT-001
  title: "Brief description of what must be true"
  severity: high
  cis:
    - {benchmark: "CIS Cisco IOS 17", control: "X.Y.Z", level: 1}
  probe:
    type: required_regex                  # or: forbidden_regex | hook | manual
    pattern: '(?m)^\s*your-regex-here'
  remediation: "What to configure to fix this."
```

3. Add a fixture to `tests/fixtures/<profile>/` that exercises the new check and add a test assertion to `tests/test_engine.py`.

To add a **Python hook** for complex logic:
1. Add a function to `src/fluff/hooks/policy_any_any.py` or `mgmt_acl.py` (or create a new module)
2. Reference it in YAML: `probe: {type: hook, module: fluff.hooks.my_module, func: check_<profile>}`
3. The function signature is `(config: ParsedConfig) -> ProbeResult`

---

## Adding a new vendor profile

1. Create `src/fluff/parsers/<profile>.py` subclassing `TextBasedConfig` (or `CiscoLikeConfig` for IOS-family syntax)
2. Register it in `src/fluff/parsers/router.py` under `_LOADERS`
3. Add fingerprint signals to `src/fluff/detect/fingerprints.py` under `PROFILE_SIGNALS`
4. Add the profile to `src/fluff/detect/models.py` → `PROFILES` and `PROFILE_VENDOR`
5. Create `src/fluff/checks/vendors/<profile>.yaml` with checks
6. Optionally add manual catalog entries to `src/fluff/checks/cis_catalog.yaml`
7. Create `tests/fixtures/<profile>/good.conf` and add detection + audit tests

---

## Phase 1 completion status

All completion criteria from the design plan (`PLAN.md`) are met:

| Criterion | Status |
|-----------|--------|
| 14 vendor profiles with documented input format | ✅ `docs/input-formats.md` |
| Auto-detect + `--vendor` override | ✅ score-based fingerprinting |
| ≥15–20 automated checks on Family A profiles | ✅ cisco_ios: 30, cisco_asa: 16, cisco_nxos: 14, arista_eos: 12, hpe_aruba: 11 |
| ≥10–15 automated checks on Family E profiles | ✅ checkpoint: 6+5 manual, sonicwall: 7+2 manual, nokia_sros: 9+1 manual |
| Full L1 catalog with `manual` entries emitted | ✅ `cis_catalog.yaml` per profile |
| JSON report with CIS grouping and compliance summary | ✅ `cis_summary` key groups by benchmark+control |
| Fixture test suite covering all profiles | ✅ 63 tests passing |
| Batch directory audit | ✅ `nd-goat audit --dir ./configs/` |

---

## Reference benchmarks & hardening guides

> **Versions below were verified in May 2026.** CIS releases updated benchmarks monthly.
> Always visit the linked vendor page to confirm you have the latest version before starting an audit engagement.
> CIS Benchmarks are freely available as PDFs for non-commercial use — **no registration required** — at [downloads.cisecurity.org](https://downloads.cisecurity.org/#/).

### Cisco

| Benchmark | Latest known version | Check for newer |
|-----------|---------------------|-----------------|
| CIS Cisco IOS 17.x | **2.0.0** | <https://www.cisecurity.org/benchmark/cisco> |
| CIS Cisco IOS XE 17.x | **2.2.1** | <https://www.cisecurity.org/benchmark/cisco> |
| CIS Cisco ASA 9.x Firewall | **1.1.0** | <https://www.cisecurity.org/benchmark/cisco> |
| CIS Cisco NX-OS | **1.2.0** | <https://www.cisecurity.org/benchmark/cisco> |
| CIS Cisco Firepower Threat Defense | **1.0.0** | <https://www.cisecurity.org/benchmark/cisco> |

### Fortinet

| Benchmark | Latest known version | Check for newer |
|-----------|---------------------|-----------------|
| CIS FortiGate 7.0.x | **1.4.0** | <https://www.cisecurity.org/benchmark/fortinet> |
| CIS FortiGate 7.4.x | **1.0.1** | <https://www.cisecurity.org/benchmark/fortinet> |

### Juniper

| Benchmark | Latest known version | Check for newer |
|-----------|---------------------|-----------------|
| CIS Juniper OS | **2.1.0** | <https://www.cisecurity.org/benchmark/juniper/> |

### Palo Alto Networks

| Benchmark | Latest known version | Check for newer |
|-----------|---------------------|-----------------|
| CIS Palo Alto Firewall 11 | **1.2.0** | <https://www.cisecurity.org/benchmark/palo_alto_networks> |
| CIS Palo Alto Firewall 10 | **1.3.0** | <https://www.cisecurity.org/benchmark/palo_alto_networks> |

### Check Point

| Benchmark | Latest known version | Check for newer |
|-----------|---------------------|-----------------|
| CIS Check Point Firewall | **1.1.0** | <https://www.cisecurity.org/benchmark/checkpoint_firewall> |

### Sophos

| Benchmark | Latest known version | Check for newer |
|-----------|---------------------|-----------------|
| CIS Sophos Firewall v21 | **1.0.0** | <https://www.cisecurity.org/benchmark/sophos> |
| CIS Sophos Firewall v22 | **1.0.0** | <https://www.cisecurity.org/benchmark/sophos> |

### Arista EOS — no CIS benchmark; DISA STIGs used

No CIS benchmark exists for Arista EOS. Checks follow the DISA Security Technical Implementation Guides (STIGs):

| STIG | URL |
|------|-----|
| Arista MLS EOS 4.X NDM STIG v1.0.0 | <https://public.cyber.mil/stigs/downloads/> |
| Arista MLS EOS 4.X Router STIG v1.0.0 | <https://public.cyber.mil/stigs/downloads/> |

Search for "Arista" in the DISA STIG downloads library.

### HPE Aruba — no CIS benchmark; official hardening guide used

| Document | URL |
|----------|-----|
| HPE AOS-CX 10.14 Hardening Guide (April 2025) | <https://arubanetworking.hpe.com/techdocs/AOS-CX/10.14/PDF/hardening.pdf> |
| HPE AOS-CX 10.13 Hardening Guide | <https://arubanetworking.hpe.com/techdocs/AOS-CX/10.13/PDF/hardening.pdf> |

### SonicWall — no CIS benchmark; official KB used

| Document | URL |
|----------|-----|
| SonicWall Firewall Best Practices for Administrators | <https://www.sonicwall.com/support/knowledge-base/best-practices-for-administrator-managing-sonicwall-firewall-appliances/kA1VN0000000Jyv0AE> |
| SonicWall Firewall Configuration Analysis Tool | <https://www.sonicwall.com/firewall-config-analysis-tool> |

### Nokia SR OS — no CIS benchmark; official documentation used

| Document | URL |
|----------|-----|
| Nokia SR OS Security — System Management Guide (24.7) | <https://documentation.nokia.com/sr/24-7/7x50-shared/system-management/security-system-management.html> |

### Nokia SR Linux — no CIS benchmark; official documentation used

| Document | URL |
|----------|-----|
| Nokia SR Linux Security — Configuration Basics Guide | <https://documentation.nokia.com/srlinux/22-6/SR_Linux_Book_Files/Configuration_Basics_Guide/configb-security.html> |
| Nokia SR Linux CPM Filter Hardening | <https://documentation.nokia.com/srlinux/23-3/books/advanced-solutions/security-harden-use-cpm-filters.html> |

---

## License

Apache-2.0. No GPL code is included or derived from nipper-ng or pynipper-ng. All checks are written clean-room from CIS benchmark documentation and publicly available vendor hardening guides.
