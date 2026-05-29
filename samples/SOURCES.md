# Sample file origins and attribution

This file documents the origin, source URL (where known), and licence of every file
in the `samples/` directory. All files are anonymized configurations with no real
credentials, IPs, or hostnames that identify production infrastructure.

---

## Synthetic samples (created for this project)

These files were written from scratch based on vendor documentation for the purpose
of exercising parsers and checks in fluff. They are released under **CC0 / Public Domain**.

| File | Based on |
|------|----------|
| `checkpoint/gaia_r81_show_configuration.conf` | Gaia R81 CLISH reference: Check Point sk83220, sk132492 |
| `cisco_ftd/ftd72_lina_running_config.conf` | Cisco FTD 7.2 LINA CLI Reference; community.cisco.com export examples |
| `cisco_xe/synthetic_cat9k_isr4k.conf` | CIS Cisco IOS 17 Benchmark + Catalyst 9300/ISR4K CLI reference; representative hardened config with Cat9K `platform type` and `AppGigabitEthernet` fingerprints |
| `huawei_vrp/synthetic_ne_router.conf` | Huawei VRP Security Hardening Guide + NE series CLI reference; representative hardened NE router config |
| `hpe_aruba/aos_s_procurve_running_config.conf` | HPE ProCurve J9727A WB.16.10 CLI reference |
| `hpe_aruba/aos_cx_running_config.conf` | AOS-CX 10.14 Hardening Guide (arubanetworking.hpe.com/techdocs/) |
| `sonicwall/sonicos7_ecli_export.conf` | SonicOS 7.x E-CLI reference; community.sonicwall.com |
| `sophos_xg/sophos_xg_backup_structure.xml` | Sophos SFOS API reference; sophos-firewall-sdk / sophosfirewall-ansible |

---

## Apache 2.0 — Batfish project

Source: https://github.com/batfish/batfish  
Licence: [Apache License 2.0](https://github.com/batfish/batfish/blob/master/LICENSE)  
The files below are derived from Batfish test fixtures. Copyright © Batfish contributors.

| File |
|------|
| `arista_eos/batfish_arista_acl.conf` |
| `arista_eos/batfish_arista_bgp.conf` |
| `arista_eos/batfish_arista_interface.conf` |
| `arista_eos/batfish_arista_misc.conf` |
| `arista_eos/batfish_arista_username.conf` |
| `arista_eos/batfish_dc_plane_0_spine_0.conf` |
| `arista_eos/batfish_dc_pod_0_leaf_0.conf` |
| `arista_eos/batfish_dc_pod_0_leaf_1.conf` |
| `cisco_asa/batfish_asa_acl.conf` |
| `cisco_asa/batfish_asa_banner.conf` |
| `cisco_asa/batfish_asa_interface.conf` |
| `cisco_asa/batfish_asa_ssh.conf` |
| `cisco_ios/batfish_cisco_aaa.conf` |
| `cisco_ios/batfish_cisco_authentication.conf` |
| `cisco_ios/batfish_exjun_as2border1.conf` |
| `cisco_ios/batfish_exjun_as2core1.conf` |
| `junos/batfish_exjun_as1border1.cfg` |
| `junos/batfish_juniper_bgp.conf` |
| `junos/batfish_juniper_interfaces.conf` |
| `junos/batfish_juniper_ntp.conf` |
| `junos/batfish_juniper_passwords.conf` |
| `junos/batfish_juniper_security.conf` |
| `junos/batfish_juniper_snmp.conf` |
| `junos/batfish_juniper_system.conf` |
| `junos/batfish_juniper_tacplus.conf` |
| `junos/batfish_junos-srx-1.cfg` |
| `junos/batfish_junos-srx-2.cfg` |

---

## Apache 2.0 — Palo Alto Networks iron-skillet

Source: https://github.com/PaloAltoNetworks/iron-skillet  
Licence: [Apache License 2.0](https://github.com/PaloAltoNetworks/iron-skillet/blob/master/LICENSE)  
Copyright © Palo Alto Networks.  
These are day-one best-practice hardened baseline configurations (template with placeholder IPs/passwords).

| File | Branch |
|------|--------|
| `palo_alto/iron_skillet_panos_full.xml` | panos_v8.x (earlier branch) |
| `palo_alto/iron_skillet_panos91_full.xml` | panos_v9.1 |
| `palo_alto/iron_skillet_panos100_full.xml` | panos_v10.0 |

---

## Community GitHub repositories (MIT / Apache 2.0 / permissive)

These files originate from public GitHub repositories shared by network engineers
for tutorial, lab, or demo purposes. Specific licences are noted per repo.

### Nick Buraglio — SR OS lab configs

Source: https://github.com/buraglio (public repos, various)  
Licence: MIT / permissive (per repo)  
The TiMOS copyright header embedded by the Nokia OS in every config export refers to
the router software, not to the configuration content.

| File |
|------|
| `nokia_sros/buraglio_vsr1.cfg` |
| `nokia_sros/buraglio_vsr2.cfg` |
| `nokia_sros/buraglio_vsr-nrc1.cfg` |
| `nokia_sros/buraglio_vsr-nrc1-flat.cfg` |
| `nokia_sros/buraglio_vsr-nrc2.cfg` |
| `nokia_sros/buraglio_vst1_flat.cfg` |

### Roman Dodin (hellt) — SR OS baseline configs

Source: https://github.com/hellt / https://github.com/srl-labs  
Licence: MIT / Apache 2.0 (per repo)

| File |
|------|
| `nokia_sros/hellt_baseline.cfg` |
| `nokia_sros/hellt_R1.cfg` |

### Karneliuk — SR OS lab config

Source: https://github.com/karneliuk-com (public tutorials)  
Licence: MIT (per repo)

| File |
|------|
| `nokia_sros/karneliuk_SR1.cfg` |

### learn-srlinux.io — SR Linux MPLS lab configs

Source: https://github.com/srl-labs/learn-srlinux  
Licence: MIT (https://github.com/srl-labs/learn-srlinux/blob/master/LICENSE)

| File |
|------|
| `nokia_srl/learn_srlinux_mpls_srl1.cfg` |
| `nokia_srl/learn_srlinux_mpls_srl2.cfg` |
| `nokia_srl/learn_srlinux_mpls_srl3.cfg` |

### ciscoconfparse — Cisco IOS/ASA examples

Source: https://github.com/mpenning/ciscoconfparse (Mike Pennington)  
Licence: Apache 2.0 / MIT  
The `sample_01.asa` header `Written by mpenning` identifies this as from Mike Pennington's
ciscoconfparse project, which uses MIT / Apache 2.0 licensing.

| File |
|------|
| `cisco_asa/sample_01.asa` |
| `cisco_ios/sample_01.ios` |
| `cisco_ios/sample_02.ios` |
| `cisco_ios/sample_03.ios` |
| `cisco_ios/sample_04.ios` |
| `cisco_ios/sample_07.ios` |
| `cisco_ios/sample_08.ios` |
| `cisco_ios/sample_09.ios` |
| `cisco_ios/sample_10.ios` |

### Cisco DevNet — NX-OS sandbox config

Source: https://github.com/CiscoDevNet/netconf-examples/blob/master/netconf-101/sandbox-nexus9kv-config.txt  
Licence: [Apache License 2.0](https://github.com/CiscoDevNet/netconf-examples/blob/master/LICENSE)  
A real Cisco DevNet sandbox N9K running-config (Nexus 9Kv, NX-OS 7.0.3.I2.1). Contains several intentional security weaknesses (telnet, no password strength-check, no AAA login, weak TACACS key) useful for negative-case testing.

| File |
|------|
| `cisco_nxos/cisco_devnet_n9k_sandbox.conf` |
| `cisco_nxos/sample_01.nxos` |

### Fortinet community / Azure / AWS examples

| File | Source |
|------|--------|
| `fortios/jsk_fortigate0.conf` | Public GitHub community FortiGate config (`jsk-*` user repos) |
| `fortios/azure_vpn_fortigate_full.conf` | Azure VPN FortiGate community template (GitHub) |
| `fortios/fortinet_aws_ha_passive.conf` | Fortinet AWS HA deployment template (GitHub, Apache 2.0 Fortinet templates) |

### Palo Alto — Mastering PAN book companion

| File | Source |
|------|--------|
| `palo_alto/mastering_pan_ch7.xml` | Community Palo Alto PAN-OS 9.x sample (public GitHub / book companion) |

### JunOS community samples

| File | Source |
|------|--------|
| `junos/sample_01.junos` | Public GitHub JunOS community example |
| `junos/sample_03.junos` | Public GitHub JunOS community example |
| `junos/sample_04.junos` | Public GitHub JunOS community example |

---

## Public pastes (no explicit licence)

These files were posted publicly on Pastebin.com by their authors. They are anonymized
community configs shared for troubleshooting or learning. No explicit licence was stated
by the poster; they are included here for testing purposes only.

| File |
|------|
| `junos/pastebin_junos_core_switch_set.conf` |
| `junos/pastebin_junos_srx_curly.conf` |
| `junos/pastebin_p04_full.conf` |
| `junos/pastebin_srx300_curly.conf` |

---

## Apache 2.0 — Batfish project (IOS-XE and IOS-XR unit test configs)

Source: https://github.com/batfish/batfish  
Licence: [Apache License 2.0](https://github.com/batfish/batfish/blob/master/LICENSE)  
Copyright © Batfish contributors.  
These are minimal grammar unit-test fixtures. They are placed in `cisco_xe/` and `cisco_xr/` for
profile-specific testing; use `--vendor cisco_xe` / `--vendor cisco_xr` when auditing them because
their generic IOS syntax auto-detects as `cisco_ios`.

| File |
|------|
| `cisco_xe/batfish_aaaAuthenticationIos.conf` |
| `cisco_xe/batfish_aaaNewmodel.conf` |
| `cisco_xe/batfish_aclIos.conf` |
| `cisco_xe/batfish_ios_aaa_group_server.conf` |
| `cisco_xe/batfish_ios_bgp_multiple_routers.conf` |
| `cisco_xe/batfish_ios_xe_crypto_parsing.conf` |
| `cisco_xe/batfish_ios_xe_eigrp_to_bgp.conf` |
| `cisco_xe/batfish_ios_xe_zone_default_behavior.conf` |
| `cisco_xe/batfish_iosxe_vasi_interface.conf` |
| `cisco_xr/batfish_bgp-aggregate.conf` |
| `cisco_xr/batfish_xr-bfd.conf` |
| `cisco_xr/batfish_xr-bgp.conf` |
| `cisco_xr/batfish_xr-dscp.conf` |

---

## Apache 2.0 — networktocode/ntc-rosetta

Source: https://github.com/networktocode/ntc-rosetta  
Licence: [Apache License 2.0](https://github.com/networktocode/ntc-rosetta/blob/develop/LICENSE)

| File |
|------|
| `cisco_xe/ntc_rosetta_ios_config.conf` |

---

## MIT — ters-golemi/IOS-XR-Segment-Routing

Source: https://github.com/ters-golemi/IOS-XR-Segment-Routing  
Licence: MIT  
Realistic IOS-XR SP configuration templates for core, edge, and aggregation routers.

| File |
|------|
| `cisco_xr/ters_golemi_CORE-1-complete-config.conf` |
| `cisco_xr/ters_golemi_aggregation-router-template.conf` |
| `cisco_xr/ters_golemi_core-router-template.conf` |
| `cisco_xr/ters_golemi_edge-router-template.conf` |

---

## MIT — napalm-automation-community/napalm-f5

Source: https://github.com/napalm-automation-community/napalm-f5  
Licence: [MIT](https://github.com/napalm-automation-community/napalm-f5/blob/master/LICENSE)  
These are BIG-IP TMSH unit-test fixtures from the NAPALM F5 driver project.

| File |
|------|
| `f5_bigip/napalm_f5_initial.conf` |
| `f5_bigip/napalm_f5_merge_good.conf` |
| `f5_bigip/napalm_f5_new_good.conf` |

---

## Public gist (no explicit licence)

This file was posted publicly on GitHub Gist by its author for reference purposes.
Included here for testing only.

| File | Source |
|------|--------|
| `huawei_vrp/glw119_s5735s_switch.conf` | https://gist.github.com/glw119/888e318fd1f49ec4063fc016e67c7079 — Huawei S5735S-L8T4S home network switch |

---

## Note for downstream redistribution

If you publish a fork or derivative work:
- The **synthetic** files are unrestricted (CC0).
- The **Apache 2.0** files (Batfish, iron-skillet) may be redistributed with the
  required licence notice.
- The **community GitHub** files should be checked against their specific repository
  licences at the time of redistribution.
- The **public paste** files should be replaced with new synthetic samples if
  redistribution is intended to be unambiguous.
