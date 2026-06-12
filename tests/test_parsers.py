"""Tests for vendor parser adapters."""

from __future__ import annotations

from pathlib import Path

import pytest

from fluff.parsers.router import load_config

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestCiscoIOSParser:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        path = FIXTURES_DIR / "cisco_ios" / "good.conf"
        self.config = load_config(path, "cisco_ios")

    def test_vendor_and_profile(self) -> None:
        assert self.config.vendor == "cisco"
        assert self.config.profile == "cisco_ios"

    def test_hostname_extraction(self) -> None:
        assert self.config.get_hostname() == "CORE-RTR-01"

    def test_find_lines(self) -> None:
        lines = self.config.find_lines(r"ntp server")
        assert len(lines) >= 1

    def test_find_blocks(self) -> None:
        blocks = self.config.find_blocks(r"^line vty")
        assert len(blocks) >= 1
        # Each block should have children
        assert any(len(b.children) > 0 for b in blocks)

    def test_text_attribute(self) -> None:
        assert "hostname" in self.config.text.lower()


class TestCiscoASAParser:
    def test_loads_and_detects(self) -> None:
        path = FIXTURES_DIR / "cisco_asa" / "good.conf"
        config = load_config(path, "cisco_asa")
        assert config.profile == "cisco_asa"
        assert config.vendor == "cisco"

    def test_hostname_extraction(self) -> None:
        path = FIXTURES_DIR / "cisco_asa" / "good.conf"
        config = load_config(path, "cisco_asa")
        assert config.get_hostname() == "FW-ASA-01"


class TestFortiOSParser:
    def test_loads(self) -> None:
        path = FIXTURES_DIR / "fortios" / "good.conf"
        config = load_config(path, "fortios")
        assert config.profile == "fortios"

    def test_hostname_extraction(self) -> None:
        path = FIXTURES_DIR / "fortios" / "good.conf"
        config = load_config(path, "fortios")
        assert config.get_hostname() == "FW-FORTI-01"


class TestJunOSParser:
    def test_loads(self) -> None:
        path = FIXTURES_DIR / "junos" / "good.conf"
        config = load_config(path, "junos")
        assert config.profile == "junos"

    def test_hostname_extraction(self) -> None:
        path = FIXTURES_DIR / "junos" / "good.conf"
        config = load_config(path, "junos")
        assert config.get_hostname() == "JNX-ROUTER-01"

    def test_is_set_format(self) -> None:
        path = FIXTURES_DIR / "junos" / "good.conf"
        config = load_config(path, "junos")
        assert config._is_set_format is True


class TestPaloAltoParser:
    def test_loads(self) -> None:
        path = FIXTURES_DIR / "palo_alto" / "good.conf"
        config = load_config(path, "palo_alto")
        assert config.profile == "palo_alto"

    def test_hostname_extraction(self) -> None:
        path = FIXTURES_DIR / "palo_alto" / "good.conf"
        config = load_config(path, "palo_alto")
        assert config.get_hostname() == "PAN-FW-01"


class TestNokiaSRLParser:
    def test_loads_json(self) -> None:
        path = FIXTURES_DIR / "nokia_srl" / "good.conf"
        config = load_config(path, "nokia_srl")
        assert config.profile == "nokia_srl"

    def test_hostname_extraction(self) -> None:
        path = FIXTURES_DIR / "nokia_srl" / "good.conf"
        config = load_config(path, "nokia_srl")
        assert config.get_hostname() == "SRL-NODE-01"


class TestCiscoXEParser:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        path = FIXTURES_DIR / "cisco_xe" / "good.conf"
        self.config = load_config(path, "cisco_xe")

    def test_vendor_and_profile(self) -> None:
        assert self.config.vendor == "cisco"
        assert self.config.profile == "cisco_xe"

    def test_hostname_extraction(self) -> None:
        assert self.config.get_hostname() == "XE-DIST-01"

    def test_find_lines(self) -> None:
        lines = self.config.find_lines(r"ntp server")
        assert len(lines) >= 1

    def test_text_attribute(self) -> None:
        assert "platform type" in self.config.text


class TestCiscoXRParser:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        path = FIXTURES_DIR / "cisco_xr" / "good.conf"
        self.config = load_config(path, "cisco_xr")

    def test_vendor_and_profile(self) -> None:
        assert self.config.vendor == "cisco"
        assert self.config.profile == "cisco_xr"

    def test_hostname_extraction(self) -> None:
        assert self.config.get_hostname() == "XR-CORE-01"

    def test_find_lines(self) -> None:
        lines = self.config.find_lines(r"ssh server v2")
        assert len(lines) >= 1

    def test_text_attribute(self) -> None:
        assert "IOS XR" in self.config.text


class TestHuaweiVRPParser:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        path = FIXTURES_DIR / "huawei_vrp" / "good.conf"
        self.config = load_config(path, "huawei_vrp")

    def test_vendor_and_profile(self) -> None:
        assert self.config.vendor == "huawei"
        assert self.config.profile == "huawei_vrp"

    def test_hostname_extraction(self) -> None:
        assert self.config.get_hostname() == "VRP-CORE-01"

    def test_find_lines(self) -> None:
        lines = self.config.find_lines(r"stelnet server enable")
        assert len(lines) >= 1

    def test_text_attribute(self) -> None:
        assert "sysname" in self.config.text


class TestF5BigIPParser:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        path = FIXTURES_DIR / "f5_bigip" / "good.conf"
        self.config = load_config(path, "f5_bigip")

    def test_vendor_and_profile(self) -> None:
        assert self.config.vendor == "f5"
        assert self.config.profile == "f5_bigip"

    def test_hostname_extraction(self) -> None:
        # get_hostname extracts from "hostname <fqdn>"
        hostname = self.config.get_hostname()
        assert hostname is not None
        assert "bigip" in hostname.lower()

    def test_find_lines(self) -> None:
        lines = self.config.find_lines(r"TMSH-VERSION")
        assert len(lines) >= 1

    def test_text_attribute(self) -> None:
        assert "sys global-settings" in self.config.text


class TestVmwareVeloCloudParser:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        path = FIXTURES_DIR / "vmware_velocloud" / "good.json"
        self.config = load_config(path, "vmware_velocloud")

    def test_vendor_and_profile(self) -> None:
        assert self.config.vendor == "vmware"
        assert self.config.profile == "vmware_velocloud"

    def test_hostname_extraction(self) -> None:
        assert self.config.get_hostname() == "EDGE-BRANCH-01"

    def test_flat_text_has_edge_keys(self) -> None:
        assert "edge.edgeName = EDGE-BRANCH-01" in self.config.text

    def test_flat_text_has_firewall_keys(self) -> None:
        assert "firewall.stateful_firewall_enabled" in self.config.text

    def test_flat_text_has_effective_ntp(self) -> None:
        assert "effective.ntp.enabled = True" in self.config.text

    def test_find_lines(self) -> None:
        lines = self.config.find_lines(r"effective\.ntp\.enabled")
        assert len(lines) >= 1


class TestVmwareNSXParser:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        path = FIXTURES_DIR / "vmware_nsx" / "good.json"
        self.config = load_config(path, "vmware_nsx")

    def test_vendor_and_profile(self) -> None:
        assert self.config.vendor == "vmware"
        assert self.config.profile == "vmware_nsx"

    def test_hostname_extraction(self) -> None:
        hostname = self.config.get_hostname()
        assert hostname is not None
        assert "nsx" in hostname.lower()

    def test_profile_marker_in_flat_text(self) -> None:
        assert "_nd_toad_profile = vmware_nsx" in self.config.text

    def test_flat_text_has_ssh_key(self) -> None:
        assert "ssh_service.service_properties.running" in self.config.text

    def test_flat_text_has_auth_policy(self) -> None:
        assert "auth_policy.minimum_password_length" in self.config.text

    def test_find_lines(self) -> None:
        lines = self.config.find_lines(r"global_config\.fips_enabled")
        assert len(lines) >= 1


def test_unknown_profile_raises() -> None:
    with pytest.raises(ValueError, match="Unknown profile"):
        load_config(Path("/dev/null"), "nonexistent_vendor")
