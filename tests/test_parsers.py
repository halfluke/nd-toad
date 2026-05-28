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


def test_unknown_profile_raises() -> None:
    with pytest.raises(ValueError, match="Unknown profile"):
        load_config(Path("/dev/null"), "nonexistent_vendor")
