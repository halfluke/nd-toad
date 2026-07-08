"""CLI smoke tests."""

from __future__ import annotations

from pathlib import Path
from typer.testing import CliRunner

from fluff.banner import reset_banner_for_tests
from fluff.cli import app

FIXTURES = Path(__file__).parent / "fixtures"


def test_audit_prints_ascii_banner() -> None:
    reset_banner_for_tests()
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["audit", "-i", str(FIXTURES / "cisco_ios" / "good.conf"), "--hide-manual"],
    )
    assert result.exit_code == 0
    assert "@..@" in result.stdout
    assert "nd-toad — Network Device Toad Auditing Tool" in result.stdout


def test_audit_json_skips_banner() -> None:
    reset_banner_for_tests()
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["audit", "-i", str(FIXTURES / "cisco_ios" / "good.conf"), "--json"],
    )
    assert result.exit_code == 0
    assert "@..@" not in result.stdout
