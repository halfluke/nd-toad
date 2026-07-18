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


def test_audit_fails_exit_code_on_findings() -> None:
    reset_banner_for_tests()
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["audit", "-i", str(FIXTURES / "cisco_ios" / "bad_telnet.conf"), "--hide-manual"],
    )
    assert result.exit_code == 2


def test_audit_exit_zero_with_fail_on_never() -> None:
    reset_banner_for_tests()
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "audit",
            "-i",
            str(FIXTURES / "cisco_ios" / "bad_telnet.conf"),
            "--fail-on",
            "never",
            "--json",
        ],
    )
    assert result.exit_code == 0


def test_audit_check_id_filter_limits_fail_on() -> None:
    """Exit code only considers findings matching --check-id."""
    reset_banner_for_tests()
    runner = CliRunner()
    # IOS-SVC-001 is a forbidden_regex for tcp-small-servers; good configs pass it,
    # but we target a check that fails on bad_telnet.
    failing = runner.invoke(
        app,
        [
            "audit",
            "-i",
            str(FIXTURES / "cisco_ios" / "bad_telnet.conf"),
            "--check-id",
            "IOS-MGMT-003",
            "--json",
        ],
    )
    assert failing.exit_code == 2

    passing_filter = runner.invoke(
        app,
        [
            "audit",
            "-i",
            str(FIXTURES / "cisco_ios" / "bad_telnet.conf"),
            "--check-id",
            "IOS-SVC-001",
            "--json",
        ],
    )
    # SVC-001 typically passes even on bad_telnet (no tcp-small-servers)
    assert passing_filter.exit_code == 0


def test_explain_check() -> None:
    reset_banner_for_tests()
    runner = CliRunner()
    result = runner.invoke(app, ["explain", "IOS-MGMT-003"])
    assert result.exit_code == 0
    assert "IOS-MGMT-003" in result.stdout
    assert "Probe:" in result.stdout


def test_explain_unknown_check() -> None:
    reset_banner_for_tests()
    runner = CliRunner()
    result = runner.invoke(app, ["explain", "DOES-NOT-EXIST-999"])
    assert result.exit_code == 1


def test_invalid_yaml_policy_exits_cleanly(tmp_path: Path) -> None:
    reset_banner_for_tests()
    policy = tmp_path / "bad.yaml"
    policy.write_text("exemptions: [\n  - check_id: IOS-MGMT-003\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "audit",
            "-i",
            str(FIXTURES / "cisco_ios" / "good.conf"),
            "--policy",
            str(policy),
            "--json",
        ],
    )
    assert result.exit_code == 1
    assert "Invalid policy file" in result.stderr
    assert "Traceback" not in result.stderr


def test_explain_hook_probe_shows_module() -> None:
    reset_banner_for_tests()
    runner = CliRunner()
    result = runner.invoke(app, ["explain", "IOS-MGMT-002"])
    assert result.exit_code == 0
    assert "hook: fluff.hooks.mgmt_acl.check_ios_http_access_class" in result.stdout


def test_status_pass_filter_not_hidden_by_show_pass_default() -> None:
    reset_banner_for_tests()
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "audit",
            "-i",
            str(FIXTURES / "cisco_ios" / "good.conf"),
            "--status",
            "pass",
            "--fail-on",
            "never",
        ],
    )
    assert result.exit_code == 0
    assert "IOS-" in result.stdout


def test_audit_with_policy_exemptions(tmp_path: Path) -> None:
    reset_banner_for_tests()
    policy = tmp_path / "policy.yaml"
    # Exempt every failing check pattern is hard; exempt the known telnet check
    # and use --fail-on never isn't the point — we want fewer fails. Instead
    # verify exempt appears in JSON.
    policy.write_text(
        """
exemptions:
  - check_id: IOS-MGMT-003
    reason: temporary
severity_overrides:
  IOS-SNMP-001: critical
""",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "audit",
            "-i",
            str(FIXTURES / "cisco_ios" / "bad_telnet.conf"),
            "--policy",
            str(policy),
            "--json",
            "--fail-on",
            "never",
        ],
    )
    assert result.exit_code == 0
    assert "exempt" in result.stdout
    assert "temporary" in result.stdout
    assert '"severity": "critical"' in result.stdout or '"severity":"critical"' in result.stdout
