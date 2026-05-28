"""Tests for the audit engine — probes, runner, and findings."""

from __future__ import annotations

from pathlib import Path

import pytest

from fluff.engine.models import Status, Severity
from fluff.engine.probe import ProbeResult, run_probe
from fluff.engine.runner import audit
from fluff.parsers.base import TextBasedConfig
from fluff.parsers.router import load_config

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _make_config(text: str, profile: str = "cisco_ios", vendor: str = "cisco") -> TextBasedConfig:
    return TextBasedConfig(
        vendor=vendor,
        profile=profile,
        path=Path("/dev/null"),
        text=text,
    )


# ──────────────────────────────────────────── probe unit tests ────────

class TestForbiddenRegex:
    def test_fail_when_found(self) -> None:
        cfg = _make_config("transport input telnet")
        result = run_probe({"type": "forbidden_regex", "pattern": r"transport input.*telnet"}, cfg)
        assert result.status == Status.FAIL
        assert result.evidence

    def test_pass_when_not_found(self) -> None:
        cfg = _make_config("transport input ssh")
        result = run_probe({"type": "forbidden_regex", "pattern": r"transport input.*telnet"}, cfg)
        assert result.status == Status.PASS
        assert result.evidence == []


class TestRequiredRegex:
    def test_pass_when_found(self) -> None:
        cfg = _make_config("aaa new-model")
        result = run_probe({"type": "required_regex", "pattern": r"aaa new-model"}, cfg)
        assert result.status == Status.PASS
        assert result.evidence

    def test_fail_when_missing(self) -> None:
        cfg = _make_config("no aaa")
        result = run_probe({"type": "required_regex", "pattern": r"aaa new-model"}, cfg)
        assert result.status == Status.FAIL

    def test_evidence_contains_matched_line(self) -> None:
        cfg = _make_config("ip ssh version 2\nhostname R1")
        result = run_probe({"type": "required_regex", "pattern": r"ip ssh version 2"}, cfg)
        assert result.status == Status.PASS
        assert "ip ssh version 2" in result.evidence[0]


class TestManualProbe:
    def test_always_manual(self) -> None:
        cfg = _make_config("anything")
        result = run_probe({"type": "manual"}, cfg)
        assert result.status == Status.MANUAL
        assert result.evidence == []


# ──────────────────────────────────── full audit on fixtures ────────

class TestAuditCiscoIOSGood:
    @pytest.fixture(autouse=True)
    def result(self) -> None:
        path = FIXTURES_DIR / "cisco_ios" / "good.conf"
        config = load_config(path, "cisco_ios")
        self.audit_result = audit(config)

    def test_has_findings(self) -> None:
        assert len(self.audit_result.findings) > 0

    def test_no_fail_on_good_config(self) -> None:
        failed = [f for f in self.audit_result.findings if f.status == Status.FAIL]
        assert failed == [], f"Unexpected failures on good config: {[f.check_id for f in failed]}"

    def test_summary_hostname(self) -> None:
        assert self.audit_result.summary.hostname == "CORE-RTR-01"

    def test_compliance_score_high(self) -> None:
        assert self.audit_result.summary.compliance_score >= 90.0

    def test_has_cis_refs(self) -> None:
        findings_with_cis = [f for f in self.audit_result.findings if f.cis]
        assert len(findings_with_cis) > 0

    def test_manual_entries_present(self) -> None:
        manual = [f for f in self.audit_result.findings if f.status == Status.MANUAL]
        assert len(manual) >= 1


class TestAuditCiscoIOSBadTelnet:
    @pytest.fixture(autouse=True)
    def result(self) -> None:
        path = FIXTURES_DIR / "cisco_ios" / "bad_telnet.conf"
        config = load_config(path, "cisco_ios")
        self.audit_result = audit(config)

    def test_telnet_fails(self) -> None:
        telnet_fail = [
            f for f in self.audit_result.findings
            if f.check_id == "IOS-MGMT-003" and f.status == Status.FAIL
        ]
        assert telnet_fail, "IOS-MGMT-003 (telnet) should fail on bad_telnet config"

    def test_snmp_default_fails(self) -> None:
        snmp_fail = [
            f for f in self.audit_result.findings
            if f.check_id == "IOS-SNMP-001" and f.status == Status.FAIL
        ]
        assert snmp_fail, "IOS-SNMP-001 should fail on config with public/private communities"

    def test_compliance_score_low(self) -> None:
        assert self.audit_result.summary.compliance_score < 60.0


class TestAuditCiscoIOSAnyAny:
    @pytest.fixture(autouse=True)
    def result(self) -> None:
        path = FIXTURES_DIR / "cisco_ios" / "bad_any_any.conf"
        config = load_config(path, "cisco_ios")
        self.audit_result = audit(config)

    def test_any_any_fails(self) -> None:
        any_any_fail = [
            f for f in self.audit_result.findings
            if f.check_id == "IOS-POLICY-001" and f.status == Status.FAIL
        ]
        assert any_any_fail, "IOS-POLICY-001 should fail on config with permit ip any any"

    def test_evidence_contains_matching_line(self) -> None:
        for f in self.audit_result.findings:
            if f.check_id == "IOS-POLICY-001":
                assert any("permit ip any any" in ev.lower() for ev in f.evidence)


# ─────────────────────────────────── audit summary structure ────────

def test_audit_result_summary_fields() -> None:
    path = FIXTURES_DIR / "cisco_ios" / "good.conf"
    config = load_config(path, "cisco_ios")
    result = audit(config)
    s = result.summary
    assert s.total == s.passed + s.failed + s.manual + s.not_applicable
    assert s.profile == "cisco_ios"
    assert s.input_file.endswith("good.conf")


def test_all_fixture_profiles_audit_without_crash() -> None:
    """Smoke test: every good.conf fixture must produce an AuditResult."""
    profiles = [
        "cisco_ios", "cisco_asa", "cisco_nxos", "cisco_ftd",
        "arista_eos", "hpe_aruba", "fortios", "junos",
        "palo_alto", "checkpoint", "sophos_xg", "sonicwall",
        "nokia_sros", "nokia_srl",
    ]
    for profile in profiles:
        path = FIXTURES_DIR / profile / "good.conf"
        if not path.exists():
            continue
        config = load_config(path, profile)
        result = audit(config)
        assert result is not None, f"audit() returned None for {profile}"
        assert result.summary.profile == profile
