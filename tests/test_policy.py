"""Tests for policy overlays (exemptions + severity overrides)."""

from __future__ import annotations

from pathlib import Path

import pytest

from fluff.engine.models import Severity, Status
from fluff.engine.runner import audit
from fluff.parsers.router import load_config
from fluff.policy import Policy, apply_policy, load_policy

FIXTURES = Path(__file__).parent / "fixtures"


def _bad_telnet_result(policy: Policy | None = None):
    path = FIXTURES / "cisco_ios" / "bad_telnet.conf"
    return audit(load_config(path, "cisco_ios"), policy=policy)


def test_load_policy_yaml(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        """
exemptions:
  - check_id: IOS-MGMT-003
    reason: lab telnet
severity_overrides:
  IOS-SNMP-001: critical
  SVC-005: high
""",
        encoding="utf-8",
    )
    policy = load_policy(path)
    assert len(policy.exemptions) == 1
    assert policy.exemptions[0].check_id == "IOS-MGMT-003"
    assert policy.severity_overrides["IOS-SNMP-001"] == Severity.CRITICAL
    assert policy.severity_overrides["SVC-005"] == Severity.HIGH


def test_load_policy_json(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text(
        '{"exemptions": [{"generic_id": "MGMT-003", "reason": "ok"}],'
        ' "severity_overrides": {"IOS-SVC-001": "low"}}',
        encoding="utf-8",
    )
    policy = load_policy(path)
    assert policy.exemptions[0].generic_id == "MGMT-003"
    assert policy.severity_overrides["IOS-SVC-001"] == Severity.LOW


def test_invalid_severity_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("severity_overrides:\n  IOS-SVC-001: banana\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid severity"):
        load_policy(path)


def test_exemption_marks_fail_as_exempt() -> None:
    policy = Policy()
    from fluff.policy import Exemption

    policy.exemptions = [
        Exemption(check_id="IOS-MGMT-003", reason="Accepted until cutover")
    ]
    result = _bad_telnet_result(policy)
    finding = next(f for f in result.findings if f.check_id == "IOS-MGMT-003")
    assert finding.status == Status.EXEMPT
    assert finding.exemption_reason == "Accepted until cutover"
    assert result.summary.exempt >= 1


def test_hostname_scoped_exemption() -> None:
    from fluff.policy import Exemption

    # bad_telnet hostname is typically set in fixture — check what it is
    bare = _bad_telnet_result()
    hostname = bare.summary.hostname
    assert hostname  # fixture should have a hostname

    policy = Policy(
        exemptions=[
            Exemption(check_id="IOS-MGMT-003", hostname="other-host", reason="wrong host")
        ]
    )
    result = _bad_telnet_result(policy)
    finding = next(f for f in result.findings if f.check_id == "IOS-MGMT-003")
    assert finding.status == Status.FAIL

    policy2 = Policy(
        exemptions=[
            Exemption(check_id="IOS-MGMT-003", hostname=hostname, reason="right host")
        ]
    )
    result2 = _bad_telnet_result(policy2)
    finding2 = next(f for f in result2.findings if f.check_id == "IOS-MGMT-003")
    assert finding2.status == Status.EXEMPT


def test_severity_override_by_check_id() -> None:
    from fluff.policy import Exemption

    policy = Policy(severity_overrides={"IOS-SNMP-001": Severity.CRITICAL})
    result = _bad_telnet_result(policy)
    finding = next(f for f in result.findings if f.check_id == "IOS-SNMP-001")
    assert finding.severity == Severity.CRITICAL


def test_apply_policy_does_not_exempt_passes() -> None:
    from fluff.engine.models import Finding
    from fluff.policy import Exemption

    finding = Finding(
        check_id="IOS-SVC-001",
        generic_id="SVC-001",
        title="t",
        description="",
        vendor="cisco",
        profile="cisco_ios",
        status=Status.PASS,
        severity=Severity.MEDIUM,
        cis=[],
        evidence=[],
        remediation="",
    )
    policy = Policy(exemptions=[Exemption(check_id="IOS-SVC-001", reason="n/a")])
    apply_policy([finding], "R1", policy)
    assert finding.status == Status.PASS
