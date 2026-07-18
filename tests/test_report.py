"""Tests for JSON report generation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fluff.engine.runner import audit
from fluff.parsers.router import load_config
from fluff.report.json_report import render, write_json

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _get_ios_result():
    path = FIXTURES_DIR / "cisco_ios" / "good.conf"
    config = load_config(path, "cisco_ios")
    return audit(config)


def test_render_returns_dict() -> None:
    result = _get_ios_result()
    data = render(result)
    assert isinstance(data, dict)
    assert "summary" in data
    assert "findings" in data
    assert "cis_summary" in data


def test_render_summary_fields() -> None:
    result = _get_ios_result()
    data = render(result)
    s = data["summary"]
    assert s["profile"] == "cisco_ios"
    assert isinstance(s["compliance_score"], float)
    assert s["total"] >= 0


def test_write_json_returns_valid_json(tmp_path: Path) -> None:
    result = _get_ios_result()
    out_file = tmp_path / "report.json"
    write_json(result, out_file)
    assert out_file.exists()
    parsed = json.loads(out_file.read_text())
    assert parsed["summary"]["profile"] == "cisco_ios"


def test_write_json_to_string() -> None:
    result = _get_ios_result()
    text = write_json(result, None)
    parsed = json.loads(text)
    assert "findings" in parsed


def test_cis_summary_prefers_exempt_over_pass() -> None:
    from fluff.engine.models import CISRef, Finding, Severity, Status
    from fluff.engine.models import AuditResult, AuditSummary
    from fluff.report.json_report import render

    cis = [CISRef(benchmark="CIS Cisco IOS 17", control="3.1.1", level=1)]
    findings = [
        Finding(
            check_id="A",
            generic_id="G",
            title="pass",
            description="",
            vendor="cisco",
            profile="cisco_ios",
            status=Status.PASS,
            severity=Severity.MEDIUM,
            cis=cis,
            evidence=[],
            remediation="",
        ),
        Finding(
            check_id="B",
            generic_id="G",
            title="exempt",
            description="",
            vendor="cisco",
            profile="cisco_ios",
            status=Status.EXEMPT,
            severity=Severity.MEDIUM,
            cis=cis,
            evidence=[],
            remediation="",
            exemption_reason="accepted",
        ),
    ]
    result = AuditResult(
        summary=AuditSummary(
            profile="cisco_ios",
            hostname="R1",
            input_file="x.conf",
            total=2,
            passed=1,
            failed=0,
            manual=0,
            not_applicable=0,
            compliance_score=100.0,
            exempt=1,
        ),
        findings=findings,
    )
    data = render(result)
    assert data["cis_summary"]["CIS Cisco IOS 17 — 3.1.1"]["status"] == "exempt"


def test_cis_summary_aggregates_correctly() -> None:
    result = _get_ios_result()
    data = render(result)
    cis_summary = data["cis_summary"]
    assert isinstance(cis_summary, dict)
    for key, val in cis_summary.items():
        assert "status" in val
        assert "findings" in val
        assert val["status"] in ("pass", "fail", "manual", "not_applicable")


def test_findings_have_required_keys() -> None:
    result = _get_ios_result()
    data = render(result)
    for finding in data["findings"]:
        for key in ("check_id", "generic_id", "title", "status", "severity", "cis", "evidence", "remediation"):
            assert key in finding, f"Missing key '{key}' in finding {finding.get('check_id')}"
