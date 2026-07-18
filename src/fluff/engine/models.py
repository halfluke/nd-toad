"""Core data models for findings, audit results, and CIS references."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    MANUAL = "manual"
    MANUAL_FP_RISK = "manual_fp_risk"
    NOT_APPLICABLE = "not_applicable"
    EXEMPT = "exempt"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def _missing_(cls, value: object) -> "Severity":
        return cls.MEDIUM


@dataclass
class CISRef:
    benchmark: str
    control: str
    level: int

    def as_dict(self) -> dict:
        return {"benchmark": self.benchmark, "control": self.control, "level": self.level}


@dataclass
class Finding:
    check_id: str       # profile-specific ID, e.g. "IOS-MGMT-001"
    generic_id: str     # cross-vendor generic ID, e.g. "MGMT-001"
    title: str
    description: str
    vendor: str
    profile: str
    status: Status
    severity: Severity
    cis: list[CISRef]
    evidence: list[str]
    remediation: str
    exemption_reason: str = ""

    def as_dict(self) -> dict:
        data = {
            "check_id": self.check_id,
            "generic_id": self.generic_id,
            "title": self.title,
            "description": self.description,
            "vendor": self.vendor,
            "profile": self.profile,
            "status": self.status.value,
            "severity": self.severity.value,
            "cis": [c.as_dict() for c in self.cis],
            "evidence": self.evidence,
            "remediation": self.remediation,
        }
        if self.exemption_reason:
            data["exemption_reason"] = self.exemption_reason
        return data


@dataclass
class AuditSummary:
    profile: str
    hostname: str | None
    input_file: str
    total: int
    passed: int
    failed: int
    manual: int
    not_applicable: int
    compliance_score: float  # percentage of automated checks passing
    exempt: int = 0

    def as_dict(self) -> dict:
        return {
            "profile": self.profile,
            "hostname": self.hostname,
            "input_file": self.input_file,
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "manual": self.manual,
            "not_applicable": self.not_applicable,
            "exempt": self.exempt,
            "compliance_score": self.compliance_score,
        }


@dataclass
class AuditResult:
    summary: AuditSummary
    findings: list[Finding]

    def as_dict(self) -> dict:
        return {
            "summary": self.summary.as_dict(),
            "findings": [f.as_dict() for f in self.findings],
        }
