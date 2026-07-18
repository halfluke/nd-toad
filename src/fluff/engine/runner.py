"""
Audit runner: load YAML checks → execute probes → merge CIS catalog manual entries.

Execution order per profile:
  1. Load ``checks/vendors/{profile}.yaml`` — automated probes
  2. Execute each probe against the ParsedConfig
  3. Load ``checks/cis_catalog.yaml`` — all L1 controls for the profile
  4. Emit ``Status.MANUAL`` for any L1 control not covered by an automated probe
  5. Build AuditResult with summary statistics
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from fluff.engine.models import (
    AuditResult,
    AuditSummary,
    CISRef,
    Finding,
    Severity,
    Status,
)
from fluff.engine.probe import ProbeResult, run_probe

if TYPE_CHECKING:
    from fluff.parsers.base import ParsedConfig
    from fluff.policy import Policy

CHECKS_DIR = Path(__file__).parent.parent / "checks"


# ------------------------------------------------------------------ loaders

def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _load_vendor_checks(profile: str) -> list[dict[str, Any]]:
    data = _load_yaml(CHECKS_DIR / "vendors" / f"{profile}.yaml")
    return data.get("checks", [])


def _load_cis_catalog(profile: str) -> list[dict[str, Any]]:
    data = _load_yaml(CHECKS_DIR / "cis_catalog.yaml")
    return data.get(profile, [])


# ------------------------------------------------------------------ runner

def audit(config: "ParsedConfig", *, policy: "Policy | None" = None) -> AuditResult:
    """Run all checks for *config* and return a structured AuditResult."""
    checks = _load_vendor_checks(config.profile)
    cis_catalog = _load_cis_catalog(config.profile)

    findings: list[Finding] = []
    covered_cis: set[tuple[str, str]] = set()

    for check in checks:
        probe_def: dict[str, Any] = check.get("probe", {"type": "manual"})
        result: ProbeResult = run_probe(probe_def, config)

        cis_refs = [
            CISRef(
                benchmark=c["benchmark"],
                control=str(c["control"]),
                level=int(c.get("level", 1)),
            )
            for c in check.get("cis", [])
        ]

        for ref in cis_refs:
            covered_cis.add((ref.benchmark, ref.control))

        findings.append(
            Finding(
                check_id=check["id"],
                generic_id=check.get("generic_id", check["id"]),
                title=check["title"],
                description=check.get("description", ""),
                vendor=config.vendor,
                profile=config.profile,
                status=result.status,
                severity=Severity(check.get("severity", "medium")),
                cis=cis_refs,
                evidence=result.evidence,
                remediation=check.get("remediation", ""),
            )
        )

    # Add manual entries from the CIS catalog not covered by automated probes
    for control in cis_catalog:
        key = (control["benchmark"], str(control["control"]))
        if key in covered_cis:
            continue
        if control.get("automation", "manual") != "manual":
            continue

        cis_ref = CISRef(
            benchmark=control["benchmark"],
            control=str(control["control"]),
            level=int(control.get("level", 1)),
        )
        findings.append(
            Finding(
                check_id=f"MANUAL-{str(control['control']).replace('.', '-')}",
                generic_id="MANUAL",
                title=control["title"],
                description=control.get("reason", "Requires manual review — cannot be fully automated."),
                vendor=config.vendor,
                profile=config.profile,
                status=Status.MANUAL,
                severity=Severity.INFO,
                cis=[cis_ref],
                evidence=[],
                remediation=control.get("remediation", "Review vendor documentation and CIS benchmark guidance."),
            )
        )

    hostname = config.get_hostname()
    if policy is not None:
        from fluff.policy import apply_policy

        apply_policy(findings, hostname, policy)

    return AuditResult(
        summary=_summarise(config, findings),
        findings=findings,
    )


def _summarise(config: "ParsedConfig", findings: list[Finding]) -> AuditSummary:
    _non_score = (
        Status.MANUAL,
        Status.MANUAL_FP_RISK,
        Status.NOT_APPLICABLE,
        Status.EXEMPT,
    )
    automated = [f for f in findings if f.status not in _non_score]
    passed = sum(1 for f in automated if f.status == Status.PASS)
    failed = sum(1 for f in automated if f.status == Status.FAIL)
    manual_count = sum(1 for f in findings if f.status in (Status.MANUAL, Status.MANUAL_FP_RISK))
    na_count = sum(1 for f in findings if f.status == Status.NOT_APPLICABLE)
    exempt_count = sum(1 for f in findings if f.status == Status.EXEMPT)
    compliance_score = round(passed / len(automated) * 100, 1) if automated else 0.0

    return AuditSummary(
        profile=config.profile,
        hostname=config.get_hostname(),
        input_file=str(config.raw_path),
        total=len(findings),
        passed=passed,
        failed=failed,
        manual=manual_count,
        not_applicable=na_count,
        compliance_score=compliance_score,
        exempt=exempt_count,
    )
