"""
CSV report renderer.

Each row is one finding.  When auditing a directory the rows from every file
are concatenated into a single sheet, making it easy to open in a spreadsheet
and filter/sort across devices.

Columns
-------
file            – basename of the audited config file
profile         – vendor profile (e.g. cisco_ios)
hostname        – detected hostname (empty if not found)
compliance_pct  – overall score for that file (0–100)
check_id        – e.g. IOS-MGMT-001
generic_id      – cross-vendor ID, e.g. MGMT-001
status          – pass / fail / manual / not_applicable
severity        – critical / high / medium / low / info
title           – short check title
cis_controls    – semi-colon-separated list of CIS references
evidence        – offending config lines joined with " | "
remediation     – guidance text
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import IO

from fluff.engine.models import AuditResult

FIELDNAMES = [
    "file",
    "profile",
    "hostname",
    "compliance_pct",
    "check_id",
    "generic_id",
    "status",
    "severity",
    "title",
    "cis_controls",
    "evidence",
    "remediation",
    "exemption_reason",
]


def _rows(result: AuditResult) -> list[dict]:
    s = result.summary
    score = round(s.compliance_score, 1)
    file_name = Path(s.input_file).name
    rows = []
    for f in result.findings:
        cis_labels = "; ".join(
            f"{c.benchmark} {c.control}" for c in f.cis
        )
        rows.append(
            {
                "file": file_name,
                "profile": s.profile,
                "hostname": s.hostname or "",
                "compliance_pct": score,
                "check_id": f.check_id,
                "generic_id": f.generic_id,
                "status": f.status.value,
                "severity": f.severity.value,
                "title": f.title,
                "cis_controls": cis_labels,
                "evidence": " | ".join(f.evidence),
                "remediation": f.remediation,
                "exemption_reason": f.exemption_reason,
            }
        )
    return rows


def write_csv(
    results: AuditResult | list[AuditResult],
    out: Path | IO | None = None,
) -> str:
    """
    Serialize one or more AuditResult objects to CSV.

    Parameters
    ----------
    results:
        A single AuditResult or a list of them (batch mode).
    out:
        - Path  → write to file, return path string.
        - file-like → write to it, return "".
        - None  → return CSV as a string.
    """
    if isinstance(results, AuditResult):
        results = [results]

    all_rows: list[dict] = []
    for r in results:
        all_rows.extend(_rows(r))

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=FIELDNAMES, lineterminator="\n")
    writer.writeheader()
    writer.writerows(all_rows)
    text = buf.getvalue()

    if isinstance(out, Path):
        out.write_text(text, encoding="utf-8")
        return str(out)
    if out is not None:
        out.write(text)
        return ""
    return text
