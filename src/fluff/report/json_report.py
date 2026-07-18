"""
JSON report renderer.

Produces a structured JSON document from an AuditResult, optionally written
to a file.  The format is documented in docs/input-formats.md.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import IO

from fluff.engine.models import AuditResult, Status


def render(result: AuditResult) -> dict:
    """Return a plain dict representing the full audit report."""
    data = result.as_dict()

    # Group findings by generic_id for CIS summary
    cis_groups: dict[str, list[dict]] = {}
    for f in result.findings:
        for cis_ref in f.cis:
            key = f"{cis_ref.benchmark} — {cis_ref.control}"
            cis_groups.setdefault(key, []).append(f.as_dict())

    data["cis_summary"] = {
        k: {
            "status": _aggregate_status(v),
            "findings": [fi["check_id"] for fi in v],
        }
        for k, v in sorted(cis_groups.items())
    }
    return data


def _aggregate_status(findings: list[dict]) -> str:
    # Worst-first so exemptions are not hidden behind a sibling pass.
    statuses = {f["status"] for f in findings}
    if Status.FAIL.value in statuses:
        return Status.FAIL.value
    if Status.EXEMPT.value in statuses:
        return Status.EXEMPT.value
    if Status.PASS.value in statuses:
        return Status.PASS.value
    if Status.MANUAL.value in statuses or Status.MANUAL_FP_RISK.value in statuses:
        return Status.MANUAL.value
    return Status.NOT_APPLICABLE.value


def write_json(result: AuditResult, out: Path | IO | None = None) -> str:
    """
    Serialize *result* to JSON.

    If *out* is a Path, write to that file and return the path as string.
    If *out* is a file-like object, write to it and return "".
    If *out* is None, return the JSON string.
    """
    data = render(result)
    text = json.dumps(data, indent=2, ensure_ascii=False)

    if isinstance(out, Path):
        out.write_text(text, encoding="utf-8")
        return str(out)
    if out is not None:
        out.write(text)
        return ""
    return text
