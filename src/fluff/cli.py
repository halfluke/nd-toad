"""
nd-toad CLI — network device configuration security auditor.

Usage examples:
  nd-toad audit -i router.conf
  nd-toad audit -i asa.conf --vendor cisco_asa
  nd-toad audit --dir ./configs/ --output report.json
  nd-toad audit --dir ./configs/ --csv report.csv
  nd-toad audit -i router.conf --severity high,critical --fail-on fail
  nd-toad audit -i router.conf --policy overrides.yaml
  nd-toad explain IOS-MGMT-001
  nd-toad vendors
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.table import Table
from rich import box

from fluff.banner import print_banner
from fluff.checks_loader import find_checks, probe_summary
from fluff.detect.fingerprints import detect_from_file
from fluff.detect.models import PROFILES, PROFILE_VENDOR
from fluff.engine.models import AuditResult, Finding, Status, Severity
from fluff.engine.runner import audit
from fluff.parsers.router import load_config
from fluff.policy import Policy, load_policy
from fluff.report.json_report import write_json
from fluff.report.csv_report import write_csv

app = typer.Typer(
    name="nd-toad",
    help="Offline network device configuration security auditor with CIS L1 mapping.",
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)

# Severity colour map for rich output
_SEV_COLOUR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_STATUS_COLOUR = {
    Status.PASS: "green",
    Status.FAIL: "red",
    Status.MANUAL: "yellow",
    Status.MANUAL_FP_RISK: "dark_orange",
    Status.NOT_APPLICABLE: "dim",
    Status.EXEMPT: "blue",
}

_STATUS_LABEL = {
    Status.PASS: "pass",
    Status.FAIL: "fail",
    Status.MANUAL: "manual",
    Status.MANUAL_FP_RISK: "manual [fp risk]",
    Status.NOT_APPLICABLE: "n/a",
    Status.EXEMPT: "exempt",
}

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _parse_csv_option(raw: str | None) -> set[str] | None:
    """Split a comma-separated CLI option into a lowercased set."""
    if raw is None:
        return None
    items = {part.strip().lower() for part in raw.split(",") if part.strip()}
    return items or None


def _parse_severity_filter(raw: str | None) -> set[Severity] | None:
    values = _parse_csv_option(raw)
    if values is None:
        return None
    valid = {s.value: s for s in Severity}
    unknown = values - set(valid)
    if unknown:
        err_console.print(
            f"[red]Error:[/red] Unknown severity: {', '.join(sorted(unknown))}. "
            f"Choose from: {', '.join(valid)}."
        )
        raise typer.Exit(code=1)
    return {valid[v] for v in values}


def _parse_status_filter(raw: str | None) -> set[Status] | None:
    values = _parse_csv_option(raw)
    if values is None:
        return None
    # Accept short aliases used in table labels
    aliases = {
        "n/a": Status.NOT_APPLICABLE.value,
        "na": Status.NOT_APPLICABLE.value,
        "manual_fp_risk": Status.MANUAL_FP_RISK.value,
        "fp": Status.MANUAL_FP_RISK.value,
    }
    normalised = {aliases.get(v, v) for v in values}
    valid = {s.value: s for s in Status}
    unknown = normalised - set(valid)
    if unknown:
        err_console.print(
            f"[red]Error:[/red] Unknown status: {', '.join(sorted(unknown))}. "
            f"Choose from: {', '.join(valid)}."
        )
        raise typer.Exit(code=1)
    return {valid[v] for v in normalised}


def _parse_id_filter(raw: str | None) -> set[str] | None:
    if raw is None:
        return None
    items = {part.strip() for part in raw.split(",") if part.strip()}
    return items or None


def finding_matches_filters(
    finding: Finding,
    *,
    severities: set[Severity] | None,
    statuses: set[Status] | None,
    check_ids: set[str] | None,
    generic_ids: set[str] | None,
) -> bool:
    if severities is not None and finding.severity not in severities:
        return False
    if statuses is not None and finding.status not in statuses:
        return False
    if check_ids is not None and finding.check_id not in check_ids:
        return False
    if generic_ids is not None and finding.generic_id not in generic_ids:
        return False
    return True


def filter_findings(
    findings: list[Finding],
    *,
    severities: set[Severity] | None = None,
    statuses: set[Status] | None = None,
    check_ids: set[str] | None = None,
    generic_ids: set[str] | None = None,
    show_pass: bool = False,
    show_manual: bool = True,
) -> list[Finding]:
    out: list[Finding] = []
    for f in findings:
        # Default hide/show flags apply only when --status is not set,
        # so `--status pass` is not silently emptied by --show-pass default.
        if statuses is None:
            if f.status == Status.PASS and not show_pass:
                continue
            if f.status in (Status.MANUAL, Status.MANUAL_FP_RISK) and not show_manual:
                continue
        if not finding_matches_filters(
            f,
            severities=severities,
            statuses=statuses,
            check_ids=check_ids,
            generic_ids=generic_ids,
        ):
            continue
        out.append(f)
    return out


@app.command("audit")
def audit_cmd(
    input_file: Optional[Path] = typer.Option(None, "--input", "-i", help="Config file to audit."),
    directory: Optional[Path] = typer.Option(None, "--dir", "-d", help="Directory of config files to audit (batch mode)."),
    vendor: Optional[str] = typer.Option(None, "--vendor", "-v", help="Force vendor profile (skip auto-detect)."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write JSON report to this file."),
    csv_output: Optional[Path] = typer.Option(None, "--csv", help="Write CSV report to this file."),
    json_stdout: bool = typer.Option(False, "--json", "-j", help="Print JSON report to stdout."),
    csv_stdout: bool = typer.Option(False, "--csv-stdout", help="Print CSV report to stdout."),
    show_pass: bool = typer.Option(False, "--show-pass", help="Include passing checks in table output."),
    show_manual: bool = typer.Option(True, "--show-manual/--hide-manual", help="Include manual checks in table."),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        help="Comma-separated severities to include in table/exit checks (e.g. critical,high).",
    ),
    status: Optional[str] = typer.Option(
        None,
        "--status",
        help="Comma-separated statuses to include in table/exit checks (e.g. fail,exempt).",
    ),
    check_id: Optional[str] = typer.Option(
        None,
        "--check-id",
        help="Comma-separated check IDs to include (e.g. IOS-MGMT-001).",
    ),
    generic_id: Optional[str] = typer.Option(
        None,
        "--generic-id",
        help="Comma-separated generic IDs to include (e.g. MGMT-001).",
    ),
    policy_file: Optional[Path] = typer.Option(
        None,
        "--policy",
        "-p",
        help="YAML/JSON policy file with exemptions and severity_overrides.",
    ),
    fail_on: str = typer.Option(
        "fail",
        "--fail-on",
        help="Exit 2 when matching findings exist: fail (default), never, or a severity floor (critical|high|medium|low|info).",
    ),
) -> None:
    """Audit one config file or a directory of configs."""
    files: list[Path] = []

    if directory:
        if not directory.is_dir():
            err_console.print(f"[red]Error:[/red] {directory} is not a directory.")
            raise typer.Exit(code=1)
        files = [f for f in sorted(directory.rglob("*")) if f.is_file()]
    elif input_file:
        if not input_file.exists():
            err_console.print(f"[red]Error:[/red] File not found: {input_file}")
            raise typer.Exit(code=1)
        files = [input_file]
    else:
        err_console.print("[red]Error:[/red] Provide --input or --dir.")
        raise typer.Exit(code=1)

    policy: Policy | None = None
    if policy_file is not None:
        try:
            policy = load_policy(policy_file)
        except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
            err_console.print(f"[red]Error:[/red] Invalid policy file: {exc}")
            raise typer.Exit(code=1) from exc

    sev_filter = _parse_severity_filter(severity)
    status_filter = _parse_status_filter(status)
    check_filter = _parse_id_filter(check_id)
    generic_filter = _parse_id_filter(generic_id)
    fail_mode = _parse_fail_on(fail_on)

    silent_terminal = json_stdout or csv_stdout
    if not silent_terminal:
        print_banner(console)

    all_results: list[AuditResult] = []
    for cfg_file in files:
        result = _audit_file(cfg_file, vendor_override=vendor, quiet=silent_terminal, policy=policy)
        if result is None:
            continue
        all_results.append(result)

        if not silent_terminal:
            _print_result(
                result,
                show_pass=show_pass,
                show_manual=show_manual,
                severities=sev_filter,
                statuses=status_filter,
                check_ids=check_filter,
                generic_ids=generic_filter,
            )

    if not all_results:
        err_console.print("[yellow]No files audited.[/yellow]")
        raise typer.Exit(code=1)

    if json_stdout:
        # For batch mode emit list; single file emit dict
        if len(all_results) == 1:
            console.print_json(write_json(all_results[0]))
        else:
            from fluff.report.json_report import render
            console.print_json(json.dumps([render(r) for r in all_results], indent=2))
    elif csv_stdout:
        print(write_csv(all_results), end="")
    elif output:
        if len(all_results) == 1:
            write_json(all_results[0], output)
            console.print(f"\n[dim]Report written to[/dim] {output}")
        else:
            from fluff.report.json_report import render
            output.write_text(
                json.dumps([render(r) for r in all_results], indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            console.print(f"\n[dim]Batch report written to[/dim] {output}")

    if csv_output:
        write_csv(all_results, csv_output)
        console.print(f"\n[dim]CSV report written to[/dim] {csv_output}")

    if _should_fail_exit(
        all_results,
        fail_mode=fail_mode,
        severities=sev_filter,
        statuses=status_filter,
        check_ids=check_filter,
        generic_ids=generic_filter,
    ):
        raise typer.Exit(code=2)


def _parse_fail_on(raw: str) -> str | Severity:
    value = raw.strip().lower()
    if value in ("fail", "never"):
        return value
    valid = {s.value: s for s in Severity}
    if value in valid:
        return valid[value]
    err_console.print(
        f"[red]Error:[/red] Invalid --fail-on {raw!r}. "
        "Use fail, never, or a severity (critical|high|medium|low|info)."
    )
    raise typer.Exit(code=1)


def _should_fail_exit(
    results: list[AuditResult],
    *,
    fail_mode: str | Severity,
    severities: set[Severity] | None,
    statuses: set[Status] | None,
    check_ids: set[str] | None,
    generic_ids: set[str] | None,
) -> bool:
    if fail_mode == "never":
        return False

    for result in results:
        for f in result.findings:
            if not finding_matches_filters(
                f,
                severities=severities,
                statuses=statuses,
                check_ids=check_ids,
                generic_ids=generic_ids,
            ):
                continue
            if fail_mode == "fail":
                if f.status == Status.FAIL:
                    return True
            elif isinstance(fail_mode, Severity):
                if f.status == Status.FAIL and _SEVERITY_ORDER[f.severity] <= _SEVERITY_ORDER[fail_mode]:
                    return True
    return False


def _audit_file(
    path: Path,
    vendor_override: str | None,
    quiet: bool = False,
    policy: Policy | None = None,
) -> AuditResult | None:
    """Detect, parse, and audit a single file.  Returns AuditResult or None on failure."""
    status_console = err_console if quiet else console
    profile = vendor_override

    if profile is None:
        detection = detect_from_file(path)
        if detection is None:
            err_console.print(f"[yellow]Skip[/yellow] {path.name} — vendor not detected (use --vendor to override).")
            return None
        profile = detection.profile
        status_console.print(
            f"[dim]{path.name}[/dim] → detected [bold]{profile}[/bold] "
            f"(confidence {detection.confidence:.0%}, signals: {', '.join(detection.signals[:3])})"
        )
    else:
        if profile not in PROFILES:
            err_console.print(f"[red]Error:[/red] Unknown vendor profile {profile!r}. Run `nd-toad vendors` to list supported profiles.")
            return None
        status_console.print(f"[dim]{path.name}[/dim] → using forced profile [bold]{profile}[/bold]")

    try:
        config = load_config(path, profile)
    except Exception as exc:
        err_console.print(f"[red]Parse error[/red] {path.name}: {exc}")
        return None

    return audit(config, policy=policy)


def _print_result(
    result: AuditResult,
    *,
    show_pass: bool,
    show_manual: bool,
    severities: set[Severity] | None = None,
    statuses: set[Status] | None = None,
    check_ids: set[str] | None = None,
    generic_ids: set[str] | None = None,
) -> None:
    s = result.summary
    console.rule(f"[bold]{s.profile}[/bold] — {s.hostname or 'unknown host'}")

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("ID", style="dim", width=20)
    table.add_column("Status", width=8)
    table.add_column("Sev", width=8)
    table.add_column("Title")
    table.add_column("CIS Controls", style="dim")

    visible = filter_findings(
        result.findings,
        severities=severities,
        statuses=statuses,
        check_ids=check_ids,
        generic_ids=generic_ids,
        show_pass=show_pass,
        show_manual=show_manual,
    )

    for f in visible:
        status_colour = _STATUS_COLOUR.get(f.status, "white")
        sev_colour = _SEV_COLOUR.get(f.severity, "white")
        status_label = _STATUS_LABEL.get(f.status, f.status.value)
        cis_str = ", ".join(f"{c.benchmark.split()[1]} {c.control}" for c in f.cis) if f.cis else ""

        table.add_row(
            f.check_id,
            f"[{status_colour}]{status_label}[/{status_colour}]",
            f"[{sev_colour}]{f.severity.value}[/{sev_colour}]",
            f.title,
            cis_str,
        )

    console.print(table)
    exempt_bit = f"  [blue]{s.exempt} exempt[/blue]" if s.exempt else ""
    console.print(
        f"  [bold green]{s.passed} passed[/bold green]  "
        f"[bold red]{s.failed} failed[/bold red]  "
        f"[yellow]{s.manual} manual[/yellow]  "
        f"[dim]{s.not_applicable} n/a[/dim]"
        f"{exempt_bit}  "
        f"— compliance score: [bold]{s.compliance_score}%[/bold]\n"
    )

    # Print evidence for failing checks (respect filters)
    for f in visible:
        if f.status == Status.FAIL and f.evidence:
            console.print(f"  [red]✗[/red] [bold]{f.check_id}[/bold]: {f.title}")
            for ev in f.evidence[:5]:
                console.print(f"    [dim]{ev}[/dim]")
            if f.remediation:
                console.print(f"    [dim]→ {f.remediation}[/dim]")
            console.print()
        elif f.status == Status.EXEMPT:
            console.print(
                f"  [blue]⊘[/blue] [bold]{f.check_id}[/bold]: exempt"
                + (f" — {f.exemption_reason}" if f.exemption_reason else "")
            )


@app.command("explain")
def explain_cmd(
    check_id: str = typer.Argument(..., help="Check ID or generic ID (e.g. IOS-MGMT-001 or MGMT-001)."),
    vendor: Optional[str] = typer.Option(None, "--vendor", "-v", help="Limit lookup to one vendor profile."),
) -> None:
    """Show details for a check definition without auditing a config."""
    if vendor is not None and vendor not in PROFILES:
        err_console.print(
            f"[red]Error:[/red] Unknown vendor profile {vendor!r}. "
            "Run `nd-toad vendors` to list supported profiles."
        )
        raise typer.Exit(code=1)

    matches = find_checks(check_id, vendor=vendor)
    if not matches:
        scope = f" in profile {vendor}" if vendor else ""
        err_console.print(f"[red]Error:[/red] No check found matching {check_id!r}{scope}.")
        raise typer.Exit(code=1)

    print_banner(console)
    for i, (profile, check) in enumerate(matches):
        if i:
            console.print()
        _print_check_explanation(profile, check)


def _print_check_explanation(profile: str, check: dict) -> None:
    console.rule(f"[bold]{check.get('id', '?')}[/bold] — {profile}")
    console.print(f"[bold]Title:[/bold]       {check.get('title', '')}")
    console.print(f"[bold]Generic ID:[/bold]  {check.get('generic_id', '')}")
    console.print(f"[bold]Severity:[/bold]    {check.get('severity', 'medium')}")
    console.print(f"[bold]Vendor:[/bold]      {PROFILE_VENDOR.get(profile, profile)}")

    description = check.get("description") or ""
    if description:
        console.print(f"[bold]Description:[/bold] {description}")

    cis = check.get("cis") or []
    if cis:
        cis_lines = ", ".join(
            f"{c.get('benchmark', '?')} {c.get('control', '?')} (L{c.get('level', 1)})"
            for c in cis
        )
        console.print(f"[bold]CIS:[/bold]         {cis_lines}")

    console.print(f"[bold]Probe:[/bold]       {probe_summary(check.get('probe'))}")

    remediation = check.get("remediation") or ""
    if remediation:
        console.print(f"[bold]Remediation:[/bold] {remediation}")


@app.command("vendors")
def list_vendors() -> None:
    """List all supported vendor profiles."""
    print_banner(console)
    table = Table(title="Supported Profiles", box=box.SIMPLE, show_header=True)
    table.add_column("Profile", style="bold")
    table.add_column("Vendor")
    for p in PROFILES:
        table.add_row(p, PROFILE_VENDOR[p])
    console.print(table)


@app.command("detect")
def detect_cmd(
    input_file: Path = typer.Argument(..., help="Config file to fingerprint."),
) -> None:
    """Detect the vendor/profile of a config file without running checks."""
    if not input_file.exists():
        err_console.print(f"[red]Error:[/red] File not found: {input_file}")
        raise typer.Exit(code=1)

    print_banner(console)
    result = detect_from_file(input_file)
    if result is None:
        console.print("[yellow]Unknown vendor[/yellow] — no profile reached detection threshold.")
        raise typer.Exit(code=1)

    console.print(f"Profile:    [bold]{result.profile}[/bold]")
    console.print(f"Vendor:     {result.vendor}")
    console.print(f"Confidence: {result.confidence:.0%}")
    console.print(f"Signals:    {', '.join(result.signals)}")


if __name__ == "__main__":
    app()
