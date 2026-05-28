"""
nd-goat CLI — network device configuration security auditor.

Usage examples:
  nd-goat audit -i router.conf
  nd-goat audit -i asa.conf --vendor cisco_asa
  nd-goat audit --dir ./configs/ --output report.json
  nd-goat vendors
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import box

from fluff.detect.fingerprints import detect_from_file
from fluff.detect.models import PROFILES, PROFILE_VENDOR
from fluff.engine.models import Status, Severity
from fluff.engine.runner import audit
from fluff.parsers.router import load_config
from fluff.report.json_report import write_json

app = typer.Typer(
    name="nd-goat",
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
    Status.NOT_APPLICABLE: "dim",
}


@app.command()
def audit_cmd(
    input_file: Optional[Path] = typer.Option(None, "--input", "-i", help="Config file to audit."),
    directory: Optional[Path] = typer.Option(None, "--dir", "-d", help="Directory of config files to audit (batch mode)."),
    vendor: Optional[str] = typer.Option(None, "--vendor", "-v", help="Force vendor profile (skip auto-detect)."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write JSON report to this file."),
    json_stdout: bool = typer.Option(False, "--json", "-j", help="Print JSON report to stdout."),
    show_pass: bool = typer.Option(False, "--show-pass", help="Include passing checks in table output."),
    show_manual: bool = typer.Option(True, "--show-manual/--hide-manual", help="Include manual checks in table."),
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

    all_results = []
    for cfg_file in files:
        result = _audit_file(cfg_file, vendor_override=vendor, quiet=json_stdout)
        if result is None:
            continue
        all_results.append(result)

        if not json_stdout:
            _print_result(result, show_pass=show_pass, show_manual=show_manual)

    if not all_results:
        err_console.print("[yellow]No files audited.[/yellow]")
        raise typer.Exit(code=1)

    if json_stdout:
        import json as _json
        # For batch mode emit list; single file emit dict
        if len(all_results) == 1:
            console.print_json(write_json(all_results[0]))
        else:
            from fluff.report.json_report import render
            console.print_json(_json.dumps([render(r) for r in all_results], indent=2))
    elif output:
        if len(all_results) == 1:
            write_json(all_results[0], output)
            console.print(f"\n[dim]Report written to[/dim] {output}")
        else:
            import json as _json
            from fluff.report.json_report import render
            output.write_text(
                _json.dumps([render(r) for r in all_results], indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            console.print(f"\n[dim]Batch report written to[/dim] {output}")


def _audit_file(path: Path, vendor_override: str | None, quiet: bool = False) -> object | None:
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
            err_console.print(f"[red]Error:[/red] Unknown vendor profile {profile!r}. Run `nd-goat vendors` to list supported profiles.")
            return None
        status_console.print(f"[dim]{path.name}[/dim] → using forced profile [bold]{profile}[/bold]")

    try:
        config = load_config(path, profile)
    except Exception as exc:
        err_console.print(f"[red]Parse error[/red] {path.name}: {exc}")
        return None

    return audit(config)


def _print_result(result, *, show_pass: bool, show_manual: bool) -> None:
    from fluff.engine.models import AuditResult
    s = result.summary
    console.rule(f"[bold]{s.profile}[/bold] — {s.hostname or 'unknown host'}")

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("ID", style="dim", width=20)
    table.add_column("Status", width=8)
    table.add_column("Sev", width=8)
    table.add_column("Title")
    table.add_column("CIS Controls", style="dim")

    for f in result.findings:
        if f.status == Status.PASS and not show_pass:
            continue
        if f.status == Status.MANUAL and not show_manual:
            continue

        status_colour = _STATUS_COLOUR.get(f.status, "white")
        sev_colour = _SEV_COLOUR.get(f.severity, "white")
        cis_str = ", ".join(f"{c.benchmark.split()[1]} {c.control}" for c in f.cis) if f.cis else ""

        table.add_row(
            f.check_id,
            f"[{status_colour}]{f.status.value}[/{status_colour}]",
            f"[{sev_colour}]{f.severity.value}[/{sev_colour}]",
            f.title,
            cis_str,
        )

    console.print(table)
    console.print(
        f"  [bold green]{s.passed} passed[/bold green]  "
        f"[bold red]{s.failed} failed[/bold red]  "
        f"[yellow]{s.manual} manual[/yellow]  "
        f"[dim]{s.not_applicable} n/a[/dim]  "
        f"— compliance score: [bold]{s.compliance_score}%[/bold]\n"
    )

    # Print evidence for failing checks
    for f in result.findings:
        if f.status == Status.FAIL and f.evidence:
            console.print(f"  [red]✗[/red] [bold]{f.check_id}[/bold]: {f.title}")
            for ev in f.evidence[:5]:
                console.print(f"    [dim]{ev}[/dim]")
            if f.remediation:
                console.print(f"    [dim]→ {f.remediation}[/dim]")
            console.print()


@app.command("vendors")
def list_vendors() -> None:
    """List all supported vendor profiles."""
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

    result = detect_from_file(input_file)
    if result is None:
        console.print(f"[yellow]Unknown vendor[/yellow] — no profile reached detection threshold.")
        raise typer.Exit(code=1)

    console.print(f"Profile:    [bold]{result.profile}[/bold]")
    console.print(f"Vendor:     {result.vendor}")
    console.print(f"Confidence: {result.confidence:.0%}")
    console.print(f"Signals:    {', '.join(result.signals)}")


# Entry-point alias so ``nd-goat audit`` is the canonical command name
app.command("audit")(audit_cmd)


if __name__ == "__main__":
    app()
