"""Rendering: rich console output and JSON serialisation."""
from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table

from .models import ScanReport, Severity


def render_console(report: ScanReport, console: Console | None = None) -> None:
    console = console or Console()
    console.print(
        f"[bold]secscan[/bold] {report.started_at}  "
        f"host={report.host}  user={report.user}"
    )

    by_cat: dict[str, list] = {}
    for f in report.findings:
        by_cat.setdefault(f.check.split(".")[0], []).append(f)

    for cat, items in by_cat.items():
        console.print(f"\n[bold blue]== {cat} ==[/bold blue]")
        for f in items:
            tag = f"[{f.severity.color}]{f.severity.label:>4}[/]"
            console.print(f"  {tag}  {f.title}")
            if f.detail:
                console.print(f"        [dim]{f.detail}[/dim]")
            if f.remediation:
                console.print(f"        [magenta]-> {f.remediation}[/magenta]")

    table = Table(title="Summary", show_header=True, header_style="bold")
    for sev in (Severity.HIGH, Severity.WARN, Severity.INFO, Severity.OK):
        table.add_column(sev.label)
    table.add_row(
        f"[bold red]{report.count(Severity.HIGH)}[/]",
        f"[yellow]{report.count(Severity.WARN)}[/]",
        f"[cyan]{report.count(Severity.INFO)}[/]",
        f"[green]{report.count(Severity.OK)}[/]",
    )
    console.print()
    console.print(table)

    if report.count(Severity.HIGH):
        console.print("[bold red]Action recommended on the HIGH items above.[/bold red]")
    elif report.count(Severity.WARN):
        console.print("[yellow]Review the WARN items; most are benign.[/yellow]")
    else:
        console.print("[green]No high/medium findings. Re-run periodically.[/green]")


def render_json(report: ScanReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2)
