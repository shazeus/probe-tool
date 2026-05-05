from __future__ import annotations
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

_SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "orange1",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "white",
}


def severity_color(severity: str) -> str:
    return _SEVERITY_COLORS.get(severity.upper(), "white")


def format_finding(finding: dict) -> str:
    sev = finding.get("severity", "INFO")
    color = severity_color(sev)
    ftype = finding.get("type", "unknown")
    detail = finding.get("detail", "")
    return f"[{color}][{sev}][/{color}] {ftype}: {detail}"


def print_finding(finding: dict) -> None:
    console.print(format_finding(finding))


def print_findings_table(findings: list[dict], title: str = "Findings") -> None:
    if not findings:
        console.print(f"[dim]No findings for {title}[/dim]")
        return
    table = Table(title=title, box=box.ROUNDED, show_header=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Module", width=10)
    table.add_column("Type", width=15)
    table.add_column("Detail")
    for f in findings:
        sev = f.get("severity", "INFO")
        color = severity_color(sev)
        table.add_row(
            f"[{color}]{sev}[/{color}]",
            f.get("module", ""),
            f.get("type", ""),
            str(f.get("detail", "")),
        )
    console.print(table)


def print_panel(title: str, content: str, color: str = "cyan") -> None:
    console.print(Panel(content, title=f"[{color}]{title}[/{color}]", box=box.ROUNDED))
