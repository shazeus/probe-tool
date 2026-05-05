from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich import box
from rich.table import Table

from probe.config import list_sessions, load_session
from probe.utils.display import console as rich_console, print_findings_table

app = typer.Typer(help="Session listing and report export")

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def severity_counts(findings: list[dict]) -> dict:
    counts = {severity: 0 for severity in _SEVERITIES}
    for finding in findings:
        severity = finding.get("severity", "INFO").upper()
        if severity in counts:
            counts[severity] += 1
    return counts


def export_json(session: dict, output_path: Optional[str]) -> Optional[str]:
    if output_path is None:
        rich_console.print_json(json.dumps(session, indent=2, ensure_ascii=False))
        return None
    path = Path(output_path)
    path.write_text(json.dumps(session, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(path)


def export_markdown(session: dict, output_path: str) -> str:
    lines = [
        f"# Probe Report - {session['target']}",
        "",
        f"**Target:** {session['target']}  ",
        f"**Modules:** {', '.join(session.get('modules', []))}  ",
        f"**Started:** {session.get('started', '')}  ",
        f"**Finished:** {session.get('finished', '')}  ",
        "",
        "## Summary",
        "",
    ]

    counts = severity_counts(session.get("findings", []))
    for severity in _SEVERITIES:
        if counts[severity]:
            lines.append(f"- **{severity}:** {counts[severity]}")
    if not any(counts.values()):
        lines.append("- No findings")

    lines.extend(["", "## Findings", ""])
    for finding in session.get("findings", []):
        severity = finding.get("severity", "INFO")
        finding_type = finding.get("type", "unknown")
        detail = finding.get("detail", "")
        module = finding.get("module", "")
        lines.extend([
            f"### [{severity}] {finding_type}",
            "",
            f"- **Module:** {module}",
            f"- **Detail:** {detail}",
            "",
        ])

    path = Path(output_path)
    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)


def export_html(session: dict, output_path: str) -> str:
    from probe import __version__

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html")
    html = template.render(
        session=session,
        counts=severity_counts(session.get("findings", [])),
        severities=_SEVERITIES,
        version=__version__,
    )
    path = Path(output_path)
    path.write_text(html, encoding="utf-8")
    return str(path)


@app.command("list")
def cmd_list():
    """List all saved scan sessions."""
    sessions = list_sessions()
    if not sessions:
        rich_console.print("[dim]No sessions found[/dim]")
        return

    table = Table(title="Sessions", box=box.ROUNDED)
    table.add_column("ID")
    table.add_column("Target")
    table.add_column("Modules")
    table.add_column("Findings")
    table.add_column("Finished")
    for session in sessions:
        counts = severity_counts(session.get("findings", []))
        summary = " ".join(
            f"{severity[0]}:{counts[severity]}" for severity in _SEVERITIES if counts[severity]
        )
        table.add_row(
            session.get("id", ""),
            session.get("target", ""),
            ", ".join(session.get("modules", [])),
            summary or "0",
            session.get("finished", "")[:16] if session.get("finished") else "",
        )
    rich_console.print(table)


@app.command("show")
def cmd_show(session_id: str):
    """Show findings for a session."""
    session = load_session(session_id)
    if not session:
        rich_console.print(f"[red]Session not found: {session_id}[/red]")
        raise typer.Exit(1)
    print_findings_table(session.get("findings", []), title=f"Session {session_id}")


@app.command("export")
def cmd_export(
    session_id: str,
    fmt: str = typer.Option("html", "--format", "-f", help="html, md, json"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
):
    """Export a session as HTML, Markdown, or JSON."""
    session = load_session(session_id)
    if not session:
        rich_console.print(f"[red]Session not found: {session_id}[/red]")
        raise typer.Exit(1)

    fmt = fmt.lower()
    if output is None and fmt != "json":
        output = f"probe-report-{session_id}.{fmt}"

    if fmt == "json":
        path = export_json(session, output)
    elif fmt == "md":
        path = export_markdown(session, output or f"probe-report-{session_id}.md")
    elif fmt == "html":
        path = export_html(session, output or f"probe-report-{session_id}.html")
    else:
        rich_console.print(f"[red]Unknown format: {fmt}. Use html, md, or json[/red]")
        raise typer.Exit(1)

    if path:
        rich_console.print(f"[green]Exported to {path}[/green]")
