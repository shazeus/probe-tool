from __future__ import annotations
import asyncio
from typing import Optional

import dns.resolver
import httpx
import typer
from rich.table import Table
from rich import box

from probe.config import new_session, save_session, add_finding
from probe.utils.display import print_panel, console as rich_console
from probe.utils.wordlist import resolve_wordlist

app = typer.Typer(help="OSINT: WHOIS, DNS, subdomains, certificate transparency")

_DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def parse_dns_records(answers, record_type: str) -> list[dict]:
    return [{"type": record_type, "value": a.to_text()} for a in answers]


async def resolve_subdomain(fqdn: str) -> Optional[str]:
    loop = asyncio.get_running_loop()
    try:
        answers = await loop.run_in_executor(None, dns.resolver.resolve, fqdn, "A")
        return answers[0].to_text()
    except Exception:
        return None


async def fetch_certs(domain: str) -> list[dict]:
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
        r.raise_for_status()
        return [{"name": e["name_value"], "logged_at": e.get("logged_at", "")} for e in r.json()]


@app.command("whois")
def cmd_whois(domain: str):
    """WHOIS lookup for a domain."""
    try:
        import whois
        info = whois.whois(domain)
        lines = []
        for key in ["registrar", "creation_date", "expiration_date", "name_servers", "emails"]:
            val = getattr(info, key, None)
            if val:
                lines.append(f"{key}: {val}")
        print_panel(f"WHOIS — {domain}", "\n".join(lines) or "No data returned")
    except Exception as e:
        rich_console.print(f"[red]WHOIS error: {e}[/red]")
        raise typer.Exit(1)


@app.command("dns")
def cmd_dns(
    domain: str,
    record_type: str = typer.Option("ALL", "--type", "-t"),
):
    """Query DNS records for a domain."""
    types = _DNS_TYPES if record_type.upper() == "ALL" else [record_type.upper()]
    table = Table(title=f"DNS — {domain}", box=box.ROUNDED)
    table.add_column("Type", width=8)
    table.add_column("Value")
    for rtype in types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for a in answers:
                table.add_row(rtype, a.to_text())
        except Exception:
            pass
    rich_console.print(table)


@app.command("subdomains")
def cmd_subdomains(
    domain: str,
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "-w"),
):
    """Enumerate subdomains via DNS resolution."""
    words = resolve_wordlist(wordlist, "subdomains.txt")
    fqdns = [f"{w}.{domain}" for w in words]
    session = new_session(domain, ["osint"])

    async def run():
        sem = asyncio.Semaphore(50)

        async def check(fqdn: str) -> None:
            async with sem:
                ip = await resolve_subdomain(fqdn)
                if ip:
                    rich_console.print(f"  [green]FOUND[/green] {fqdn} → {ip}")
                    add_finding(session, "osint", "subdomain", "INFO", subdomain=fqdn, ip=ip)

        await asyncio.gather(*[check(f) for f in fqdns])

    rich_console.print(f"[cyan]Enumerating {len(fqdns)} subdomains...[/cyan]")
    asyncio.run(run())
    path = save_session(session)
    rich_console.print(f"[dim]Session saved: {path}[/dim]")


@app.command("certs")
def cmd_certs(domain: str):
    """Query certificate transparency logs (crt.sh)."""
    try:
        results = asyncio.run(fetch_certs(domain))
        table = Table(title=f"Cert Transparency — {domain}", box=box.ROUNDED)
        table.add_column("Name")
        table.add_column("Logged At")
        for r in results[:50]:
            table.add_row(r["name"], r["logged_at"])
        rich_console.print(table)
    except Exception as e:
        rich_console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
