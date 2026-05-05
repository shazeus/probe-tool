from __future__ import annotations
import asyncio
from typing import Optional

import typer

from probe.config import new_session, save_session, add_finding, get_setting
from probe.utils.display import console as rich_console, print_panel

app = typer.Typer(help="Network scanner and banner grabber")

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 27017, 5432, 6379, 11211,
    2181, 9200, 9300, 4848, 7001, 7002, 4444, 1099, 2049, 512, 513, 514,
]

_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}


def parse_port_range(spec: str) -> list[int]:
    if "-" in spec:
        start, end = spec.split("-", 1)
        return list(range(int(start), int(end) + 1))
    return [int(spec)]


async def scan_port(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def scan_ports(host: str, ports: list[int], timeout: float = 3.0) -> list[int]:
    semaphore = asyncio.Semaphore(200)

    async def _scan(port: int) -> Optional[int]:
        async with semaphore:
            return port if await scan_port(host, port, timeout) else None

    results = await asyncio.gather(*[_scan(p) for p in ports])
    return [p for p in results if p is not None]


async def grab_banner(host: str, port: int, timeout: float = 5.0) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return banner.decode(errors="replace").strip()
    except Exception as e:
        return f"Error: {e}"


@app.command("scan")
def cmd_scan(
    host: str,
    ports: Optional[str] = typer.Option(None, "--ports", help="e.g. 1-1024"),
    top: int = typer.Option(0, "--top", help="Scan top N ports"),
):
    """Scan ports on a host."""
    if ports:
        port_list = parse_port_range(ports)
    elif top > 0:
        port_list = TOP_PORTS[:top]
    else:
        port_list = TOP_PORTS

    timeout = float(get_setting("timeout"))
    session = new_session(host, ["network"])

    rich_console.print(f"[cyan]Scanning {host} ({len(port_list)} ports)...[/cyan]")
    open_ports = asyncio.run(scan_ports(host, port_list, timeout=timeout))

    for p in open_ports:
        service = _SERVICE_MAP.get(p, "unknown")
        rich_console.print(f"  [green]OPEN[/green] {p}/{service}")
        add_finding(session, "network", "open_port", "INFO", port=p, service=service)

    path = save_session(session)
    rich_console.print(f"\n[dim]Session saved: {path}[/dim]")


@app.command("banner")
def cmd_banner(host: str, port: int):
    """Grab service banner from a port."""
    banner = asyncio.run(grab_banner(host, port))
    print_panel(f"Banner {host}:{port}", banner)


@app.command("ping")
def cmd_ping(host: str):
    """TCP connectivity check via port 80."""
    result = asyncio.run(scan_port(host, 80))
    status = "[green]UP[/green]" if result else "[red]DOWN[/red]"
    rich_console.print(f"{host} is {status}")
