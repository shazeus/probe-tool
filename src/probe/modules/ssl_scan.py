from __future__ import annotations
import ssl
import socket
from datetime import datetime, timezone

import typer
from cryptography import x509
from rich.table import Table
from rich import box

from probe.utils.display import print_panel, console as rich_console

app = typer.Typer(help="SSL/TLS certificate and cipher analysis")

_WEAK_KEYWORDS = ["RC4", "DES", "MD5", "NULL", "EXPORT", "anon", "ADH", "AECDH"]


def is_weak_cipher(cipher_name: str) -> bool:
    return any(kw.upper() in cipher_name.upper() for kw in _WEAK_KEYWORDS)


def parse_cert_info(cert: x509.Certificate) -> dict:
    try:
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        cn = "Unknown"

    try:
        issuer_cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        issuer_cn = "Unknown"

    # Handle both timezone-aware and naive datetimes
    not_after_raw = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
    if not_after_raw.tzinfo is None:
        not_after = not_after_raw.replace(tzinfo=timezone.utc)
    else:
        not_after = not_after_raw

    now = datetime.now(timezone.utc)
    days_left = (not_after - now).days

    return {
        "subject": cn,
        "issuer": issuer_cn,
        "not_after": not_after.isoformat(),
        "days_left": days_left,
        "self_signed": cn == issuer_cn,
        "expired": days_left < 0,
        "expiring_soon": 0 <= days_left <= 30,
    }


def get_cert(host: str, port: int = 443) -> x509.Certificate:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
    return x509.load_der_x509_certificate(der)


def get_supported_ciphers(host: str, port: int = 443) -> list[str]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cipher_name, _, _ = ssock.cipher()
            return [cipher_name]


@app.command("cert")
def cmd_cert(host: str, port: int = typer.Option(443, "--port", "-p")):
    """Show certificate details."""
    try:
        cert = get_cert(host, port)
        info = parse_cert_info(cert)
        lines = [
            f"Subject : {info['subject']}",
            f"Issuer  : {info['issuer']}",
            f"Expires : {info['not_after']} ({info['days_left']} days)",
            f"Self-signed: {'YES' if info['self_signed'] else 'No'}",
            f"Expired : {'YES' if info['expired'] else 'No'}",
        ]
        print_panel(f"SSL Cert — {host}", "\n".join(lines))
    except Exception as e:
        rich_console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("scan")
def cmd_scan(host: str, port: int = typer.Option(443, "--port", "-p")):
    """Full SSL scan — cert + ciphers."""
    cmd_cert(host, port)
    cmd_ciphers(host, port)


@app.command("ciphers")
def cmd_ciphers(host: str, port: int = typer.Option(443, "--port", "-p")):
    """Show negotiated cipher."""
    try:
        ciphers = get_supported_ciphers(host, port)
        table = Table(title=f"Ciphers — {host}:{port}", box=box.ROUNDED)
        table.add_column("Cipher")
        table.add_column("Weak?")
        for c in ciphers:
            weak = is_weak_cipher(c)
            table.add_row(c, "[red]YES[/red]" if weak else "[green]No[/green]")
        rich_console.print(table)
    except Exception as e:
        rich_console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("version")
def cmd_version(host: str, port: int = typer.Option(443, "--port", "-p")):
    """Show TLS version used by server."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
        print_panel(f"TLS Version — {host}", version or "Unknown")
    except Exception as e:
        rich_console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
