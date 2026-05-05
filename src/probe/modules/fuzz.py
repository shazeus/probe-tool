from __future__ import annotations

import asyncio
from typing import Callable, Optional

import typer
from rich import box
from rich.table import Table

from probe.config import add_finding, new_session, save_session
from probe.utils.display import console as rich_console
from probe.utils.http import async_client
from probe.utils.wordlist import resolve_wordlist

app = typer.Typer(help="HTTP fuzzer: path, param, header, vhost")

_DEFAULT_IGNORE_CODES = {400, 404}
_DEFAULT_CONCURRENCY = 50


def should_report(response, match_codes: Optional[list[int]], filter_size: Optional[int]) -> bool:
    if match_codes:
        if response.status_code not in match_codes:
            return False
    elif response.status_code in _DEFAULT_IGNORE_CODES:
        return False

    if filter_size is not None and len(response.text) == filter_size:
        return False
    return True


async def fuzz_paths(
    base_url: str,
    paths: list[str],
    get_func: Callable,
    match_codes: Optional[list[int]] = None,
    filter_size: Optional[int] = None,
) -> list[dict]:
    semaphore = asyncio.Semaphore(_DEFAULT_CONCURRENCY)
    results: list[dict] = []

    async def check(path: str) -> None:
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        async with semaphore:
            try:
                response = await get_func(url)
            except Exception:
                return
        if should_report(response, match_codes, filter_size):
            results.append({
                "path": path,
                "url": url,
                "status": response.status_code,
                "length": len(response.text),
            })

    await asyncio.gather(*(check(path) for path in paths))
    return results


async def fuzz_params(
    url: str,
    param: str,
    values: list[str],
    get_func: Callable,
    match_codes: Optional[list[int]] = None,
    filter_size: Optional[int] = None,
) -> list[dict]:
    semaphore = asyncio.Semaphore(_DEFAULT_CONCURRENCY)
    results: list[dict] = []

    async def check(value: str) -> None:
        async with semaphore:
            try:
                response = await get_func(url, params={param: value})
            except Exception:
                return
        if should_report(response, match_codes, filter_size):
            results.append({
                "value": value,
                "status": response.status_code,
                "length": len(response.text),
            })

    await asyncio.gather(*(check(value) for value in values))
    return results


def _parse_codes(match_code: Optional[str]) -> Optional[list[int]]:
    if not match_code:
        return None
    return [int(code.strip()) for code in match_code.split(",") if code.strip()]


def _print_results_table(results: list[dict], title: str) -> None:
    if not results:
        rich_console.print(f"[dim]No results for {title}[/dim]")
        return

    table = Table(title=title, box=box.ROUNDED)
    for key in results[0].keys():
        table.add_column(key.capitalize())
    for result in results:
        table.add_row(*(str(value) for value in result.values()))
    rich_console.print(table)


def _save_fuzz_session(target: str, finding_type: str, results: list[dict]) -> None:
    session = new_session(target, ["fuzz"])
    for result in results:
        add_finding(
            session,
            "fuzz",
            finding_type,
            "INFO",
            detail=str(result),
            **result,
        )
    save_session(session)


@app.command("path")
def cmd_path(
    url: str,
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "-w"),
    match_code: Optional[str] = typer.Option(None, "--match-code"),
    filter_size: Optional[int] = typer.Option(None, "--filter-size"),
    dry: bool = typer.Option(False, "--dry"),
):
    """Fuzz URL paths."""
    paths = resolve_wordlist(wordlist, "common-paths.txt")
    codes = _parse_codes(match_code)

    if dry:
        rich_console.print(f"[dim]Would send {len(paths)} requests to {url}[/dim]")
        return

    async def run() -> list[dict]:
        async with async_client() as client:
            async def get(u, **kwargs):
                return await client.get(u)

            return await fuzz_paths(url, paths, get, codes, filter_size)

    results = asyncio.run(run())
    _print_results_table(results, f"Path fuzz - {url}")
    _save_fuzz_session(url, "path_fuzz", results)


@app.command("param")
def cmd_param(
    url: str,
    param: str = typer.Option(..., "--param", "-p"),
    wordlist: str = typer.Option(..., "--wordlist", "-w"),
    match_code: Optional[str] = typer.Option(None, "--match-code"),
    filter_size: Optional[int] = typer.Option(None, "--filter-size"),
    dry: bool = typer.Option(False, "--dry"),
):
    """Fuzz URL parameter values."""
    values = resolve_wordlist(wordlist, "common-paths.txt")
    codes = _parse_codes(match_code)

    if dry:
        rich_console.print(f"[dim]Would send {len(values)} requests to {url}?{param}=...[/dim]")
        return

    async def run() -> list[dict]:
        async with async_client() as client:
            async def get(u, params=None, **kwargs):
                return await client.get(u, params=params)

            return await fuzz_params(url, param, values, get, codes, filter_size)

    results = asyncio.run(run())
    _print_results_table(results, f"Param fuzz - {url}?{param}")
    _save_fuzz_session(url, "param_fuzz", results)


@app.command("header")
def cmd_header(
    url: str,
    header: str = typer.Option(..., "--header"),
    wordlist: str = typer.Option(..., "--wordlist", "-w"),
    dry: bool = typer.Option(False, "--dry"),
):
    """Fuzz a specific HTTP header value."""
    values = resolve_wordlist(wordlist, "common-paths.txt")
    if dry:
        rich_console.print(f"[dim]Would send {len(values)} requests with {header}: ...[/dim]")
        return

    async def run() -> list[dict]:
        results: list[dict] = []
        semaphore = asyncio.Semaphore(_DEFAULT_CONCURRENCY)
        async with async_client() as client:
            async def check(value: str) -> None:
                async with semaphore:
                    try:
                        response = await client.get(url, headers={header: value})
                    except Exception:
                        return
                if should_report(response, None, None):
                    results.append({
                        "header_value": value,
                        "status": response.status_code,
                        "length": len(response.text),
                    })

            await asyncio.gather(*(check(value) for value in values))
        return results

    results = asyncio.run(run())
    _print_results_table(results, f"Header fuzz - {header}")
    _save_fuzz_session(url, "header_fuzz", results)


@app.command("vhost")
def cmd_vhost(
    ip: str,
    host: str = typer.Option(..., "--host"),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "-w"),
    dry: bool = typer.Option(False, "--dry"),
):
    """Fuzz virtual host names."""
    subdomains = resolve_wordlist(wordlist, "subdomains.txt")
    if dry:
        rich_console.print(f"[dim]Would send {len(subdomains)} requests to {ip} with Host: ...[/dim]")
        return

    async def run() -> list[dict]:
        results: list[dict] = []
        semaphore = asyncio.Semaphore(_DEFAULT_CONCURRENCY)
        async with async_client() as client:
            async def check(subdomain: str) -> None:
                vhost = f"{subdomain}.{host}"
                async with semaphore:
                    try:
                        response = await client.get(f"http://{ip}", headers={"Host": vhost})
                    except Exception:
                        return
                if should_report(response, None, None):
                    results.append({
                        "vhost": vhost,
                        "status": response.status_code,
                        "length": len(response.text),
                    })

            await asyncio.gather(*(check(subdomain) for subdomain in subdomains))
        return results

    results = asyncio.run(run())
    _print_results_table(results, f"VHost fuzz - {ip}")
    _save_fuzz_session(ip, "vhost_fuzz", results)
