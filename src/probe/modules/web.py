from __future__ import annotations
import asyncio
from typing import Callable
from urllib.parse import urljoin

import typer
from bs4 import BeautifulSoup

from probe.config import new_session, save_session, add_finding, get_setting
from probe.utils.display import print_findings_table, console as rich_console, print_finding
from probe.utils.http import async_client
from probe.utils.wordlist import resolve_wordlist

app = typer.Typer(help="Web security scanner: SQLi, XSS, traversal, headers, CORS, crawl")

_SQLI_PAYLOADS = ["'", "' OR '1'='1", "'; DROP TABLE users--", "' AND 1=1--", "\" OR \"1\"=\"1"]
_SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-", "syntax error", "sqlite_",
    "pg_query", "unclosed quotation", "warning: mysql",
]

_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
]

_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
]


async def test_sqli(url: str, param: str, get_func: Callable) -> list[dict]:
    findings = []
    for payload in _SQLI_PAYLOADS:
        try:
            r = await get_func(url, params={param: payload})
            body = r.text.lower()
            if any(err in body for err in _SQLI_ERRORS):
                findings.append({
                    "type": "sqli",
                    "severity": "HIGH",
                    "detail": f"Param '{param}' reflected SQL error with payload: {payload!r}",
                })
                break
        except Exception:
            continue
    return findings


async def test_xss(url: str, param: str, get_func: Callable) -> list[dict]:
    findings = []
    for payload in _XSS_PAYLOADS:
        try:
            r = await get_func(url, params={param: payload})
            if payload in r.text:
                findings.append({
                    "type": "xss",
                    "severity": "HIGH",
                    "detail": f"Param '{param}' reflected XSS payload: {payload!r}",
                })
                break
        except Exception:
            continue
    return findings


async def check_headers(url: str, get_func: Callable) -> list[dict]:
    findings = []
    try:
        r = await get_func(url)
        headers = {k.lower(): v for k, v in r.headers.items()}
        for h in _SECURITY_HEADERS:
            if h.lower() not in headers:
                findings.append({
                    "type": "missing_header",
                    "severity": "MEDIUM",
                    "detail": f"Missing security header: {h}",
                })
    except Exception as e:
        findings.append({"type": "error", "severity": "INFO", "detail": str(e)})
    return findings


async def check_cors(url: str, get_func: Callable) -> list[dict]:
    findings = []
    try:
        r = await get_func(url, headers={"Origin": "https://evil.com"})
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*":
            findings.append({"type": "cors_wildcard", "severity": "HIGH",
                              "detail": "Access-Control-Allow-Origin: * (wildcard)"})
        elif acao == "https://evil.com":
            sev = "CRITICAL" if acac.lower() == "true" else "HIGH"
            findings.append({"type": "cors_reflection", "severity": sev,
                              "detail": f"Origin reflected: {acao}, credentials: {acac}"})
    except Exception:
        pass
    return findings


async def crawl_links(url: str, depth: int, get_func: Callable) -> list[str]:
    visited: set[str] = set()
    found: list[str] = []

    async def _crawl(current_url: str, current_depth: int) -> None:
        if current_depth == 0 or current_url in visited:
            return
        visited.add(current_url)
        try:
            r = await get_func(current_url)
            soup = BeautifulSoup(r.text, "html.parser")
            for tag in soup.find_all("a", href=True):
                href = urljoin(current_url, tag["href"])
                if href.startswith(url) and href not in visited:
                    found.append(href)
                    await _crawl(href, current_depth - 1)
        except Exception:
            pass

    await _crawl(url, depth)
    return found


@app.command("headers")
def cmd_headers(url: str):
    """Check security headers."""
    async def run():
        async with async_client() as client:
            async def get(u, **kw): return await client.get(u)
            return await check_headers(url, get)
    findings = asyncio.run(run())
    for f in findings:
        print_finding(f)
    if not findings:
        rich_console.print("[green]All expected security headers present[/green]")


@app.command("cors")
def cmd_cors(url: str):
    """Check CORS misconfiguration."""
    async def run():
        async with async_client() as client:
            async def get(u, headers=None, **kw): return await client.get(u, headers=headers or {})
            return await check_cors(url, get)
    findings = asyncio.run(run())
    for f in findings:
        print_finding(f)
    if not findings:
        rich_console.print("[green]No CORS issues detected[/green]")


@app.command("sqli")
def cmd_sqli(url: str, param: str = typer.Option(..., "--param", "-p")):
    """Test SQL injection on a URL parameter."""
    session = new_session(url, ["web"])
    async def run():
        async with async_client() as client:
            async def get(u, params=None, **kw): return await client.get(u, params=params)
            return await test_sqli(url, param, get)
    findings = asyncio.run(run())
    for f in findings:
        print_finding(f)
        session["findings"].append(f)
    save_session(session)


@app.command("xss")
def cmd_xss(url: str, param: str = typer.Option(..., "--param", "-p")):
    """Test reflected XSS on a URL parameter."""
    session = new_session(url, ["web"])
    async def run():
        async with async_client() as client:
            async def get(u, params=None, **kw): return await client.get(u, params=params)
            return await test_xss(url, param, get)
    findings = asyncio.run(run())
    for f in findings:
        print_finding(f)
        session["findings"].append(f)
    save_session(session)


@app.command("crawl")
def cmd_crawl(url: str, depth: int = typer.Option(2, "--depth", "-d")):
    """Crawl links from a URL."""
    async def run():
        async with async_client() as client:
            async def get(u, **kw): return await client.get(u)
            return await crawl_links(url, depth, get)
    links = asyncio.run(run())
    for link in links:
        rich_console.print(f"  [cyan]{link}[/cyan]")
    rich_console.print(f"\n[dim]{len(links)} links found[/dim]")


@app.command("traversal")
def cmd_traversal(url: str, wordlist: str = typer.Option(None, "--wordlist", "-w")):
    """Test path traversal."""
    paths = resolve_wordlist(wordlist, "common-paths.txt")
    session = new_session(url, ["web"])
    traversal_payloads = ["../", "../../", "../../../", "....//", "..%2F"]
    async def run():
        findings = []
        async with async_client() as client:
            for path in paths[:50]:
                for payload in traversal_payloads:
                    test_url = f"{url.rstrip('/')}/{payload}{path}"
                    try:
                        r = await client.get(test_url)
                        if r.status_code == 200 and len(r.text) > 100:
                            findings.append({
                                "type": "traversal",
                                "severity": "HIGH",
                                "detail": f"Possible traversal: {test_url}",
                            })
                            break
                    except Exception:
                        pass
        return findings
    findings = asyncio.run(run())
    for f in findings:
        print_finding(f)
        session["findings"].append(f)
    save_session(session)


@app.command("scan")
def cmd_scan(url: str):
    """Run all web checks on a URL."""
    session = new_session(url, ["web"])
    rich_console.print(f"[cyan]Scanning {url}...[/cyan]")

    async def run():
        results = []
        async with async_client() as client:
            async def get(u, params=None, headers=None, **kw):
                return await client.get(u, params=params, headers=headers or {})
            results += await check_headers(url, get)
            results += await check_cors(url, get)
        return results

    findings = asyncio.run(run())
    for f in findings:
        add_finding(session, "web", f["type"], f["severity"], detail=f.get("detail", ""))
    print_findings_table(session["findings"], title=f"Web scan — {url}")
    path = save_session(session)
    rich_console.print(f"[dim]Session saved: {path}[/dim]")
