from __future__ import annotations
import hashlib
import re
from typing import Optional

import typer
from rich.console import Console

from probe.utils.display import print_panel, console as rich_console
from probe.utils.wordlist import load_wordlist

app = typer.Typer(help="Hash identification, cracking, and generation")
console = Console()

_HASH_PATTERNS = [
    ("MD5",     r"^[a-f0-9]{32}$"),
    ("SHA1",    r"^[a-f0-9]{40}$"),
    ("SHA224",  r"^[a-f0-9]{56}$"),
    ("SHA256",  r"^[a-f0-9]{64}$"),
    ("SHA384",  r"^[a-f0-9]{96}$"),
    ("SHA512",  r"^[a-f0-9]{128}$"),
    ("bcrypt",  r"^\$2[aby]\$\d{2}\$.{53}$"),
]

_SUPPORTED = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512"}


def identify_hash(h: str) -> str:
    h = h.strip()
    matches = [name for name, pattern in _HASH_PATTERNS if re.match(pattern, h, re.I)]
    return ", ".join(matches) if matches else "Unknown"


def generate_hash(text: str, hash_type: str) -> str:
    ht = hash_type.lower()
    if ht not in _SUPPORTED:
        raise ValueError(f"Unsupported hash type: {hash_type}. Use: {_SUPPORTED}")
    return hashlib.new(ht, text.encode()).hexdigest()


def crack_hash(h: str, wordlist_path: str, hash_type: Optional[str] = None) -> Optional[str]:
    h = h.strip().lower()
    detected = identify_hash(h)
    if hash_type:
        ht = hash_type.lower()
    elif detected != "Unknown":
        ht = detected.split(",")[0].strip().lower().replace("-", "")
    else:
        return None

    words = load_wordlist(wordlist_path)
    for word in words:
        try:
            candidate = hashlib.new(ht, word.encode()).hexdigest()
            if candidate == h:
                return word
        except Exception:
            continue
    return None


@app.command("identify")
def cmd_identify(hash_val: str):
    """Identify hash type."""
    result = identify_hash(hash_val)
    print_panel("Hash Type", result)


@app.command("generate")
def cmd_generate(
    text: str,
    hash_type: str = typer.Option("sha256", "--type", "-t"),
):
    """Generate hash of a string."""
    try:
        result = generate_hash(text, hash_type)
        print_panel(f"{hash_type.upper()} hash", result)
    except ValueError as e:
        rich_console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)


@app.command("crack")
def cmd_crack(
    hash_val: str,
    wordlist: str = typer.Option(..., "--wordlist", "-w"),
    hash_type: Optional[str] = typer.Option(None, "--type", "-t"),
):
    """Crack hash against a wordlist."""
    rich_console.print(f"[cyan]Cracking {hash_val[:16]}...[/cyan]")
    result = crack_hash(hash_val, wordlist, hash_type)
    if result:
        print_panel("Cracked!", f"[green]{result}[/green]")
    else:
        rich_console.print("[red]Not found in wordlist[/red]")
