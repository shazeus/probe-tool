from __future__ import annotations
from pathlib import Path

_WORDLISTS_DIR = Path(__file__).parent.parent / "wordlists"


def load_wordlist(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Wordlist not found: {path}")
    lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    return [l.strip() for l in lines if l.strip() and not l.startswith("#")]


def load_bundled(name: str) -> list[str]:
    return load_wordlist(str(_WORDLISTS_DIR / name))


def resolve_wordlist(custom: str | None, bundled_name: str) -> list[str]:
    if custom:
        return load_wordlist(custom)
    return load_bundled(bundled_name)
