from __future__ import annotations
import base64
import binascii
import codecs
from urllib.parse import quote, unquote

import typer
from rich.console import Console

from probe.utils.display import print_panel

app = typer.Typer(help="Encode/decode toolkit")
console = Console()


def b64_encode(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def b64_decode(text: str) -> str:
    return base64.b64decode(text.encode()).decode()


def hex_encode(text: str) -> str:
    return binascii.hexlify(text.encode()).decode()


def hex_decode(text: str) -> str:
    return binascii.unhexlify(text.encode()).decode()


def url_encode(text: str) -> str:
    return quote(text, safe="")


def url_decode(text: str) -> str:
    return unquote(text)


def rot13_encode(text: str) -> str:
    return codecs.encode(text, "rot_13")


def binary_encode(text: str) -> str:
    return "".join(format(ord(c), "08b") for c in text)


def binary_decode(binary: str) -> str:
    binary = binary.replace(" ", "")
    chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
    return "".join(chr(int(c, 2)) for c in chars)


_OPS = {
    "base64": b64_encode,
    "hex": hex_encode,
    "url": url_encode,
    "rot13": rot13_encode,
    "binary": binary_encode,
}


def chain_encode(text: str, ops: list[str]) -> str:
    result = text
    for op in ops:
        if op not in _OPS:
            raise ValueError(f"Unknown op: {op}. Available: {list(_OPS)}")
        result = _OPS[op](result)
    return result


@app.command("base64")
def cmd_base64(text: str, decode: bool = typer.Option(False, "--decode", "-d")):
    """Base64 encode or decode."""
    result = b64_decode(text) if decode else b64_encode(text)
    print_panel("base64", result)


@app.command("hex")
def cmd_hex(text: str, decode: bool = typer.Option(False, "--decode", "-d")):
    """Hex encode or decode."""
    result = hex_decode(text) if decode else hex_encode(text)
    print_panel("hex", result)


@app.command("url")
def cmd_url(text: str, decode: bool = typer.Option(False, "--decode", "-d")):
    """URL encode or decode."""
    result = url_decode(text) if decode else url_encode(text)
    print_panel("url", result)


@app.command("rot13")
def cmd_rot13(text: str):
    """ROT13 encode/decode (symmetric)."""
    print_panel("rot13", rot13_encode(text))


@app.command("binary")
def cmd_binary(text: str, decode: bool = typer.Option(False, "--decode", "-d")):
    """Binary encode or decode."""
    result = binary_decode(text) if decode else binary_encode(text)
    print_panel("binary", result)


@app.command("chain")
def cmd_chain(
    text: str,
    ops: str = typer.Option(..., "--ops", help="Comma-separated ops: base64,url,rot13,hex,binary"),
):
    """Chain multiple encode operations."""
    op_list = [o.strip() for o in ops.split(",")]
    result = chain_encode(text, op_list)
    print_panel(f"chain({ops})", result)
