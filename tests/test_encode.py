import pytest
from probe.modules.encode import (
    b64_encode, b64_decode,
    hex_encode, hex_decode,
    url_encode, url_decode,
    rot13_encode,
    binary_encode, binary_decode,
    chain_encode,
)


def test_base64_encode():
    assert b64_encode("hello world") == "aGVsbG8gd29ybGQ="


def test_base64_decode():
    assert b64_decode("aGVsbG8gd29ybGQ=") == "hello world"


def test_base64_roundtrip():
    assert b64_decode(b64_encode("test123")) == "test123"


def test_hex_encode():
    assert hex_encode("hello") == "68656c6c6f"


def test_hex_decode():
    assert hex_decode("68656c6c6f") == "hello"


def test_url_encode():
    result = url_encode("hello world&foo=bar")
    assert "hello%20world" in result or "hello+world" in result
    assert "foo%3Dbar" in result or "foo=bar" not in result.split("?")[0]


def test_url_decode():
    assert url_decode("hello%20world") == "hello world"


def test_rot13():
    assert rot13_encode("hello") == "uryyb"
    assert rot13_encode(rot13_encode("hello")) == "hello"


def test_binary_encode():
    assert binary_encode("A") == "01000001"


def test_binary_decode():
    assert binary_decode("01000001") == "A"


def test_chain_encode():
    result = chain_encode("hello", ["base64"])
    assert result == b64_encode("hello")


def test_chain_multiple_ops():
    result = chain_encode("hello", ["rot13", "base64"])
    assert result == b64_encode(rot13_encode("hello"))
