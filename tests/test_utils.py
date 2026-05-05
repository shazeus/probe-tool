import pytest
from pathlib import Path


def test_load_custom_wordlist(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("admin\nroot\nguest\n# comment\n\n")
    from probe.utils.wordlist import load_wordlist
    words = load_wordlist(str(wl))
    assert words == ["admin", "root", "guest"]


def test_load_bundled_wordlist():
    from probe.utils.wordlist import load_bundled
    words = load_bundled("passwords.txt")
    assert len(words) > 0
    assert all(isinstance(w, str) for w in words)


def test_load_wordlist_missing_raises(tmp_path):
    from probe.utils.wordlist import load_wordlist
    with pytest.raises(FileNotFoundError):
        load_wordlist(str(tmp_path / "nonexistent.txt"))


def test_severity_color():
    from probe.utils.display import severity_color
    assert severity_color("CRITICAL") == "red"
    assert severity_color("HIGH") == "orange1"
    assert severity_color("MEDIUM") == "yellow"
    assert severity_color("LOW") == "blue"
    assert severity_color("INFO") == "white"
    assert severity_color("UNKNOWN") == "white"


def test_format_finding():
    from probe.utils.display import format_finding
    f = {"module": "web", "type": "sqli", "severity": "HIGH", "detail": "error"}
    result = format_finding(f)
    assert "sqli" in result
    assert "HIGH" in result
