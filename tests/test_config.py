import json
import os
import pytest
from pathlib import Path


@pytest.fixture
def probe_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("PROBE_DIR", str(tmp_path))
    return tmp_path


def test_load_config_defaults(probe_dir):
    from probe.config import load_config, DEFAULT_CONFIG
    cfg = load_config()
    assert cfg == DEFAULT_CONFIG


def test_save_and_load_config(probe_dir):
    from probe.config import save_config, load_config
    save_config({"timeout": 30, "threads": 10, "output_dir": "/tmp"})
    cfg = load_config()
    assert cfg["timeout"] == 30
    assert cfg["threads"] == 10


def test_set_and_get_setting(probe_dir):
    from probe.config import set_setting, get_setting
    set_setting("timeout", 99)
    assert get_setting("timeout") == 99


def test_new_session_structure(probe_dir):
    from probe.config import new_session
    s = new_session("example.com", ["web"])
    assert s["target"] == "example.com"
    assert s["modules"] == ["web"]
    assert s["findings"] == []
    assert s["finished"] is None


def test_save_and_list_sessions(probe_dir):
    from probe.config import new_session, save_session, list_sessions
    s = new_session("example.com", ["web"])
    save_session(s)
    sessions = list_sessions()
    assert len(sessions) == 1
    assert sessions[0]["target"] == "example.com"


def test_load_session_by_id(probe_dir):
    from probe.config import new_session, save_session, load_session
    s = new_session("target.com", ["network"])
    save_session(s)
    loaded = load_session(s["id"])
    assert loaded is not None
    assert loaded["target"] == "target.com"


def test_add_finding(probe_dir):
    from probe.config import new_session, add_finding
    s = new_session("target.com", ["web"])
    add_finding(s, "web", "sqli", "HIGH", detail="error in query")
    assert len(s["findings"]) == 1
    assert s["findings"][0]["severity"] == "HIGH"
    assert s["findings"][0]["detail"] == "error in query"
