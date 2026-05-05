from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

DEFAULT_CONFIG = {
    "timeout": 10,
    "threads": 50,
    "output_dir": str(Path.home() / ".probe" / "sessions"),
}


def get_probe_dir() -> Path:
    override = os.environ.get("PROBE_DIR")
    if override:
        return Path(override)
    return Path.home() / ".probe"


def get_sessions_dir() -> Path:
    return get_probe_dir() / "sessions"


def _config_path() -> Path:
    return get_probe_dir() / "config.json"


def load_config() -> dict:
    path = _config_path()
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return DEFAULT_CONFIG.copy()


def save_config(config: dict) -> None:
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")


def get_setting(key: str):
    return load_config().get(key, DEFAULT_CONFIG.get(key))


def set_setting(key: str, value) -> None:
    config = load_config()
    config[key] = value
    save_config(config)


def new_session(target: str, modules: list[str]) -> dict:
    session_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    return {
        "id": session_id,
        "target": target,
        "modules": modules,
        "findings": [],
        "started": datetime.now().isoformat(),
        "finished": None,
    }


def save_session(session: dict) -> Path:
    sessions_dir = get_sessions_dir()
    sessions_dir.mkdir(parents=True, exist_ok=True)
    target_slug = session["target"].replace("://", "_").replace("/", "_").replace(".", "_")
    path = sessions_dir / f"{session['id']}-{target_slug}.json"
    session["finished"] = datetime.now().isoformat()
    path.write_text(json.dumps(session, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def list_sessions() -> list[dict]:
    sessions_dir = get_sessions_dir()
    if not sessions_dir.exists():
        return []
    sessions = []
    for f in sorted(sessions_dir.glob("*.json"), reverse=True):
        try:
            sessions.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            pass
    return sessions


def load_session(session_id: str) -> dict | None:
    for session in list_sessions():
        if session.get("id") == session_id:
            return session
    return None


def add_finding(session: dict, module: str, finding_type: str, severity: str, **kwargs) -> None:
    finding = {"module": module, "type": finding_type, "severity": severity, **kwargs}
    session["findings"].append(finding)
