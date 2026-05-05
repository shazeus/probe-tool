import json
from pathlib import Path

import pytest


@pytest.fixture
def session():
    return {
        "id": "20260504-120000",
        "target": "example.com",
        "modules": ["web"],
        "findings": [
            {
                "module": "web",
                "type": "sqli",
                "severity": "HIGH",
                "detail": "error in id param",
            },
            {
                "module": "web",
                "type": "missing_header",
                "severity": "MEDIUM",
                "detail": "No CSP",
            },
        ],
        "started": "2026-05-04T12:00:00",
        "finished": "2026-05-04T12:01:00",
    }


def test_export_json(tmp_path, session):
    from probe.modules.report import export_json

    out = export_json(session, str(tmp_path / "out.json"))
    assert Path(out).exists()
    data = json.loads(Path(out).read_text())
    assert data["target"] == "example.com"


def test_export_markdown(tmp_path, session):
    from probe.modules.report import export_markdown

    out = export_markdown(session, str(tmp_path / "out.md"))
    content = Path(out).read_text()
    assert "example.com" in content
    assert "sqli" in content
    assert "HIGH" in content


def test_export_html(tmp_path, session):
    from probe.modules.report import export_html

    out = export_html(session, str(tmp_path / "out.html"))
    content = Path(out).read_text()
    assert "example.com" in content
    assert "sqli" in content
    assert "<html" in content.lower() or "<!DOCTYPE" in content


def test_export_json_stdout(session):
    from probe.modules.report import export_json

    result = export_json(session, None)
    assert result is None


def test_severity_counts(session):
    from probe.modules.report import severity_counts

    counts = severity_counts(session["findings"])
    assert counts["HIGH"] == 1
    assert counts["MEDIUM"] == 1
