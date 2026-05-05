import pytest
from unittest.mock import MagicMock


def _mock_response(text="", status_code=200, headers=None):
    r = MagicMock()
    r.text = text
    r.status_code = status_code
    r.headers = headers or {}
    r.url = "http://example.com"
    return r


@pytest.mark.asyncio
async def test_sqli_detects_error():
    from probe.modules.web import test_sqli
    error_response = _mock_response("You have an error in your SQL syntax")
    normal_response = _mock_response("Welcome")

    async def fake_get(url, params=None, **kwargs):
        if params and "'" in str(list(params.values())):
            return error_response
        return normal_response

    results = await test_sqli("http://example.com/page", "id", fake_get)
    assert len(results) > 0
    assert any("sqli" in r["type"] for r in results)


@pytest.mark.asyncio
async def test_sqli_no_false_positive():
    from probe.modules.web import test_sqli

    async def fake_get(url, params=None, **kwargs):
        return _mock_response("Normal page content")

    results = await test_sqli("http://example.com/page", "id", fake_get)
    assert len(results) == 0


@pytest.mark.asyncio
async def test_xss_detects_reflection():
    from probe.modules.web import test_xss

    async def fake_get(url, params=None, **kwargs):
        if params:
            val = list(params.values())[0]
            return _mock_response(f"Search results for: {val}")
        return _mock_response("Normal")

    results = await test_xss("http://example.com/search", "q", fake_get)
    assert len(results) > 0
    assert any("xss" in r["type"] for r in results)


@pytest.mark.asyncio
async def test_headers_missing_csp():
    from probe.modules.web import check_headers

    async def fake_get(url, **kwargs):
        return _mock_response(headers={"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"})

    findings = await check_headers("http://example.com", fake_get)
    assert any("Content-Security-Policy" in f["detail"] for f in findings)


@pytest.mark.asyncio
async def test_cors_detects_wildcard():
    from probe.modules.web import check_cors

    async def fake_get(url, **kwargs):
        return _mock_response(headers={"Access-Control-Allow-Origin": "*"})

    findings = await check_cors("http://example.com", fake_get)
    assert len(findings) > 0
    assert findings[0]["severity"] in ("HIGH", "MEDIUM", "CRITICAL")


@pytest.mark.asyncio
async def test_cors_no_issue():
    from probe.modules.web import check_cors

    async def fake_get(url, **kwargs):
        return _mock_response(headers={"Access-Control-Allow-Origin": "https://trusted.com"})

    findings = await check_cors("http://example.com", fake_get)
    assert len(findings) == 0
