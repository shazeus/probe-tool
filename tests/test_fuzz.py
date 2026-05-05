from unittest.mock import MagicMock

import pytest


def _mock_resp(status=200, length=500, url="http://example.com/admin"):
    response = MagicMock()
    response.status_code = status
    response.headers = {"content-length": str(length)}
    response.text = "x" * length
    response.url = url
    return response


@pytest.mark.asyncio
async def test_fuzz_paths_finds_hit():
    from probe.modules.fuzz import fuzz_paths

    async def fake_get(url, **kwargs):
        if "admin" in url:
            return _mock_resp(200, 500, url)
        return _mock_resp(404, 0, url)

    results = await fuzz_paths(
        "http://example.com",
        ["admin", "login", "notfound"],
        fake_get,
    )
    assert any(r["path"] == "admin" for r in results)
    assert not any(r["path"] == "notfound" for r in results)


@pytest.mark.asyncio
async def test_fuzz_paths_filters_404():
    from probe.modules.fuzz import fuzz_paths

    async def fake_get(url, **kwargs):
        return _mock_resp(404, 0, url)

    results = await fuzz_paths("http://example.com", ["a", "b"], fake_get)
    assert results == []


@pytest.mark.asyncio
async def test_fuzz_params_hit():
    from probe.modules.fuzz import fuzz_params

    async def fake_get(url, params=None, **kwargs):
        if params and params.get("id") == "1":
            return _mock_resp(200, 1000, url)
        return _mock_resp(200, 100, url)

    results = await fuzz_params(
        "http://example.com/page",
        "id",
        ["1", "2", "3"],
        fake_get,
        filter_size=100,
    )
    assert any(r["value"] == "1" for r in results)
    assert not any(r["value"] == "2" for r in results)


def test_should_report_non404():
    from probe.modules.fuzz import should_report

    response = _mock_resp(200)
    assert should_report(response, match_codes=None, filter_size=None) is True


def test_should_not_report_404():
    from probe.modules.fuzz import should_report

    response = _mock_resp(404)
    assert should_report(response, match_codes=None, filter_size=None) is False


def test_should_report_match_code():
    from probe.modules.fuzz import should_report

    response = _mock_resp(403)
    assert should_report(response, match_codes=[403, 200], filter_size=None) is True
