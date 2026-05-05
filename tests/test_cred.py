import ftplib
from unittest.mock import MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_http_brute_success():
    from probe.modules.cred import brute_http

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "Welcome admin"

    async def fake_post(url, data=None, **kwargs):
        if data and data.get("password") == "secret":
            return mock_response
        response = MagicMock()
        response.status_code = 401
        response.text = "Invalid"
        return response

    result = await brute_http(
        "http://example.com/login",
        "admin",
        ["wrong", "secret"],
        fake_post,
    )
    assert result == "secret"


@pytest.mark.asyncio
async def test_http_brute_failure():
    from probe.modules.cred import brute_http

    async def fake_post(url, data=None, **kwargs):
        response = MagicMock()
        response.status_code = 401
        response.text = "Invalid"
        return response

    result = await brute_http(
        "http://example.com/login",
        "admin",
        ["wrong", "bad"],
        fake_post,
    )
    assert result is None


def test_ftp_brute_success():
    from probe.modules.cred import brute_ftp

    def fake_login(host, user, passwd):
        if passwd == "ftppass":
            return
        raise ftplib.error_perm("Login failed")

    with patch("probe.modules.cred._ftp_login", side_effect=fake_login):
        result = brute_ftp("ftp.example.com", "anonymous", ["wrong", "ftppass"])

    assert result == "ftppass"


def test_ftp_brute_failure():
    from probe.modules.cred import brute_ftp

    with patch("probe.modules.cred._ftp_login", side_effect=ftplib.error_perm("fail")):
        result = brute_ftp("ftp.example.com", "anonymous", ["a", "b"])

    assert result is None
