import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import dns.resolver


def test_parse_dns_records():
    from probe.modules.osint import parse_dns_records
    mock_answer = MagicMock()
    mock_answer.to_text.return_value = "93.184.216.34"
    records = parse_dns_records([mock_answer], "A")
    assert records == [{"type": "A", "value": "93.184.216.34"}]


@pytest.mark.asyncio
async def test_resolve_subdomain_found():
    from probe.modules.osint import resolve_subdomain
    mock_answer = MagicMock()
    mock_answer.to_text.return_value = "1.2.3.4"
    with patch("dns.resolver.resolve", return_value=[mock_answer]):
        result = await resolve_subdomain("www.example.com")
    assert result == "1.2.3.4"


@pytest.mark.asyncio
async def test_resolve_subdomain_not_found():
    from probe.modules.osint import resolve_subdomain
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN):
        result = await resolve_subdomain("nonexistent.example.com")
    assert result is None


@pytest.mark.asyncio
async def test_fetch_certs_returns_list():
    from probe.modules.osint import fetch_certs
    mock_data = [
        {"name_value": "sub.example.com", "logged_at": "2026-01-01"}
    ]
    mock_response = MagicMock()
    mock_response.json.return_value = mock_data
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("httpx.AsyncClient", return_value=mock_client):
        results = await fetch_certs("example.com")
    assert any("sub.example.com" in r["name"] for r in results)
