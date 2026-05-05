import asyncio
import pytest
from unittest.mock import patch, AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_scan_open_port():
    from probe.modules.network import scan_port
    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_conn.return_value = (mock_reader, mock_writer)
        result = await scan_port("127.0.0.1", 80, timeout=1.0)
    assert result is True


@pytest.mark.asyncio
async def test_scan_closed_port():
    from probe.modules.network import scan_port
    with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
        result = await scan_port("127.0.0.1", 9999, timeout=1.0)
    assert result is False


@pytest.mark.asyncio
async def test_scan_ports_returns_open_list():
    from probe.modules.network import scan_ports
    async def fake_scan(host, port, timeout):
        return port in [22, 80]
    with patch("probe.modules.network.scan_port", side_effect=fake_scan):
        results = await scan_ports("127.0.0.1", [22, 80, 443], timeout=1.0)
    assert 22 in results
    assert 80 in results
    assert 443 not in results


@pytest.mark.asyncio
async def test_banner_grab_returns_string():
    from probe.modules.network import grab_banner
    mock_reader = AsyncMock()
    mock_reader.read.return_value = b"SSH-2.0-OpenSSH_8.4\r\n"
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)):
        banner = await grab_banner("127.0.0.1", 22, timeout=2.0)
    assert "SSH" in banner


def test_parse_port_range():
    from probe.modules.network import parse_port_range
    assert parse_port_range("22-25") == [22, 23, 24, 25]
    assert parse_port_range("80") == [80]


def test_top_ports_returns_list():
    from probe.modules.network import TOP_PORTS
    assert 80 in TOP_PORTS
    assert 443 in TOP_PORTS
    assert len(TOP_PORTS) >= 20
