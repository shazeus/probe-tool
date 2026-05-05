from __future__ import annotations
from contextlib import asynccontextmanager
from typing import Optional

import httpx
from probe.config import get_setting


def default_headers() -> dict:
    return {
        "User-Agent": "Mozilla/5.0 (compatible; probe-tool/0.1)",
        "Accept": "*/*",
    }


@asynccontextmanager
async def async_client(timeout: Optional[float] = None, follow_redirects: bool = True):
    t = timeout if timeout is not None else float(get_setting("timeout"))
    async with httpx.AsyncClient(
        timeout=t,
        follow_redirects=follow_redirects,
        headers=default_headers(),
        verify=False,
    ) as client:
        yield client


async def get(url: str, params: Optional[dict] = None, timeout: Optional[float] = None) -> httpx.Response:
    async with async_client(timeout=timeout) as client:
        return await client.get(url, params=params)


async def post(url: str, data: Optional[dict] = None, timeout: Optional[float] = None) -> httpx.Response:
    async with async_client(timeout=timeout) as client:
        return await client.post(url, data=data)
