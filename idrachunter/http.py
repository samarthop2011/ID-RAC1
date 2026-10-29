"""Shared aiohttp client: UA rotation, proxies, retries, per-host caps."""

from __future__ import annotations

import asyncio
import logging
import random
import ssl
from typing import Any

import aiohttp

from .config import Config
from .proxies import ProxyPool
from .ratelimit import HostLimiter, backoff

log = logging.getLogger("idrachunter.scrape")

RETRY = {408, 425, 429, 500, 502, 503, 504, 520, 522, 524}


def _ctx() -> ssl.SSLContext:
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    c.set_ciphers("DEFAULT@SECLEVEL=1")
    return c


class HttpClient:
    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._session: aiohttp.ClientSession | None = None
        self._sem = asyncio.Semaphore(cfg.http.concurrency)
        self._hosts = HostLimiter(2)
        self._pool = ProxyPool(cfg.http.proxies)

    async def start(self) -> None:
        self._session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=0, ssl=_ctx(), ttl_dns_cache=600),
            timeout=aiohttp.ClientTimeout(total=self._cfg.http.timeout,
                                          connect=self._cfg.http.connect_timeout),
            cookie_jar=aiohttp.DummyCookieJar(), trust_env=bool(self._pool))

    async def close(self) -> None:
        if self._session:
            await self._session.close()
            self._session = None

    async def request(self, method: str, url: str, *, headers: dict[str, str] | None = None,
                      data: Any = None, retries: int | None = None,
                      allow_redirects: bool = True) -> tuple[int, dict[str, str], str]:
        if self._session is None:
            raise RuntimeError("client not started")
        host = url.split("//", 1)[-1].split("/", 1)[0]
        tries = self._cfg.http.retries if retries is None else retries
        hdrs = {"User-Agent": random.choice(self._cfg.http.user_agents),
                "Accept": "*/*", "Connection": "close"}
        if headers:
            hdrs.update(headers)

        for attempt in range(tries + 1):
            proxy = self._pool.next()
            async with self._sem, self._hosts.slot(host):
                try:
                    async with self._session.request(
                            method, url, headers=hdrs, data=data, proxy=proxy,
                            allow_redirects=allow_redirects) as r:
                        body = await r.text(errors="replace")
                        if r.status in RETRY and attempt < tries:
                            await asyncio.sleep(backoff(attempt, self._cfg.http.backoff_base))
                            continue
                        return r.status, {k.lower(): v for k, v in r.headers.items()}, body[:250_000]
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    self._pool.penalise(proxy)
                    if attempt < tries:
                        await asyncio.sleep(backoff(attempt, self._cfg.http.backoff_base))
                        continue
                    log.debug("fail %s %s: %s", method, url, exc)
        return 0, {}, ""

    async def get(self, url: str, **kw: Any) -> tuple[int, dict[str, str], str]:
        return await self.request("GET", url, **kw)
