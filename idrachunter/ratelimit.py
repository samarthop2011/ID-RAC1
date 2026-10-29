"""Token bucket, per-host semaphore and jittered backoff."""

from __future__ import annotations

import asyncio
import random
import time
from collections import defaultdict


class TokenBucket:
    __slots__ = ("_rate", "_cap", "_tokens", "_ts", "_lock")

    def __init__(self, rate: float, burst: int = 1) -> None:
        self._rate = max(0.01, rate)
        self._cap = max(1, burst)
        self._tokens = float(self._cap)
        self._ts = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, n: float = 1.0) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                self._tokens = min(self._cap, self._tokens + (now - self._ts) * self._rate)
                self._ts = now
                if self._tokens >= n:
                    self._tokens -= n
                    return
                wait = (n - self._tokens) / self._rate
            await asyncio.sleep(min(wait, 5.0))


class HostLimiter:
    def __init__(self, per_host: int = 2) -> None:
        self._n = per_host
        self._sems: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(self._n))

    def slot(self, host: str) -> asyncio.Semaphore:
        return self._sems[host]


def backoff(attempt: int, base: float = 1.6, cap: float = 120.0) -> float:
    return min(cap, (base ** attempt) * (0.5 + random.random()))
