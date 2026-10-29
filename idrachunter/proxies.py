"""Rotating proxy pool with quarantine."""

from __future__ import annotations

import time

QUARANTINE = 300


class ProxyPool:
    def __init__(self, proxies: list[str]) -> None:
        self._items = [p.strip() for p in proxies if p.strip()]
        self._i = 0
        self._bad: dict[str, float] = {}

    def __bool__(self) -> bool:
        return bool(self._items)

    def next(self) -> str | None:
        if not self._items:
            return None
        now = time.monotonic()
        for _ in range(len(self._items)):
            p = self._items[self._i % len(self._items)]
            self._i += 1
            if self._bad.get(p, 0) <= now:
                return p
        return self._items[self._i % len(self._items)]

    def penalise(self, proxy: str | None) -> None:
        if proxy:
            self._bad[proxy] = time.monotonic() + QUARANTINE
