"""Re-probe old entries and mark them dead."""

from __future__ import annotations

import asyncio
import logging

from .db import Database
from .pipeline import Pipeline

log = logging.getLogger("idrachunter.scrape")


class Pruner:
    def __init__(self, db: Database, pipeline: Pipeline, interval: int,
                 after_hours: int) -> None:
        self._db = db
        self._pipeline = pipeline
        self._interval = interval
        self._after = after_hours

    async def run(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            try:
                rows = await self._db.stale(self._after)
            except Exception as exc:
                log.warning("prune query failed: %s", exc)
                continue
            dead = 0
            for row in rows:
                if not await self._pipeline._tcp(row["ip"], row["port"]):
                    await self._db.mark_dead(row["ip"], row["port"])
                    dead += 1
            if rows:
                log.info("prune: %d checked, %d marked dead", len(rows), dead)
</｜DSML｜ parameter>
</｜DSML｜ invoke>
</｜DSML｜ calls>
