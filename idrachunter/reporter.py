"""Discord output: per-channel token buckets, embed builders, optional webhook mirror."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import discord

from .config import Config
from .db import Database
from .ratelimit import TokenBucket

log = logging.getLogger("idrachunter.hits")

GEN_COLOR = {6: 0x8E8E8E, 7: 0x3498DB, 8: 0x2ECC71}
VULN_COLOR = 0xE74C3C


class Reporter:
    def __init__(self, bot: discord.Client, cfg: Config, db: Database) -> None:
        self._bot = bot
        self._cfg = cfg
        self._db = db
        self._queues: dict[int, asyncio.Queue[discord.Embed]] = {}
        self._buckets: dict[int, TokenBucket] = {}
        self._tasks: dict[int, asyncio.Task] = {}
        self.sent = 0

    def _channel(self, cid: int) -> discord.abc.Messageable | None:
        ch = self._bot.get_channel(cid)
        return ch if isinstance(ch, discord.abc.Messageable) else None

    def _ensure(self, cid: int) -> None:
        if cid in self._queues:
            return
        self._queues[cid] = asyncio.Queue(maxsize=5000)
        self._buckets[cid] = TokenBucket(1.0 / max(0.4, self._cfg.discord.send_delay), 1)
        self._tasks[cid] = asyncio.create_task(self._drain(cid), name=f"report:{cid}")

    async def _drain(self, cid: int) -> None:
        q, bucket = self._queues[cid], self._buckets[cid]
        while True:
            embed = await q.get()
            await bucket.acquire()
            ch = self._channel(cid)
            if ch is None:
                log.warning("channel %s unavailable", cid)
                continue
            for attempt in range(3):
                try:
                    await ch.send(embed=embed)
                    self.sent += 1
                    break
                except discord.HTTPException as exc:
                    if exc.status == 429:
                        await asyncio.sleep(getattr(exc, "retry_after", 3) or 3)
                        continue
                    log.warning("send failed: %s", exc)
                    break
            q.task_done()

    def submit(self, cid: int, embed: discord.Embed) -> None:
        if not cid:
            return
        self._ensure(cid)
        try:
            self._queues[cid].put_nowait(embed)
        except asyncio.QueueFull:
            log.warning("report queue full for %s", cid)

    async def discovery(self, *, ip: str, port: int, generation: int, title: str,
                        country: str, asn: str, org: str, source: str) -> None:
        e = discord.Embed(
            title=f"iDRAC {generation} - {ip}:{port}",
            colour=GEN_COLOR.get(generation, 0x95A5A6),
            timestamp=datetime.now(timezone.utc))
        e.add_field(name="Generation", value=f"iDRAC {generation}", inline=True)
        e.add_field(name="Source", value=source, inline=True)
        if country or asn:
            e.add_field(name="Location",
                        value=f"{country or '?'} - {asn or '?'}\n{org or ''}".strip(),
                        inline=False)
        if title:
            e.add_field(name="Title", value=title[:240], inline=False)
        if generation == 6:
            e.set_footer(text="legacy - CVE-2018-1207 does not apply")
        self.submit(self._cfg.discord.discovery_channel, e)

    async def vuln_alert(self, *, ip: str, port: int, generation: int, confidence: int,
                         firmware: str, proof: str, country: str, org: str) -> None:
        e = discord.Embed(
            title=f"CVE-2018-1207 CONFIRMED - {ip}:{port}",
            description=f"Confidence **{confidence}%**",
            colour=VULN_COLOR, timestamp=datetime.now(timezone.utc))
        e.add_field(name="Generation", value=f"iDRAC {generation}", inline=True)
        e.add_field(name="Firmware", value=firmware or "unknown", inline=True)
        if country:
            e.add_field(name="Location", value=f"{country}\n{org or ''}".strip(), inline=False)
        e.add_field(name="Proof", value=f"```{proof[:400]}```", inline=False)
        e.add_field(name="Method", value="CGI injection in dispatcher.cgi", inline=False)
        e.set_footer(text="dispatcher.cgi is unauthenticated - patch or isolate")

        content = ""
        role = self._cfg.discord.ping_role
        if role:
            content = f"<@&{role}>"
        self.submit(self._cfg.discord.alert_channel, e)
        if content:
            ch = self._channel(self._cfg.discord.alert_channel)
            if ch:
                try:
                    await ch.send(content, allowed_mentions=discord.AllowedMentions(roles=True))
                except discord.HTTPException:
                    pass

    async def heartbeat(self, text: str) -> None:
        ch = self._channel(self._cfg.discord.status_channel)
        if not ch:
            return
        try:
            await ch.send(text)
        except discord.HTTPException as exc:
            log.warning("heartbeat failed: %s", exc)

    async def shutdown(self) -> None:
        for t in self._tasks.values():
            t.cancel()
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)
