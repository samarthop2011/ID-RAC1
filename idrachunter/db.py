"""aiosqlite persistence. One connection, serialised writes, dedup on (ip, port)."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import aiosqlite

log = logging.getLogger(__name__)

SCHEMA = (Path(__file__).parent.parent / "schema.sql").read_text(encoding="utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._db: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()
        self.counters: dict[str, int] = {}

    async def open(self) -> None:
        self._db = await aiosqlite.connect(self._path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(SCHEMA)
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            async with self._lock:
                await self._db.commit()
                await self._db.close()
            self._db = None

    async def _write(self, sql: str, params: tuple) -> None:
        assert self._db is not None
        async with self._lock:
            await self._db.execute(sql, params)
            await self._db.commit()

    async def _read(self, sql: str, params: tuple = ()) -> list[aiosqlite.Row]:
        assert self._db is not None
        async with self._lock:
            cur = await self._db.execute(sql, params)
            rows = await cur.fetchall()
            await cur.close()
        return list(rows)

    async def record_host(self, *, ip: str, port: int, generation: int | None,
                          source: str, title: str = "", country: str = "",
                          asn: str = "", org: str = "", firmware: str = "",
                          notes: str = "") -> bool:
        rows = await self._read("SELECT sources FROM all_ips WHERE ip=? AND port=?",
                                (ip, port))
        now = _now()
        if rows:
            merged = rows[0]["sources"] or ""
            if source not in merged.split(","):
                merged = f"{merged},{source}" if merged else source
            await self._write(
                """UPDATE all_ips SET last_seen=?, is_alive=1, sources=?,
                   title=COALESCE(NULLIF(?,''),title),
                   country=COALESCE(NULLIF(?,''),country),
                   asn=COALESCE(NULLIF(?,''),asn),
                   org=COALESCE(NULLIF(?,''),org),
                   firmware=COALESCE(NULLIF(?,''),firmware),
                   notes=COALESCE(NULLIF(?,''),notes) WHERE ip=? AND port=?""",
                (now, merged, title, country, asn, org, firmware, notes, ip, port))
            return False
        await self._write(
            """INSERT INTO all_ips (ip,port,generation,first_seen,last_seen,sources,
               title,country,asn,org,is_alive,firmware,notes)
               VALUES (?,?,?,?,?,?,?,?,?,?,1,?,?)""",
            (ip, port, generation, now, now, source, title, country, asn, org,
             firmware, notes))
        return True

    async def record_vuln(self, *, ip: str, port: int, generation: int | None,
                          source: str, title: str, country: str, asn: str, org: str,
                          firmware: str, confidence: int, proof: str) -> bool:
        rows = await self._read("SELECT confidence FROM vuln_ips WHERE ip=? AND port=?",
                                (ip, port))
        now = _now()
        if rows:
            await self._write(
                """UPDATE vuln_ips SET last_seen=?, confidence=MAX(confidence,?),
                   proof=?, firmware=COALESCE(NULLIF(?,''),firmware)
                   WHERE ip=? AND port=?""",
                (now, confidence, proof, firmware, ip, port))
            return False
        await self._write(
            """INSERT INTO vuln_ips (ip,port,generation,first_seen,last_seen,
               vuln_confirmed_at,sources,title,country,asn,org,firmware,confidence,proof)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ip, port, generation, now, now, now, source, title, country, asn, org,
             firmware, confidence, proof))
        return True

    async def mark_dead(self, ip: str, port: int) -> None:
        await self._write("UPDATE all_ips SET is_alive=0 WHERE ip=? AND port=?", (ip, port))

    async def stale(self, hours: int, limit: int = 500) -> list[aiosqlite.Row]:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        return await self._read(
            "SELECT ip,port FROM all_ips WHERE is_alive=1 AND last_seen<? LIMIT ?",
            (cutoff, limit))

    async def lookup(self, needle: str) -> tuple[list[aiosqlite.Row], list[aiosqlite.Row]]:
        return (await self._read("SELECT * FROM all_ips WHERE ip LIKE ? LIMIT 20",
                                 (f"%{needle}%",)),
                await self._read("SELECT * FROM vuln_ips WHERE ip LIKE ? LIMIT 20",
                                 (f"%{needle}%",)))

    async def recent_all(self, limit: int) -> list[aiosqlite.Row]:
        return await self._read("SELECT * FROM all_ips ORDER BY first_seen DESC LIMIT ?",
                                (limit,))

    async def recent_vuln(self, limit: int) -> list[aiosqlite.Row]:
        return await self._read(
            "SELECT * FROM vuln_ips ORDER BY vuln_confirmed_at DESC LIMIT ?", (limit,))

    async def stats(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for key, sql in (
            ("total", "SELECT COUNT(*) c FROM all_ips"),
            ("alive", "SELECT COUNT(*) c FROM all_ips WHERE is_alive=1"),
            ("gen6", "SELECT COUNT(*) c FROM all_ips WHERE generation=6"),
            ("gen7", "SELECT COUNT(*) c FROM all_ips WHERE generation=7"),
            ("gen8", "SELECT COUNT(*) c FROM all_ips WHERE generation=8"),
            ("vuln", "SELECT COUNT(*) c FROM vuln_ips"),
            ("vuln_today", "SELECT COUNT(*) c FROM vuln_ips WHERE vuln_confirmed_at>=?"),
        ):
            params = ((datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),) \
                if key == "vuln_today" else ()
            rows = await self._read(sql, params)
            out[key] = rows[0]["c"] if rows else 0
        return out

    async def dump(self, table: str, fmt: str) -> tuple[str, bytes]:
        rows = await self._read(f"SELECT * FROM {table} ORDER BY last_seen DESC")
        records = [dict(r) for r in rows]
        if fmt == "json":
            return f"{table}.json", json.dumps(records, indent=2).encode()
        buf = io.StringIO()
        if records:
            w = csv.DictWriter(buf, fieldnames=list(records[0]))
            w.writeheader()
            w.writerows(records)
        return f"{table}.csv", buf.getvalue().encode()

    async def bump(self, name: str) -> None:
        self.counters[name] = self.counters.get(name, 0) + 1
