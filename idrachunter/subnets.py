"""subnets.txt with mtime hot-reload and optional masscan fast path."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import shutil
from collections.abc import Iterator
from pathlib import Path

log = logging.getLogger("idrachunter.scrape")

SKIP = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
    "240.0.0.0/4", "100.64.0.0/10")]


class SubnetList:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._mtime = 0.0
        self.entries: list[str] = []
        self.reload()

    def reload(self) -> None:
        try:
            raw = self._path.read_text(encoding="utf-8")
            self._mtime = self._path.stat().st_mtime
        except OSError:
            return
        self.entries = [ln.split("#", 1)[0].strip() for ln in raw.splitlines()
                        if ln.split("#", 1)[0].strip()]
        log.info("subnets loaded: %d entries", len(self.entries))

    def changed(self) -> bool:
        try:
            return self._path.stat().st_mtime != self._mtime
        except OSError:
            return False

    def add(self, cidr: str) -> None:
        ipaddress.ip_network(cidr, strict=False)
        lines = [ln for ln in self._path.read_text(encoding="utf-8").splitlines()
                 if ln.strip()] if self._path.exists() else []
        if cidr in lines:
            return
        lines.append(cidr)
        self._path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.reload()

    def expand(self, cap: int) -> Iterator[str]:
        seen = 0
        for entry in self.entries:
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            hosts = net.hosts() if net.num_addresses > 2 else [net.network_address]
            for ip in hosts:
                if any(ip in s for s in SKIP):
                    continue
                yield str(ip)
                seen += 1
                if seen >= cap:
                    return


async def masscan(entries: list[str], ports: list[int], rate: int,
                  binary: str = "masscan") -> list[tuple[str, int]]:
    if not shutil.which(binary) or not entries:
        return []
    port_arg = ",".join(str(p) for p in ports)
    cmd = [binary, "-p", port_arg, "--rate", str(rate), "--open-only", "-oL", "-",
           *entries]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), 1800)
    except (OSError, asyncio.TimeoutError) as exc:
        log.warning("masscan failed: %s", exc)
        return []
    hits: list[tuple[str, int]] = []
    for line in out.decode(errors="replace").splitlines():
        if not line.startswith("open"):
            continue
        parts = [p.strip() for p in line.split()]
        if len(parts) >= 4:
            try:
                hits.append((parts[3], int(parts[2])))
            except ValueError:
                continue
    log.info("masscan: %d open ports", len(hits))
    return hits
