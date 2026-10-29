"""Console + rotating file logging, split by concern."""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

FMT = "%(asctime)s %(levelname)-8s %(name)-26s %(message)s"


def setup(log_dir: Path, level: str = "INFO") -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    for h in list(root.handlers):
        root.removeHandler(h)

    console = logging.StreamHandler()
    console.setLevel(getattr(logging, level.upper(), logging.INFO))
    console.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S"))
    root.addHandler(console)

    for name, fname, lvl in (("", "bot.log", logging.INFO),
                             ("idrachunter.scrape", "scrape.log", logging.DEBUG),
                             ("idrachunter.hits", "hits.log", logging.INFO)):
        h = logging.handlers.RotatingFileHandler(
            log_dir / fname, maxBytes=32 << 20, backupCount=8, encoding="utf-8")
        h.setLevel(lvl)
        h.setFormatter(logging.Formatter(FMT))
        if name:
            lg = logging.getLogger(name)
            lg.setLevel(lvl)
            lg.propagate = False
            lg.addHandler(h)
        else:
            root.addHandler(h)

    for noisy in ("discord", "discord.http", "discord.gateway", "aiohttp", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
