"""Config load with env expansion and mtime hot-reload for mutable keys."""

from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_ENV = re.compile(r"\$\{([A-Za-z0-9_]+)(?::-([^}]*))?\}")

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
]


def _expand(node: Any) -> Any:
    if isinstance(node, str):
        return _ENV.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), node)
    if isinstance(node, list):
        return [_expand(v) for v in node]
    if isinstance(node, dict):
        return {k: _expand(v) for k, v in node.items()}
    return node


@dataclass(slots=True)
class HttpCfg:
    timeout: float = 12.0
    connect_timeout: float = 6.0
    concurrency: int = 80
    retries: int = 2
    backoff_base: float = 1.6
    proxies: list[str] = field(default_factory=list)
    user_agents: list[str] = field(default_factory=lambda: list(UA_POOL))


@dataclass(slots=True)
class ScanCfg:
    subnets_file: Path = Path("subnets.txt")
    cycle_sleep: int = 1800
    subnet_concurrency: int = 300
    ports: list[int] = field(default_factory=lambda: [443, 80, 5900, 623, 8443])
    port_timeout: float = 3.5
    identify_threshold: int = 55
    max_hosts_per_cycle: int = 25000
    use_masscan: bool = False
    masscan_binary: str = "masscan"
    masscan_rate: int = 2000


@dataclass(slots=True)
class VulnCfg:
    enabled: bool = True
    request_delay: float = 0.25
    require_high_confidence: bool = False
    nuclei_binary: str = ""
    nuclei_timeout: int = 60


@dataclass(slots=True)
class DiscordCfg:
    token: str = ""
    guild_id: int = 0
    discovery_channel: int = 0
    alert_channel: int = 0
    status_channel: int = 0
    ping_role: int = 0
    send_delay: float = 1.15
    heartbeat_minutes: int = 30


@dataclass(slots=True)
class EngineCfg:
    name: str
    enabled: bool = False
    interval: int = 1800
    pages: int = 2
    page_size: int = 100
    queries: list[str] = field(default_factory=list)
    rate: float = 0.4
    burst: int = 3


@dataclass(slots=True)
class Config:
    http: HttpCfg = field(default_factory=HttpCfg)
    scan: ScanCfg = field(default_factory=ScanCfg)
    vuln: VulnCfg = field(default_factory=VulnCfg)
    discord: DiscordCfg = field(default_factory=DiscordCfg)
    engines: dict[str, EngineCfg] = field(default_factory=dict)
    data_dir: Path = Path("data")
    log_dir: Path = Path("logs")
    export_dir: Path = Path("exports")
    log_level: str = "INFO"
    health_port: int = 8091
    prune_interval: int = 21600
    prune_after_hours: int = 72

    @property
    def db_path(self) -> Path:
        return self.data_dir / "idrac.db"


def _sub(raw: dict, key: str, cls):
    data = raw.get(key) or {}
    if not isinstance(data, dict):
        raise ValueError(f"'{key}' must be a mapping")
    allowed = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
    return cls(**{k: v for k, v in data.items() if k in allowed})


def load(path: Path) -> Config:
    raw = _expand(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})
    cfg = Config()
    cfg.http = _sub(raw, "http", HttpCfg)
    cfg.scan = _sub(raw, "scan", ScanCfg)
    cfg.vuln = _sub(raw, "vuln", VulnCfg)
    cfg.discord = _sub(raw, "discord", DiscordCfg)

    if p := raw.get("paths"):
        cfg.data_dir = Path(p.get("data_dir", cfg.data_dir))
        cfg.log_dir = Path(p.get("log_dir", cfg.log_dir))
        cfg.export_dir = Path(p.get("export_dir", cfg.export_dir))
    cfg.log_level = raw.get("log_level", cfg.log_level)
    cfg.health_port = int(raw.get("health_port", cfg.health_port))
    cfg.prune_interval = int(raw.get("prune_interval", cfg.prune_interval))
    cfg.prune_after_hours = int(raw.get("prune_after_hours", cfg.prune_after_hours))

    for name, body in (raw.get("engines") or {}).items():
        body = body or {}
        cfg.engines[name] = EngineCfg(
            name=name, enabled=bool(body.get("enabled", False)),
            interval=int(body.get("interval", 1800)), pages=int(body.get("pages", 2)),
            page_size=int(body.get("page_size", 100)),
            queries=list(body.get("queries") or []),
            rate=float(body.get("rate", 0.4)), burst=int(body.get("burst", 3)))

    for d in (cfg.data_dir, cfg.log_dir, cfg.export_dir):
        d.mkdir(parents=True, exist_ok=True)
    return cfg


class ConfigStore:
    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._cfg = load(self._path)
        self._mtime = self._path.stat().st_mtime

    @property
    def cfg(self) -> Config:
        with self._lock:
            return self._cfg

    def reload(self) -> bool:
        try:
            mtime = self._path.stat().st_mtime
            if mtime == self._mtime:
                return False
            new = load(self._path)
        except Exception:
            return False
        with self._lock:
            self._cfg, self._mtime = new, mtime
        return True
