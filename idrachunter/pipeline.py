"""candidate -> probe -> fingerprint -> store -> report -> vuln check -> alert."""

from __future__ import annotations

import asyncio
import logging
import ssl

from .config import Config
from .cve_2018_1207 import check as cve_check
from .cve_2018_1207 import nuclei_check
from .db import Database
from .fingerprint import fingerprint
from .geoloc import GeoCache
from .http import HttpClient
from .reporter import Reporter

log = logging.getLogger("idrachunter.scrape")


class Pipeline:
    def __init__(self, cfg: Config, http: HttpClient, db: Database, geo: GeoCache,
                 reporter: Reporter) -> None:
        self._cfg = cfg
        self._http = http
        self._db = db
        self._geo = geo
        self._reporter = reporter
        self._seen: set[tuple[str, int]] = set()
        self.counters = {"scanned": 0, "idrac": 0, "vuln": 0, "errors": 0}

    def fresh(self, ip: str, port: int) -> bool:
        key = (ip, port)
        if key in self._seen:
            return False
        self._seen.add(key)
        return True

    async def _cert(self, ip: str, port: int) -> str:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            async with asyncio.timeout(self._cfg.scan.port_timeout):
                _, w = await asyncio.open_connection(ip, port, ssl=ctx, server_hostname=ip)
                der = w.get_extra_info("peercert", binary_form=True)
                w.close()
        except Exception:
            return ""
        if not der:
            return ""
        try:
            from cryptography import x509
            c = x509.load_der_x509_certificate(der)
            return f"{c.subject.rfc4514_string()} | {c.issuer.rfc4514_string()}"
        except Exception:
            return ""

    async def _tcp(self, ip: str, port: int) -> bool:
        try:
            async with asyncio.timeout(self._cfg.scan.port_timeout):
                _, w = await asyncio.open_connection(ip, port)
                w.close()
            return True
        except Exception:
            return False

    async def process(self, ip: str, port: int, source: str) -> None:
        try:
            await self._run(ip, port, source)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.counters["errors"] += 1
            log.debug("pipeline %s:%s -> %s", ip, port, exc)

    async def _run(self, ip: str, port: int, source: str) -> None:
        if not await self._tcp(ip, port):
            return
        self.counters["scanned"] += 1
        await self._db.bump("scanned")

        tls = port in (443, 8443)
        cert = await self._cert(ip, port) if tls else ""
        fp = await fingerprint(self._http, ip, port, tls, cert)

        if fp.score < self._cfg.scan.identify_threshold or fp.generation is None:
            return

        self.counters["idrac"] += 1
        geo = await self._geo.enrich(ip)
        is_new = await self._db.record_host(
            ip=ip, port=port, generation=fp.generation, source=source,
            title=fp.title, country=geo.country, asn=geo.asn, org=geo.org,
            firmware=fp.firmware, notes=fp.notes)

        if is_new:
            await self._reporter.discovery(
                ip=ip, port=port, generation=fp.generation, title=fp.title,
                country=geo.country, asn=geo.asn, org=geo.org, source=source)

        if fp.generation in (7, 8) and self._cfg.vuln.enabled:
            await asyncio.sleep(self._cfg.vuln.request_delay)
            verdict = await cve_check(self._http, ip, port, tls, fp.firmware,
                                      self._cfg.vuln.request_delay)
            if not verdict.vulnerable and self._cfg.vuln.nuclei_binary:
                deeper = await nuclei_check(self._cfg.vuln.nuclei_binary, ip, port, tls,
                                            self._cfg.vuln.nuclei_timeout)
                if deeper:
                    verdict = deeper
            if verdict.vulnerable:
                if self._cfg.vuln.require_high_confidence and verdict.confidence < 85:
                    return
                self.counters["vuln"] += 1
                await self._db.bump("vuln")
                new_vuln = await self._db.record_vuln(
                    ip=ip, port=port, generation=fp.generation, source=source,
                    title=fp.title, country=geo.country, asn=geo.asn, org=geo.org,
                    firmware=fp.firmware, confidence=verdict.confidence,
                    proof=verdict.proof)
                if new_vuln:
                    log.info("VULN %s:%s conf=%d %s", ip, port, verdict.confidence,
                             verdict.proof)
                    await self._reporter.vuln_alert(
                        ip=ip, port=port, generation=fp.generation,
                        confidence=verdict.confidence, firmware=fp.firmware,
                        proof=verdict.proof, country=geo.country, org=geo.org)
