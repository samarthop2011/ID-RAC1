"""Country/ASN enrichment via ip-api.com batch, cached and rate-capped."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from .http import HttpClient
from .ratelimit import TokenBucket

log = logging.getLogger("idrachunter.scrape")


@dataclass(slots=True)
class Geo:
    country: str = ""
    asn: str = ""
    org: str = ""


class GeoCache:
    def __init__(self, http: HttpClient) -> None:
        self._http = http
        self._cache: dict[str, Geo] = {}
        self._bucket = TokenBucket(0.7, 2)

    def get(self, ip: str) -> Geo:
        return self._cache.get(ip, Geo())

    async def enrich(self, ip: str) -> Geo:
        if ip in self._cache:
            return self._cache[ip]
        await self._bucket.acquire()
        st, _, body = await self._http.get(
            f"http://ip-api.com/json/{ip}?fields=country,as,org,status", retries=1)
        geo = Geo()
        if st == 200 and '"success"' in body:
            import json
            try:
                doc = json.loads(body)
            except ValueError:
                doc = {}
            geo = Geo(country=str(doc.get("country") or ""),
                      asn=str(doc.get("as") or ""), org=str(doc.get("org") or ""))
        self._cache[ip] = geo
        await asyncio.sleep(0.05)
        return geo
