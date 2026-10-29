"""iDRAC generation classification. Scored per generation, highest wins."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from .http import HttpClient

log = logging.getLogger("idrachunter.scrape")

TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

PATHS = ["/login.html", "/cgi-bin/webcgi/login", "/cgi-bin/dispatcher.cgi",
         "/redfish/v1/", "/session?aimgettft"]

GEN_RULES: dict[int, list[tuple[str, int, str]]] = {
    6: [(r"idrac\s*6", 50, "title idrac6"),
        (r"integrated dell remote access controller 6", 50, "title idrac6 long"),
        (r"remote access controller 6", 30, "cert/body idrac6"),
        (r"idrac6", 30, "idrac6 token")],
    7: [(r"idrac\s*7", 50, "title idrac7"),
        (r"integrated dell remote access controller 7", 50, "title idrac7 long"),
        (r"remote access controller 7", 30, "cert/body idrac7"),
        (r"idrac7", 30, "idrac7 token")],
    8: [(r"idrac\s*8", 50, "title idrac8"),
        (r"integrated dell remote access controller 8", 50, "title idrac8 long"),
        (r"remote access controller 8", 30, "cert/body idrac8"),
        (r"idrac8", 30, "idrac8 token")],
}

COMMON = [(r"integrated dell remote access controller", 25, "generic idrac title"),
          (r"dell remote access controller", 20, "dell rac title"),
          (r"\bidrac\b", 15, "idrac token"),
          (r"dispatcher\.cgi", 12, "dispatcher path"),
          (r"virtual console", 8, "virtual console"),
          (r"dell", 6, "dell token")]

REDFISH_ONLY_8 = 18
CERT_DELL = 22

FW_RE = re.compile(r"\b(\d\.\d{2}\.\d{2}\.\d{2})\b")


@dataclass(slots=True)
class Fingerprint:
    ip: str
    port: int
    generation: int | None = None
    score: int = 0
    title: str = ""
    firmware: str = ""
    cert: str = ""
    indicators: list[str] = field(default_factory=list)
    base_url: str = ""
    dispatcher_ok: bool = False

    @property
    def alive(self) -> bool:
        return self.score >= 40

    @property
    def notes(self) -> str:
        return "; ".join(self.indicators)


def _add(scores: dict[int, int], ind: list[str], blob: str, scale: float = 1.0) -> None:
    low = blob.lower()
    for gen, rules in GEN_RULES.items():
        for rx, pts, label in rules:
            if re.search(rx, low):
                scores[gen] += int(pts * scale)
                ind.append(label)
    for rx, pts, label in COMMON:
        if re.search(rx, low):
            for gen in scores:
                scores[gen] += int(pts * scale)
            ind.append(label)


async def fingerprint(http: HttpClient, ip: str, port: int, tls: bool,
                      cert: str = "") -> Fingerprint:
    scheme = "https" if tls else "http"
    fp = Fingerprint(ip=ip, port=port, base_url=f"{scheme}://{ip}:{port}", cert=cert)
    scores = {6: 0, 7: 0, 8: 0}
    ind: list[str] = []

    if cert:
        _add(scores, ind, cert)
        if "dell" in cert.lower() or "idrac" in cert.lower():
            for g in scores:
                scores[g] += CERT_DELL
            ind.append("dell/idrac certificate")

    status, headers, body = await http.get(fp.base_url + "/")
    if status:
        _add(scores, ind, headers.get("server", ""))
        if m := TITLE.search(body):
            fp.title = re.sub(r"\s+", " ", m.group(1)).strip()[:180]
            _add(scores, ind, fp.title)

    for path in PATHS:
        st, _, bd = await http.get(fp.base_url + path)
        if st in (0, 404):
            continue
        _add(scores, ind, bd[:4000], 0.6)
        if path == "/redfish/v1/" and st == 200 and '"RedfishVersion"' in bd:
            scores[8] += REDFISH_ONLY_8
            ind.append("redfish service root")
        if path == "/cgi-bin/dispatcher.cgi" and st == 200:
            fp.dispatcher_ok = True
            ind.append("dispatcher.cgi reachable")
        if m := FW_RE.search(bd[:8000]):
            fp.firmware = fp.firmware or m.group(1)

    gen = max(scores, key=lambda g: scores[g])
    fp.generation = gen if scores[gen] > 0 else None
    fp.score = min(100, scores[gen])
    fp.indicators = ind[:14]
    return fp
