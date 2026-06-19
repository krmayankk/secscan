"""Network checks using psutil: listening sockets, outbound peers, /etc/hosts tampering."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

import psutil

from ..models import Finding
from ..registry import Check, Context, register


def _pname(pid: int | None) -> str:
    if not pid:
        return "?"
    try:
        return psutil.Process(pid).name()
    except psutil.Error:
        return "?"


@register
class ListeningSocketsCheck(Check):
    name = "network.listen"
    category = "network"
    description = "Listening TCP/UDP sockets, flagging all-interface binds"

    def run(self, ctx: Context) -> Iterable[Finding]:
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            yield self.info("Need root to enumerate all sockets; run with sudo for full view.")
            return
        listeners = [c for c in conns if c.status == psutil.CONN_LISTEN]
        if not listeners:
            yield self.ok("No listening sockets (or none visible without root).")
        for c in listeners:
            ip = c.laddr.ip if c.laddr else "?"
            line = f"{ip}:{c.laddr.port} ({_pname(c.pid)}, pid {c.pid})"
            if ip in ("0.0.0.0", "::", "*"):
                yield self.warn("listening on ALL interfaces", detail=line)
            else:
                yield self.info("listening", detail=line)


@register
class OutboundCheck(Check):
    name = "network.outbound"
    category = "network"
    description = "Established outbound connections (review unknown peers)"

    def run(self, ctx: Context) -> Iterable[Finding]:
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            yield self.info("Need root for full connection list.")
            return
        peers = set()
        for c in conns:
            if c.status == psutil.CONN_ESTABLISHED and c.raddr:
                peers.add((c.raddr.ip, c.raddr.port, _pname(c.pid)))
        if not peers:
            yield self.ok("No established outbound connections.")
        for ip, port, name in sorted(peers)[:40]:
            yield self.info(f"{ip}:{port}  ({name})")
        if peers:
            yield self.info("Review any peer you don't recognize.")


@register
class HostsFileCheck(Check):
    name = "network.hosts"
    category = "network"
    description = "/etc/hosts tampering (bank/AV redirect)"

    SKIP = re.compile(
        r"^\s*#|^\s*$|localhost|127\.0\.0\.1|127\.0\.1\.1|::1|255|ip6-|^\s*0\.0\.0\.0\s*$"
    )

    def run(self, ctx: Context) -> Iterable[Finding]:
        hosts = Path("/etc/hosts")
        if not hosts.is_file():
            return
        bad = [l.strip() for l in hosts.read_text(errors="replace").splitlines()
               if l.strip() and not self.SKIP.search(l)]
        if bad:
            for l in bad:
                yield self.warn("non-standard /etc/hosts entry", detail=l)
            yield self.info("Malware sometimes redirects bank/AV domains here — verify these.")
        else:
            yield self.ok("/etc/hosts looks standard.")
