"""Persistence mechanisms: cron, systemd user units, autostart, shell rc, ld.so.preload."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Iterable

from ..models import Finding
from ..registry import Check, Context, register

# payload patterns commonly injected into shell rc files
_RC_PAYLOAD = re.compile(
    r"curl[^|]*\|\s*(ba)?sh|wget[^|]*\|\s*(ba)?sh|base64\s+-d|"
    r"eval\s+.*\$\(curl|/tmp/[^\s]*\.(sh|py)|nc\s+-e|/dev/tcp/",
    re.IGNORECASE,
)


@register
class CronCheck(Check):
    name = "persistence.cron"
    category = "persistence"
    description = "User crontab and recently-changed system cron files"

    def run(self, ctx: Context) -> Iterable[Finding]:
        try:
            out = subprocess.run(["crontab", "-l"], capture_output=True,
                                 text=True, timeout=10).stdout
            lines = [l for l in out.splitlines() if l.strip() and not l.strip().startswith("#")]
        except (FileNotFoundError, subprocess.SubprocessError):
            lines = []
        if lines:
            for l in lines:
                yield self.warn("user crontab entry", detail=l)
        else:
            yield self.ok("No user crontab entries.")


@register
class SystemdUserUnitsCheck(Check):
    name = "persistence.systemd"
    category = "persistence"
    description = "Per-user systemd service units"

    def run(self, ctx: Context) -> Iterable[Finding]:
        sysd = ctx.home / ".config/systemd/user"
        if not sysd.is_dir():
            yield self.ok("No per-user systemd units.")
            return
        for unit in sysd.glob("*.service"):
            execs = [l.strip() for l in unit.read_text(errors="replace").splitlines()
                     if l.startswith("ExecStart=")]
            yield self.info(f"user service: {unit.name}", detail="; ".join(execs) or None)


@register
class AutostartCheck(Check):
    name = "persistence.autostart"
    category = "persistence"
    description = "XDG autostart .desktop entries"

    def run(self, ctx: Context) -> Iterable[Finding]:
        user_dir = ctx.home / ".config/autostart"
        entries = sorted(user_dir.glob("*.desktop")) if user_dir.is_dir() else []
        for desktop in entries:
            try:
                text = desktop.read_text(errors="replace")
            except OSError:
                # dangling symlink or unreadable entry
                yield self.warn(f"user autostart unreadable: {desktop.name}")
                continue
            exec_line = next((l for l in text.splitlines() if l.startswith("Exec=")), "")
            # user-level autostart is a favourite persistence spot -> WARN
            yield self.warn(f"user autostart: {desktop.name}", detail=exec_line or None)
        sysroot = Path("/etc/xdg/autostart")
        if sysroot.is_dir():
            count = len(list(sysroot.glob("*.desktop")))
            yield self.info(f"{count} system autostart entries (distro defaults).")


@register
class ShellRcCheck(Check):
    name = "persistence.shellrc"
    category = "persistence"
    description = "Payload patterns injected into shell startup files"

    FILES = [".bashrc", ".profile", ".bash_profile", ".bash_aliases", ".zshrc",
             ".bash_login", ".zprofile"]

    def run(self, ctx: Context) -> Iterable[Finding]:
        any_file = False
        for rel in self.FILES:
            rc = ctx.home / rel
            if not rc.is_file():
                continue
            any_file = True
            hit = False
            for i, line in enumerate(rc.read_text(errors="replace").splitlines(), 1):
                if _RC_PAYLOAD.search(line):
                    hit = True
                    yield self.high(f"Suspicious line in {rel}:{i}", detail=line.strip())
            if not hit:
                yield self.ok(f"{rel} clean of obvious payload patterns.")
        if not any_file:
            yield self.ok("No shell rc files present.")


@register
class PreloadHijackCheck(Check):
    name = "persistence.preload"
    category = "persistence"
    description = "/etc/ld.so.preload and LD_PRELOAD hijacks"

    def run(self, ctx: Context) -> Iterable[Finding]:
        preload = Path("/etc/ld.so.preload")
        if preload.is_file() and preload.read_text(errors="replace").strip():
            yield self.high("/etc/ld.so.preload is non-empty",
                            detail=preload.read_text(errors="replace").strip(),
                            remediation="A non-empty ld.so.preload is a classic rootkit hook. "
                                        "Verify every library listed.")
        else:
            yield self.ok("/etc/ld.so.preload empty or absent.")
        for rel in (".bashrc", ".profile"):
            f = ctx.home / rel
            if f.is_file() and "LD_PRELOAD" in f.read_text(errors="replace"):
                yield self.warn(f"LD_PRELOAD referenced in {rel}")
