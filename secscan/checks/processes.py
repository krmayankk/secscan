"""Process-based checks using psutil: deleted binaries, miners, temp/hidden execution."""
from __future__ import annotations

import re
from typing import Iterable

import psutil

from ..models import Finding
from ..registry import Check, Context, register

_MINER = re.compile(
    r"\b(xmrig|minerd|cpuminer|cryptonight|kdevtmpfsi|kinsing|nicehash|"
    r"ethminer|phoenixminer)\b|stratum\+tcp",
    re.IGNORECASE,
)
# hidden home dirs that are legitimately full of executables
_ALLOWED_HIDDEN = re.compile(
    r"/\.(config|cache|local|nvm|vscode|dotnet|nuget|npm|m2|cargo|rustup|"
    r"pyenv|conda|gem|cabal|steam|mozilla|java|gradle)/"
)
_SUSPICIOUS_EXE_DIR = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")


@register
class DeletedBinaryCheck(Check):
    name = "process.deleted"
    category = "process"
    description = "Processes running from a deleted/anonymous binary"

    def run(self, ctx: Context) -> Iterable[Finding]:
        suspicious = 0
        upgraded = 0
        for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
            try:
                exe = proc.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            # psutil strips the " (deleted)" suffix; detect via /proc fallback
            deleted = self._is_deleted(proc.pid)
            if not deleted and "memfd:" not in exe:
                continue
            cmd = " ".join(proc.info["cmdline"] or [proc.info["name"] or "?"])
            if (exe.startswith(_SUSPICIOUS_EXE_DIR) or exe.startswith(str(ctx.home))
                    or "memfd:" in exe or "/." in exe):
                suspicious += 1
                yield self.high(
                    f"PID {proc.pid} runs a deleted binary from a suspicious path",
                    detail=f"{exe}  cmd={cmd}",
                    remediation="Investigate this process; malware often unlinks its own binary.",
                )
            elif exe.startswith(("/usr", "/bin", "/sbin", "/lib", "/opt", "/snap")):
                upgraded += 1
            else:
                yield self.warn(f"PID {proc.pid} runs a deleted binary", detail=f"{exe}  cmd={cmd}")
        if suspicious == 0:
            yield self.ok("No processes running deleted binaries from suspicious paths.")
        if upgraded:
            yield self.info(
                f"{upgraded} system process(es) run a since-upgraded binary "
                "(normal after apt updates; a reboot/relogin clears it)."
            )

    @staticmethod
    def _is_deleted(pid: int) -> bool:
        try:
            import os
            return "(deleted)" in os.readlink(f"/proc/{pid}/exe")
        except OSError:
            return False


@register
class MalwareProcessCheck(Check):
    name = "process.malware"
    category = "process"
    description = "Crypto-miner signatures and execution from temp/hidden dirs"

    def run(self, ctx: Context) -> Iterable[Finding]:
        clean = True
        for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
            try:
                cmd = " ".join(proc.info["cmdline"] or [])
                exe = proc.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if not cmd:
                continue
            if _MINER.search(cmd) or _MINER.search(exe):
                clean = False
                yield self.high("crypto-miner signature", detail=f"PID {proc.pid}: {cmd}")
                continue
            if exe.startswith(_SUSPICIOUS_EXE_DIR):
                clean = False
                yield self.warn("process running from a temp directory",
                                detail=f"PID {proc.pid}: {exe}")
                continue
            hidden = f"{ctx.home}/."
            if exe.startswith(hidden) and not _ALLOWED_HIDDEN.search(exe):
                clean = False
                yield self.warn("process running from a hidden home directory",
                                detail=f"PID {proc.pid}: {exe}")
        if clean:
            yield self.ok("No miner signatures or temp/hidden-dir execution.")


@register
class TopCpuCheck(Check):
    name = "process.topcpu"
    category = "process"
    description = "Top CPU consumers (informational)"

    def run(self, ctx: Context) -> Iterable[Finding]:
        psutil.cpu_percent()  # prime the per-process counters
        procs = []
        for proc in psutil.process_iter(["pid", "name", "username"]):
            try:
                procs.append((proc.cpu_percent(), proc))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        procs.sort(key=lambda t: t[0], reverse=True)
        for pct, proc in procs[:5]:
            yield self.info(
                f"{proc.info['name']} (PID {proc.pid}) "
                f"{proc.info['username']} cpu~{pct:.0f}%"
            )
