"""Filesystem checks: recent Download executables, world-writable files, non-standard SUID."""
from __future__ import annotations

import os
import stat
import time
from pathlib import Path
from typing import Iterable

from ..models import Finding
from ..registry import Check, Context, register

_STD_SUID = {
    "sudo", "su", "passwd", "chsh", "chfn", "newgrp", "gpasswd", "mount",
    "umount", "pkexec", "fusermount", "fusermount3", "ping", "ssh-agent",
    "dbus-daemon-launch-helper", "snap-confine", "at", "chrome-sandbox",
    "polkit-agent-helper-1", "vmware-user-suid-wrapper", "Xorg.wrap",
    "pppd", "ssh-keysign", "mount.nfs", "mount.cifs", "ntfs-3g",
    "exim4", "dotlockfile", "unix_chkpwd",
}
_EXEC_SUFFIX = (".sh", ".run", ".appimage", ".deb", ".bin", ".elf")


@register
class DownloadExecCheck(Check):
    name = "fs.downloads"
    category = "filesystem"
    description = "Recently added executables/installers in ~/Downloads"

    def run(self, ctx: Context) -> Iterable[Finding]:
        dl = ctx.home / "Downloads"
        if not dl.is_dir():
            yield self.ok("No Downloads directory.")
            return
        cutoff = time.time() - 45 * 86400
        hits = 0
        for f in dl.rglob("*"):
            try:
                if not f.is_file() or f.stat().st_mtime < cutoff:
                    continue
            except OSError:
                continue
            executable = os.access(f, os.X_OK)
            if executable or f.suffix.lower() in _EXEC_SUFFIX:
                hits += 1
                yield self.warn("recent executable/installer in Downloads", detail=str(f))
        if hits == 0:
            yield self.ok("No recent executables/installers in Downloads.")


@register
class WorldWritableCheck(Check):
    name = "fs.worldwritable"
    category = "filesystem"
    description = "World-writable files under your home (slow; skipped in --quick)"

    def run(self, ctx: Context) -> Iterable[Finding]:
        if ctx.quick:
            yield self.info("Skipped world-writable scan (--quick).")
            return
        count = 0
        skip = ("/.cache/", "/node_modules/", "/.git/")
        for f in ctx.home.rglob("*"):
            if count >= 20:
                yield self.info("... more world-writable files exist (truncated at 20).")
                break
            sp = str(f)
            if any(s in sp for s in skip):
                continue
            try:
                if f.is_file() and (f.stat().st_mode & stat.S_IWOTH):
                    count += 1
                    yield self.warn("world-writable file", detail=sp)
            except OSError:
                continue
        if count == 0:
            yield self.ok("No world-writable files in home (outside caches).")


@register
class SuidCheck(Check):
    name = "fs.suid"
    category = "filesystem"
    description = "Non-standard SUID/SGID binaries (slow; skipped in --quick)"

    def run(self, ctx: Context) -> Iterable[Finding]:
        if ctx.quick:
            yield self.info("Skipped SUID scan (--quick).")
            return
        flagged = 0
        for root in ("/usr", "/bin", "/sbin", "/opt"):
            base = Path(root)
            if not base.exists():
                continue
            for f in base.rglob("*"):
                try:
                    st = f.lstat()
                    if not stat.S_ISREG(st.st_mode) or not (st.st_mode & stat.S_ISUID):
                        continue
                except OSError:
                    continue
                if f.name not in _STD_SUID:
                    flagged += 1
                    yield self.warn("non-standard SUID binary", detail=str(f))
        if flagged == 0:
            yield self.ok("All SUID binaries are on the standard allowlist.")
