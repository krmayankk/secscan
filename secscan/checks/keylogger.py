"""Keylogger / input-capture indicators."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

import psutil

from ..models import Finding
from ..registry import Check, Context, register

# legit processes that read /dev/input by design
_LEGIT_INPUT = ("xorg", "gnome", "wayland", "systemd", "ibus", "pipewire",
                "mutter", "kwin", "plasmashell", "spice-vdagent")
_KEYLOG_LIBS = ("pynput", "pyxhook", "evdev", "keyboard")


@register
class InputCaptureCheck(Check):
    name = "keylog.input"
    category = "keylogger"
    description = "Processes holding raw keyboard /dev/input handles"

    def run(self, ctx: Context) -> Iterable[Finding]:
        flagged = False
        input_dir = Path("/dev/input")
        if input_dir.is_dir():
            for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
                try:
                    files = proc.open_files()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                if any("/dev/input/event" in f.path for f in files):
                    name = (proc.info["name"] or "").lower()
                    if any(k in name for k in _LEGIT_INPUT):
                        continue
                    flagged = True
                    cmd = " ".join(proc.info["cmdline"] or [proc.info["name"] or "?"])
                    yield self.high(
                        f"PID {proc.pid} ({proc.info['username']}) holds a raw keyboard handle",
                        detail=cmd,
                        remediation="A non-desktop process reading /dev/input/event* may be logging keystrokes.",
                    )
        if not flagged:
            yield self.ok("No unexpected process reading raw keyboard input.")

        # known keylogger libraries running
        lib_hit = False
        for proc in psutil.process_iter(["pid", "cmdline"]):
            cmd = " ".join(proc.info["cmdline"] or [])
            if any(f" {lib}" in f" {cmd}" or f"/{lib}" in cmd for lib in _KEYLOG_LIBS):
                lib_hit = True
                yield self.warn("input-capture library in a running process",
                                detail=f"PID {proc.pid}: {cmd}")
        if not lib_hit:
            yield self.ok("No known keylogger libraries in running processes.")

        if os.environ.get("XDG_SESSION_TYPE") == "x11":
            yield self.info("Session is X11 — any app can read global keystrokes by design; "
                            "Wayland is stricter.")
