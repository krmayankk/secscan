"""Explicit, opt-in cleanup commands.

Scanning never modifies the system. Each `fix-*` subcommand does exactly one
well-understood cleanup: it prints what it would change (dry run) and only
writes when invoked with --yes. Anything it rewrites is backed up first.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess

from .checks.browser import _chrome_profiles, chrome_notification_grants, is_suspicious_host
from .registry import Context


def _browser_running() -> bool:
    try:
        return subprocess.run(["pgrep", "-x", "chrome|chromium|brave"],
                              capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False  # can't tell; the JSON rewrite is still atomic-enough


def fix_notifications(ctx: Context, apply: bool) -> int:
    """Remove suspicious-host notification ALLOW grants from Chromium prefs."""
    found = 0
    for prefs in _chrome_profiles(ctx):
        bad = [h for h in chrome_notification_grants(prefs) if is_suspicious_host(h)]
        if not bad:
            continue
        found += len(bad)
        for host in bad:
            print(f"{'removing' if apply else 'would remove'}: {host}  ({prefs})")
        if not apply:
            continue
        if _browser_running():
            print("Refusing to edit Preferences while the browser is running — "
                  "close it and re-run.")
            return 2
        data = json.loads(prefs.read_text(errors="replace"))
        exc = (data.get("profile", {}).get("content_settings", {})
                   .get("exceptions", {}).get("notifications", {}))
        for site in [s for s in exc
                     if is_suspicious_host(s.split("//")[-1].split(":")[0].split(",")[0])]:
            del exc[site]
        backup = prefs.parent / (prefs.name + ".secscan-bak")
        shutil.copy2(prefs, backup)
        prefs.write_text(json.dumps(data))
        print(f"cleaned {prefs} (backup: {backup.name})")
    if not found:
        print("No suspicious notification grants found — nothing to do.")
    elif not apply:
        print("Dry run. Close your browser and re-run with --yes to apply.")
    return 0


def fix_autostart(ctx: Context, apply: bool) -> int:
    """Remove broken/unreadable XDG autostart entries (uninstaller leftovers)."""
    autostart = ctx.home / ".config/autostart"
    found = 0
    if autostart.is_dir():
        for entry in sorted(autostart.iterdir()):
            if entry.suffix != ".desktop":
                continue
            broken = entry.is_symlink() and not entry.exists()
            if not broken:
                try:
                    entry.read_text(errors="replace")
                    continue  # readable entry: report-only, never auto-delete
                except OSError:
                    pass
            found += 1
            why = "broken symlink" if broken else "unreadable"
            print(f"{'removing' if apply else 'would remove'}: {entry}  ({why})")
            if apply:
                entry.unlink()
    if not found:
        print("No broken autostart entries — nothing to do.")
    elif not apply:
        print("Dry run. Re-run with --yes to apply.")
    return 0


_COMMANDS = {
    "fix-notifications": (fix_notifications,
                          "remove spam notification grants (Chromium; browser closed)"),
    "fix-autostart": (fix_autostart,
                      "remove broken/unreadable autostart .desktop leftovers"),
}


def main(argv: list[str]) -> int:
    cmd = argv[0]
    parser = argparse.ArgumentParser(prog=f"secscan {cmd}",
                                     description=_COMMANDS[cmd][1])
    parser.add_argument("--yes", action="store_true",
                        help="actually apply the change (default: dry run)")
    args = parser.parse_args(argv[1:])
    return _COMMANDS[cmd][0](Context(), args.yes)
