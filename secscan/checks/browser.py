"""Browser checks: push-notification spam grants and extension inventory."""
from __future__ import annotations

import json
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Iterable

from ..models import Finding
from ..registry import Check, Context, register

# A hostname label that is long AND mixes letters+digits is almost always a
# throwaway push-spam subdomain (e.g. d8p1haghubcc73fl7ri0.example.com).
_RANDOMISH = re.compile(r"^(?=.{12,})(?=.*[a-z])(?=.*[0-9])[a-z0-9]+$")


def is_suspicious_host(host: str) -> bool:
    label = host.split(".")[0].lower()
    return bool(_RANDOMISH.match(label))


def _chrome_profiles(ctx: Context) -> list[Path]:
    roots = [
        ctx.home / ".config/google-chrome",
        ctx.home / ".config/chromium",
        ctx.home / "snap/chromium/common/chromium",
    ]
    profiles: list[Path] = []
    for root in roots:
        if root.is_dir():
            profiles.extend(p for p in root.glob("*/Preferences") if p.is_file())
    return profiles


def chrome_notification_grants(prefs: Path) -> list[str]:
    """Return hostnames with notifications == ALLOW (setting==1)."""
    try:
        data = json.loads(prefs.read_text(errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []
    exc = (data.get("profile", {})
               .get("content_settings", {})
               .get("exceptions", {})
               .get("notifications", {}))
    out = []
    for site, val in exc.items():
        if val.get("setting") == 1:
            out.append(site.split("//")[-1].split(":")[0])
    return out


@register
class NotificationSpamCheck(Check):
    name = "browser.notifications"
    category = "browser"
    description = "Web push-notification ALLOW grants (Chrome/Chromium/Firefox)"

    def run(self, ctx: Context) -> Iterable[Finding]:
        seen = False
        for prefs in _chrome_profiles(ctx):
            label = str(prefs.parent).replace(str(ctx.home) + "/", "")
            for host in chrome_notification_grants(prefs):
                seen = True
                if is_suspicious_host(host):
                    yield self.high(
                        f"Suspicious notification grant: {host}",
                        detail=f"profile: {label}",
                        remediation="Revoke in chrome://settings/content/notifications "
                                    "or run: secscan fix-notifications (browser closed).",
                    )
                else:
                    yield self.ok(f"notifications allowed: {host}", detail=label)

        # Firefox stores these in permissions.sqlite (moz_perms).
        for perms in (ctx.home / ".mozilla/firefox").glob("*/permissions.sqlite"):
            seen = True
            yield from self._firefox(perms)

        if not seen:
            yield self.ok("No browser notification grants found.")

    def _firefox(self, perms: Path) -> Iterable[Finding]:
        try:
            with tempfile.NamedTemporaryFile(suffix=".sqlite") as tmp:
                tmp.write(perms.read_bytes())
                tmp.flush()
                con = sqlite3.connect(tmp.name)
                rows = con.execute(
                    "SELECT origin FROM moz_perms "
                    "WHERE type='desktop-notification' AND permission=1"
                ).fetchall()
                con.close()
        except (sqlite3.Error, OSError):
            return
        for (origin,) in rows:
            host = origin.split("://")[-1].split(":")[0]
            if is_suspicious_host(host):
                yield self.high(f"Suspicious Firefox notification grant: {host}")
            else:
                yield self.ok(f"firefox notifications allowed: {host}")


@register
class ExtensionInventoryCheck(Check):
    name = "browser.extensions"
    category = "browser"
    description = "Inventory of installed Chromium extensions"

    def run(self, ctx: Context) -> Iterable[Finding]:
        seen = False
        for root in (ctx.home / ".config/google-chrome",
                     ctx.home / ".config/chromium"):
            for extdir in root.glob("*/Extensions/*"):
                if not extdir.is_dir():
                    continue
                seen = True
                name = self._ext_name(extdir) or extdir.name
                yield self.info(f"extension: {name}", detail=extdir.name)
        if not seen:
            yield self.ok("No unpacked Chromium extensions installed.")
        else:
            yield self.info(
                "Review extensions you don't recognize.",
                remediation="chrome://extensions — remove anything unfamiliar.",
            )

    @staticmethod
    def _ext_name(extdir: Path) -> str | None:
        for manifest in extdir.glob("*/manifest.json"):
            try:
                return json.loads(manifest.read_text(errors="replace")).get("name")
            except (json.JSONDecodeError, OSError):
                continue
        return None
