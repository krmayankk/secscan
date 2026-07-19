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


# --- extension permission risk -------------------------------------------
# Extensions are a top consumer attack vector: a malicious or bought-out
# extension with broad permissions can read every page (including banking
# sessions), steal cookies, or reroute traffic. We grade each installed
# extension by what its manifest *can* do, not by reputation.

_ALL_URLS = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*")
_BROAD_WITH_ALL_URLS = ("cookies", "webRequest", "scripting", "history",
                        "clipboardRead")


def extension_risk(manifest: dict) -> tuple[str, list[str]]:
    """Grade a manifest: ('high'|'warn'|'ok', human-readable reasons)."""
    perms = {str(p) for p in (manifest.get("permissions") or [])
             if isinstance(p, (str, int))}
    perms |= {str(p) for p in (manifest.get("optional_permissions") or [])
              if isinstance(p, (str, int))}
    hosts = {str(p) for p in (manifest.get("host_permissions") or [])}  # MV3
    all_urls = bool((perms | hosts) & set(_ALL_URLS))

    level, reasons = "ok", []
    if "proxy" in perms:
        level = "high"
        reasons.append("can silently reroute all your traffic ('proxy')")
    if "debugger" in perms:
        level = "high"
        reasons.append("can attach to any tab and read sessions/cookies ('debugger')")
    if all_urls:
        broad = sorted(p for p in perms if p in _BROAD_WITH_ALL_URLS)
        if broad:
            if level != "high":
                level = "warn"
            reasons.append("can read/modify every site you visit "
                           f"(<all_urls> + {', '.join(broad)})")
        else:
            if level == "ok":
                level = "warn"
            reasons.append("has access to every website (<all_urls>)")
    if "nativeMessaging" in perms:
        if level == "ok":
            level = "warn"
        reasons.append("can talk to native programs on your machine "
                       "('nativeMessaging')")
    return level, reasons


@register
class ExtensionInventoryCheck(Check):
    name = "browser.extensions"
    category = "browser"
    description = "Installed Chromium extensions, graded by permission risk"

    def run(self, ctx: Context) -> Iterable[Finding]:
        seen = False
        for root in (ctx.home / ".config/google-chrome",
                     ctx.home / ".config/chromium",
                     ctx.home / ".config/BraveSoftware/Brave-Browser"):
            for extdir in root.glob("*/Extensions/*"):
                if not extdir.is_dir():
                    continue
                seen = True
                name, manifest = self._ext_manifest(extdir)
                name = name or extdir.name
                level, reasons = extension_risk(manifest or {})
                # Web Store CRXs unpack with a signed _metadata dir; its absence
                # means the extension was side-loaded — the riskier install path.
                sideloaded = not any(v.is_dir() for v in extdir.glob("*/_metadata"))
                if sideloaded and level != "ok":
                    reasons.append("side-loaded (not installed from the Web Store)")
                if level == "high" and not sideloaded:
                    level = "warn"  # store-signed: dangerous but user-chosen
                if level == "high":
                    yield self.high(
                        f"extension '{name}' has dangerous permissions",
                        detail=f"{extdir.name}: " + "; ".join(reasons),
                        remediation="Fine only if you installed and fully trust it. "
                                    "Otherwise remove it in chrome://extensions.",
                    )
                elif level == "warn":
                    yield self.warn(
                        f"extension '{name}' has broad permissions",
                        detail=f"{extdir.name}: " + "; ".join(reasons),
                        remediation="Normal for ad-blockers/password managers you "
                                    "chose; a red flag on anything unfamiliar.",
                    )
                else:
                    yield self.info(f"extension: {name}", detail=extdir.name)
        if not seen:
            yield self.ok("No unpacked Chromium extensions installed.")
        else:
            yield self.info(
                "Review extensions you don't recognize.",
                remediation="chrome://extensions — remove anything unfamiliar.",
            )

    @staticmethod
    def _ext_manifest(extdir: Path) -> tuple[str | None, dict | None]:
        # newest version dir last — that's the live one
        for manifest in sorted(extdir.glob("*/manifest.json"), reverse=True):
            try:
                data = json.loads(manifest.read_text(errors="replace"))
                return data.get("name"), data
            except (json.JSONDecodeError, OSError):
                continue
        return None, None
