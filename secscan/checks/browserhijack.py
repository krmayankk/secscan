"""Browser integrity / hijack indicators.

Covers the ways adware and stealers take over a browser from the *outside*:
suspicious launch flags on running browsers, tampered .desktop launchers
(homepage hijack), forced enterprise policies, and startup/homepage settings
pointing at throwaway spam domains.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import psutil

from ..models import Finding
from ..registry import Check, Context, register
from .browser import _chrome_profiles, is_suspicious_host

_CHROMIUM = ("chrome", "chromium", "brave", "vivaldi", "opera", "msedge")

# flag -> why it matters
_FLAG_REASONS = {
    "--load-extension": "side-loads an extension that never went through the Web Store",
    "--disable-extensions-except": "side-loads an extension bypassing the Web Store",
    "--proxy-server": "routes all browsing through a proxy",
    "--proxy-pac-url": "routes browsing via a remote proxy autoconfig script",
    "--remote-debugging-port": "opens a debug port that lets any local process "
                               "read cookies and control the browser",
    "--remote-debugging-pipe": "exposes a debug channel that can read cookies "
                               "and control the browser",
    "--disable-web-security": "turns off the same-origin policy",
    "--ignore-certificate-errors": "accepts forged HTTPS certificates",
}

# Chromium/Firefox managed-policy locations (system-wide, applied silently).
_POLICY_DIRS = [
    "/etc/opt/chrome/policies/managed",
    "/etc/opt/edge/policies/managed",
    "/etc/chromium/policies/managed",
    "/etc/chromium-browser/policies/managed",
    "/etc/brave/policies/managed",
]
_FIREFOX_POLICY_FILES = [
    "/etc/firefox/policies/policies.json",
    "/usr/lib/firefox/distribution/policies.json",
]

# policy keys that change what the user sees or force-install code
_HIGH_POLICY_KEYS = ("ExtensionInstallForcelist", "ExtensionInstallSources",
                     "ProxySettings", "ProxyMode", "ProxyServer", "ProxyPacUrl")
_WARN_POLICY_KEYS = ("HomepageLocation", "RestoreOnStartupURLs",
                     "DefaultSearchProviderSearchURL", "DefaultSearchProviderEnabled",
                     "NewTabPageLocation")


def suspicious_browser_flags(args: Iterable[str]) -> list[tuple[str, str]]:
    """Return (argument, reason) for each hijack-grade flag in a cmdline."""
    hits = []
    for a in args:
        reason = _FLAG_REASONS.get(a.split("=", 1)[0])
        if reason:
            hits.append((a, reason))
    return hits


@register
class BrowserFlagsCheck(Check):
    name = "browser.flags"
    category = "browser"
    description = "Running browsers launched with hijack-grade flags"

    def run(self, ctx: Context) -> Iterable[Finding]:
        seen: set[tuple[str, tuple[str, ...]]] = set()
        flagged = False
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            name = (proc.info["name"] or "").lower()
            if not any(b in name for b in _CHROMIUM):
                continue
            args = proc.info["cmdline"] or []
            # child processes (--type=renderer/gpu/...) inherit the flags;
            # only report the main browser process
            if any(a.startswith("--type=") for a in args):
                continue
            hits = suspicious_browser_flags(args)
            if not hits:
                continue
            key = (name, tuple(a for a, _ in hits))
            if key in seen:
                continue
            seen.add(key)
            flagged = True
            for arg, reason in hits:
                yield self.warn(
                    f"{name} (PID {proc.pid}) launched with {arg.split('=', 1)[0]}",
                    detail=f"{arg} — {reason}",
                    remediation="Expected if you run browser automation "
                                "(Selenium/Playwright/Claude); otherwise find what "
                                "launched the browser with this flag.",
                )
        if not flagged:
            yield self.ok("No running browser has suspicious launch flags.")


@register
class LauncherTamperCheck(Check):
    name = "browser.launcher"
    category = "browser"
    description = "Tampered browser .desktop launchers (homepage hijack)"

    def run(self, ctx: Context) -> Iterable[Finding]:
        flagged = False
        for d in (ctx.home / ".local/share/applications", ctx.home / "Desktop"):
            if not d.is_dir():
                continue
            for desktop in d.glob("*.desktop"):
                try:
                    text = desktop.read_text(errors="replace")
                except OSError:
                    continue
                for line in text.splitlines():
                    if not line.startswith("Exec="):
                        continue
                    args = line[len("Exec="):].split()
                    if not args or not any(b in args[0].lower()
                                           for b in _CHROMIUM + ("firefox",)):
                        continue
                    urls = [a for a in args[1:] if a.startswith(("http://", "https://"))]
                    if urls:
                        flagged = True
                        yield self.high(
                            f"Browser launcher {desktop.name} opens a fixed URL",
                            detail=line,
                            remediation="Classic homepage hijack: the launcher was "
                                        "edited to always open this site. Delete the "
                                        f"file ({desktop}) to restore the system one.",
                        )
                    for arg, reason in suspicious_browser_flags(args[1:]):
                        flagged = True
                        yield self.high(
                            f"Browser launcher {desktop.name} adds {arg.split('=', 1)[0]}",
                            detail=f"{line} — {reason}",
                            remediation=f"Delete {desktop} to restore the standard launcher.",
                        )
        if not flagged:
            yield self.ok("No tampered browser launchers in user .desktop files.")


@register
class ManagedPolicyCheck(Check):
    name = "browser.policy"
    category = "browser"
    description = "Forced browser policies (force-installed extensions, proxy, search)"

    def run(self, ctx: Context) -> Iterable[Finding]:
        found = False
        for d in _POLICY_DIRS:
            dp = Path(d)
            if not dp.is_dir():
                continue
            for pf in sorted(dp.glob("*.json")):
                found = True
                yield from self._judge(pf)
        for f in _FIREFOX_POLICY_FILES:
            pf = Path(f)
            if pf.is_file():
                found = True
                yield from self._judge(pf)
        if not found:
            yield self.ok("No managed browser policies installed.")

    def _judge(self, pf: Path) -> Iterable[Finding]:
        try:
            data = json.loads(pf.read_text(errors="replace"))
        except (json.JSONDecodeError, OSError):
            yield self.warn(f"Unreadable browser policy file: {pf}")
            return
        keys = self._all_keys(data)
        high = sorted(k for k in keys if k in _HIGH_POLICY_KEYS)
        warn = sorted(k for k in keys if k in _WARN_POLICY_KEYS)
        if high:
            yield self.high(
                f"Browser policy forces {', '.join(high)}",
                detail=str(pf),
                remediation="Policies here silently override user settings and can "
                            "force-install extensions or reroute traffic. Expected on "
                            "a company machine; on a personal one, remove the file "
                            "(needs sudo) and check how it got there.",
            )
        elif warn:
            yield self.warn(f"Browser policy sets {', '.join(warn)}", detail=str(pf))
        else:
            yield self.info(f"Managed browser policy present: {pf}",
                            detail="Normal on a company-managed machine; "
                                   "unexpected on a personal one.")

    @staticmethod
    def _all_keys(obj) -> set[str]:
        keys: set[str] = set()
        if isinstance(obj, dict):
            for k, v in obj.items():
                keys.add(str(k))
                keys |= ManagedPolicyCheck._all_keys(v)
        elif isinstance(obj, list):
            for v in obj:
                keys |= ManagedPolicyCheck._all_keys(v)
        return keys


@register
class StartPageHijackCheck(Check):
    name = "browser.startpage"
    category = "browser"
    description = "Homepage/startup pages pointing at throwaway spam domains"

    def run(self, ctx: Context) -> Iterable[Finding]:
        flagged = False
        for prefs in _chrome_profiles(ctx):
            try:
                data = json.loads(prefs.read_text(errors="replace"))
            except (json.JSONDecodeError, OSError):
                continue
            label = str(prefs.parent).replace(str(ctx.home) + "/", "")
            urls = [data.get("homepage", "")]
            urls += (data.get("session", {}) or {}).get("startup_urls", [])
            search = ((data.get("default_search_provider_data", {}) or {})
                      .get("template_url_data", {}) or {}).get("url", "")
            urls.append(search)
            for url in urls:
                host = url.split("//")[-1].split("/")[0].split(":")[0] if url else ""
                if host and is_suspicious_host(host):
                    flagged = True
                    yield self.high(
                        f"Browser start/search page hijacked to {host}",
                        detail=f"profile: {label}  url: {url}",
                        remediation="Reset homepage, startup pages, and search engine "
                                    "in browser settings; then check extensions.",
                    )
        if not flagged:
            yield self.ok("No hijacked homepage/startup/search settings found.")
