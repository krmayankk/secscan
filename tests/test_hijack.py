import json

import secscan.checks.browserhijack as bh
from secscan.checks.browser import ExtensionInventoryCheck, extension_risk
from secscan.models import Severity
from secscan.registry import Context


# --- extension permission risk ---

def test_extension_risk_grades():
    assert extension_risk({})[0] == "ok"
    assert extension_risk({"permissions": ["storage", "alarms"]})[0] == "ok"
    level, reasons = extension_risk(
        {"permissions": ["cookies", "webRequest", "<all_urls>"]})
    assert level == "warn" and any("every site" in r for r in reasons)
    assert extension_risk({"permissions": ["proxy"]})[0] == "high"
    assert extension_risk({"permissions": ["debugger"]})[0] == "high"
    # MV3 puts hosts in host_permissions
    assert extension_risk({"permissions": ["scripting"],
                           "host_permissions": ["<all_urls>"]})[0] == "warn"


def test_sideloaded_dangerous_ext_high_webstore_warn(tmp_path):
    exts = tmp_path / ".config/google-chrome/Default/Extensions"
    store = exts / "aaaa" / "1.0_0"
    store.mkdir(parents=True)
    (store / "manifest.json").write_text(
        json.dumps({"name": "StoreExt", "permissions": ["debugger"]}))
    (store / "_metadata").mkdir()
    side = exts / "bbbb" / "1.0_0"
    side.mkdir(parents=True)
    (side / "manifest.json").write_text(
        json.dumps({"name": "SideExt", "permissions": ["debugger"]}))
    findings = list(ExtensionInventoryCheck().run(Context(home=tmp_path)))
    by_name = {f.title: f.severity for f in findings if "Ext'" in f.title}
    assert by_name["extension 'SideExt' has dangerous permissions"] == Severity.HIGH
    assert by_name["extension 'StoreExt' has broad permissions"] == Severity.WARN


# --- launch flags ---

def test_suspicious_browser_flags():
    hits = bh.suspicious_browser_flags(
        ["--proxy-server=1.2.3.4:8080", "--new-window", "--load-extension=/tmp/x"])
    assert {h[0].split("=")[0] for h in hits} == {"--proxy-server", "--load-extension"}
    assert bh.suspicious_browser_flags(["--profile-directory=Default"]) == []


# --- tampered launchers ---

def test_launcher_url_hijack_flagged(tmp_path):
    apps = tmp_path / ".local/share/applications"
    apps.mkdir(parents=True)
    (apps / "google-chrome.desktop").write_text(
        "[Desktop Entry]\nName=Chrome\n"
        "Exec=/usr/bin/google-chrome-stable https://evil-search.example %U\n")
    findings = list(bh.LauncherTamperCheck().run(Context(home=tmp_path)))
    assert any(f.severity == Severity.HIGH and "fixed URL" in f.title
               for f in findings)


def test_clean_launcher_ok(tmp_path):
    apps = tmp_path / ".local/share/applications"
    apps.mkdir(parents=True)
    (apps / "google-chrome.desktop").write_text(
        "[Desktop Entry]\nExec=/usr/bin/google-chrome-stable %U\n")
    findings = list(bh.LauncherTamperCheck().run(Context(home=tmp_path)))
    assert all(f.severity == Severity.OK for f in findings)


# --- managed policies ---

def test_forcelist_policy_is_high(tmp_path, monkeypatch):
    pdir = tmp_path / "managed"
    pdir.mkdir()
    (pdir / "evil.json").write_text(json.dumps(
        {"ExtensionInstallForcelist": ["aaaa;https://evil.example/crx"]}))
    monkeypatch.setattr(bh, "_POLICY_DIRS", [str(pdir)])
    monkeypatch.setattr(bh, "_FIREFOX_POLICY_FILES", [])
    findings = list(bh.ManagedPolicyCheck().run(Context(home=tmp_path)))
    assert any(f.severity == Severity.HIGH and "ExtensionInstallForcelist" in f.title
               for f in findings)


def test_no_policies_ok(tmp_path, monkeypatch):
    monkeypatch.setattr(bh, "_POLICY_DIRS", [str(tmp_path / "nope")])
    monkeypatch.setattr(bh, "_FIREFOX_POLICY_FILES", [])
    findings = list(bh.ManagedPolicyCheck().run(Context(home=tmp_path)))
    assert all(f.severity == Severity.OK for f in findings)


# --- start page hijack ---

def test_startpage_hijack_flagged(tmp_path):
    prof = tmp_path / ".config/google-chrome/Default"
    prof.mkdir(parents=True)
    (prof / "Preferences").write_text(json.dumps({
        "homepage": "https://p9x2kq7wm31zr8.hijack.example/start",
        "session": {"startup_urls": []},
    }))
    findings = list(bh.StartPageHijackCheck().run(Context(home=tmp_path)))
    assert any(f.severity == Severity.HIGH and "hijacked" in f.title
               for f in findings)


def test_normal_homepage_ok(tmp_path):
    prof = tmp_path / ".config/google-chrome/Default"
    prof.mkdir(parents=True)
    (prof / "Preferences").write_text(json.dumps({"homepage": "https://claude.ai"}))
    findings = list(bh.StartPageHijackCheck().run(Context(home=tmp_path)))
    assert all(f.severity == Severity.OK for f in findings)
