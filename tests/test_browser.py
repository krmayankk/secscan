import json

from secscan.checks.browser import (
    NotificationSpamCheck,
    chrome_notification_grants,
    is_suspicious_host,
)
from secscan.models import Severity
from secscan.registry import Context


def test_suspicious_host_flags_random_subdomain():
    assert is_suspicious_host("d8p1haghubcc73fl7ri0.vectorgrowthforge.com")
    assert is_suspicious_host("v7x1mz4z78kw1h.vectorgrowthforge.com")


def test_suspicious_host_allows_real_sites():
    for good in ("calendar.google.com", "claude.ai", "app.zoom.us",
                 "chatgpt.com", "www.perplexity.ai", "meet.google.com"):
        assert not is_suspicious_host(good), good


def test_chrome_grants_parsing(tmp_path):
    prefs = tmp_path / "Preferences"
    prefs.write_text(json.dumps({
        "profile": {"content_settings": {"exceptions": {"notifications": {
            "https://claude.ai:443,*": {"setting": 1},
            "https://spam9xk3mz81qq.bad.com:443,*": {"setting": 1},
            "https://blocked.example.com:443,*": {"setting": 2},
        }}}}
    }))
    grants = chrome_notification_grants(prefs)
    assert "claude.ai" in grants
    assert "spam9xk3mz81qq.bad.com" in grants
    assert "blocked.example.com" not in grants  # setting==2 is BLOCK


def test_notification_check_emits_high_for_spam(tmp_path, monkeypatch):
    chrome = tmp_path / ".config/google-chrome/Default"
    chrome.mkdir(parents=True)
    (chrome / "Preferences").write_text(json.dumps({
        "profile": {"content_settings": {"exceptions": {"notifications": {
            "https://x9k3mz81qq7wld.evil.com:443,*": {"setting": 1},
        }}}}
    }))
    ctx = Context(home=tmp_path)
    findings = list(NotificationSpamCheck().run(ctx))
    assert any(f.severity == Severity.HIGH and "evil.com" in f.title for f in findings)
