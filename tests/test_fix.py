import json
import os

import secscan.fix as fix
from secscan.registry import Context


def _ctx(tmp_path):
    return Context(home=tmp_path)


# --- fix-autostart ---

def _autostart(tmp_path):
    d = tmp_path / ".config/autostart"
    d.mkdir(parents=True)
    (d / "good.desktop").write_text("[Desktop Entry]\nExec=/usr/bin/thing\n")
    (d / "dangling.desktop").symlink_to(tmp_path / "gone/nothing.desktop")
    return d


def test_fix_autostart_dry_run_removes_nothing(tmp_path, capsys):
    d = _autostart(tmp_path)
    assert fix.fix_autostart(_ctx(tmp_path), apply=False) == 0
    assert (d / "dangling.desktop").is_symlink()
    assert "would remove" in capsys.readouterr().out


def test_fix_autostart_removes_only_broken(tmp_path):
    d = _autostart(tmp_path)
    assert fix.fix_autostart(_ctx(tmp_path), apply=True) == 0
    assert not os.path.lexists(d / "dangling.desktop")
    assert (d / "good.desktop").is_file()


# --- fix-notifications ---

def _prefs(tmp_path):
    prof = tmp_path / ".config/google-chrome/Default"
    prof.mkdir(parents=True)
    p = prof / "Preferences"
    p.write_text(json.dumps({
        "profile": {"content_settings": {"exceptions": {"notifications": {
            "https://claude.ai:443,*": {"setting": 1},
            "https://x9k3mz81qq7wld.evil.com:443,*": {"setting": 1},
        }}}}
    }))
    return p


def test_fix_notifications_dry_run(tmp_path, capsys):
    p = _prefs(tmp_path)
    before = p.read_text()
    assert fix.fix_notifications(_ctx(tmp_path), apply=False) == 0
    assert p.read_text() == before
    assert "would remove: x9k3mz81qq7wld.evil.com" in capsys.readouterr().out


def test_fix_notifications_apply_removes_spam_keeps_good(tmp_path, monkeypatch):
    p = _prefs(tmp_path)
    monkeypatch.setattr(fix, "_browser_running", lambda: False)
    assert fix.fix_notifications(_ctx(tmp_path), apply=True) == 0
    grants = json.loads(p.read_text())["profile"]["content_settings"][
        "exceptions"]["notifications"]
    assert list(grants) == ["https://claude.ai:443,*"]
    assert (p.parent / "Preferences.secscan-bak").is_file()  # backup written


def test_fix_notifications_refuses_while_browser_running(tmp_path, monkeypatch):
    p = _prefs(tmp_path)
    before = p.read_text()
    monkeypatch.setattr(fix, "_browser_running", lambda: True)
    assert fix.fix_notifications(_ctx(tmp_path), apply=True) == 2
    assert p.read_text() == before
