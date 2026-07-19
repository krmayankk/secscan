import types

import psutil

from secscan.checks.stealer import (
    SecretsAccessCheck,
    classify_secret_path,
    is_allowed_reader,
)
from secscan.models import Severity
from secscan.registry import Context

HOME = "/home/alice"


def _cls(path):
    return classify_secret_path(path, HOME)


def test_classifies_browser_credential_dbs():
    assert _cls(f"{HOME}/.config/google-chrome/Default/Cookies").high
    assert _cls(f"{HOME}/.config/chromium/Default/Login Data").high
    assert _cls(f"{HOME}/.mozilla/firefox/x.default/cookies.sqlite").high
    # ordinary profile files are not secrets
    assert _cls(f"{HOME}/.config/google-chrome/Default/History") is None


def test_classifies_keys_creds_wallets():
    assert "SSH" in _cls(f"{HOME}/.ssh/id_ed25519").label
    assert _cls(f"{HOME}/.ssh/known_hosts") is None
    assert "AWS" in _cls(f"{HOME}/.aws/credentials").label
    assert "Kubernetes" in _cls(f"{HOME}/.kube/config").label
    assert "wallet" in _cls(f"{HOME}/.electrum/wallets/default_wallet").label
    assert _cls("/etc/passwd") is None


def test_env_files_are_warn_not_high():
    sc = _cls(f"{HOME}/projects/app/.env")
    assert sc is not None and not sc.high


def test_allowed_readers():
    ssh = _cls(f"{HOME}/.ssh/id_rsa")
    assert is_allowed_reader(ssh, "ssh-agent", "ssh-agent")
    assert is_allowed_reader(ssh, "python3", "/usr/bin/git credential-helper")
    assert not is_allowed_reader(ssh, "python3", "python3 /tmp/collect.py")
    # backup/AV tools may read anything
    assert is_allowed_reader(ssh, "clamscan", "clamscan -r /home")


class FakeProc:
    def __init__(self, pid, name, cmdline, paths, peers=()):
        self.pid = pid
        self.info = {"pid": pid, "name": name, "cmdline": cmdline,
                     "username": "alice"}
        self._paths = paths
        self._peers = peers

    def open_files(self):
        return [types.SimpleNamespace(path=p) for p in self._paths]

    def net_connections(self, kind="inet"):
        out = []
        for ip, port in self._peers:
            out.append(types.SimpleNamespace(
                raddr=types.SimpleNamespace(ip=ip, port=port),
                status=psutil.CONN_ESTABLISHED))
        return out


def _run_with(monkeypatch, procs):
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: iter(procs))
    return list(SecretsAccessCheck().run(Context(home=__import__("pathlib").Path(HOME))))


def test_stealer_flagged_high_with_outbound(monkeypatch):
    evil = FakeProc(4242, "python3", ["python3", "/tmp/x.py"],
                    [f"{HOME}/.config/google-chrome/Default/Cookies"],
                    peers=[("203.0.113.7", 443)])
    findings = _run_with(monkeypatch, [evil])
    f = next(f for f in findings if f.severity == Severity.HIGH)
    assert "4242" in f.title and "network" in f.title
    assert "203.0.113.7:443" in f.detail


def test_browser_reading_own_db_is_clean(monkeypatch):
    chrome = FakeProc(1000, "chrome", ["/opt/google/chrome/chrome"],
                      [f"{HOME}/.config/google-chrome/Default/Cookies"])
    findings = _run_with(monkeypatch, [chrome])
    assert all(f.severity == Severity.OK for f in findings)
