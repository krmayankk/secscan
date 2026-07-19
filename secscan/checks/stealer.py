"""Infostealer / credential-theft canary.

The most common real-world compromise of a personal Linux box today is not a
rootkit but a smash-and-grab infostealer: code that copies browser cookie and
password databases, SSH keys, cloud credentials, or crypto wallets and uploads
them — often leaving no persistent artifact at all. The reliable tell is
behavioral: an unexpected process holding one of those files open, especially
while it also holds an outbound network connection.

This check snapshots `open_files()` for every visible process, so it catches a
stealer mid-read; a scan that runs after the theft finished will not see it.
That is the honest ceiling of a point-in-time scanner — which is why the README
recommends running secscan on a schedule.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import psutil

from ..models import Finding
from ..registry import Check, Context, register


@dataclass(frozen=True)
class SecretClass:
    """A family of secret files plus the processes allowed to read them."""

    label: str
    high: bool                 # HIGH when read by a non-allowlisted process
    readers: tuple[str, ...]   # substrings matched against process name/cmdline


_CHROMIUM_BROWSERS = ("chrome", "chromium", "brave", "vivaldi", "opera", "msedge")

# Tools that legitimately read *everything* (backup, indexing, AV). Matching any
# of these in the process name suppresses the finding for every secret class.
_GLOBAL_READERS = ("clamscan", "clamd", "freshclam", "rkhunter", "chkrootkit",
                   "restic", "borg", "duplicity", "rclone", "rsync", "deja-dup",
                   "timeshift", "baloo", "tracker", "updatedb", "plocate")

_BROWSER_DB_NAMES = ("Cookies", "Login Data", "Login Data For Account", "Web Data")
_FIREFOX_DB_NAMES = ("cookies.sqlite", "logins.json", "key4.db", "signons.sqlite")
_WALLET_DIRS = ("/.electrum", "/.bitcoin", "/.monero", "/.ethereum",
                "/.config/Exodus", "/.config/Ledger Live")

_DEV_READERS = ("node", "npm", "yarn", "pnpm", "python", "docker", "compose",
                "java", "ruby", "php", "code", "uvicorn", "gunicorn", "cargo", "go")


def classify_secret_path(path: str, home: str) -> SecretClass | None:
    """Map an open-file path to the secret family it belongs to (or None)."""
    if not path.startswith(home + "/"):
        return None
    rel = path[len(home):]
    name = rel.rsplit("/", 1)[-1]

    if rel.startswith(("/.config/google-chrome/", "/.config/chromium/",
                       "/.config/BraveSoftware/", "/snap/chromium/")):
        if name in _BROWSER_DB_NAMES:
            return SecretClass("a browser cookie/password database", True,
                               _CHROMIUM_BROWSERS)
        return None
    if rel.startswith("/.mozilla/firefox/") and name in _FIREFOX_DB_NAMES:
        return SecretClass("the Firefox cookie/password database", True, ("firefox",))
    if rel.startswith("/.ssh/") and name not in ("known_hosts", "known_hosts.old"):
        return SecretClass("SSH key material", True,
                           ("ssh", "scp", "sftp", "rsync", "git", "mosh",
                            "gnome-keyring"))
    if rel.startswith("/.gnupg/") and ("private-keys" in rel or "secring" in name):
        return SecretClass("GPG private keys", True, ("gpg",))
    if rel == "/.aws/credentials":
        return SecretClass("AWS credentials", True,
                           ("aws", "terraform", "pulumi", "packer", "ansible", "sam"))
    if rel.startswith("/.config/gcloud/") and (
            "credential" in name or "access_tokens" in name):
        return SecretClass("Google Cloud credentials", True,
                           ("gcloud", "gsutil", "bq", "docker-credential"))
    if rel == "/.kube/config":
        return SecretClass("the Kubernetes config (cluster credentials)", True,
                           ("kubectl", "helm", "k9s", "minikube", "kind", "flux",
                            "argocd", "terraform", "lens"))
    if rel == "/.docker/config.json":
        return SecretClass("Docker registry credentials", True, ("docker",))
    if rel.startswith(_WALLET_DIRS) or name == "wallet.dat":
        return SecretClass("a cryptocurrency wallet", True,
                           ("electrum", "bitcoin", "monero", "geth", "exodus",
                            "ledger"))
    if rel in ("/.netrc", "/.git-credentials"):
        return SecretClass("stored login credentials (netrc/git)", False,
                           ("git", "curl"))
    if name == ".env" or name.startswith(".env."):
        return SecretClass("a .env secrets file", False, _DEV_READERS)
    return None


def is_allowed_reader(sc: SecretClass, proc_name: str, cmdline: str) -> bool:
    name = proc_name.lower()
    cmd = cmdline.lower()
    if any(g in name for g in _GLOBAL_READERS):
        return True
    return any(r in name or r in cmd for r in sc.readers)


@register
class SecretsAccessCheck(Check):
    name = "stealer.secrets"
    category = "stealer"
    description = ("Processes reading browser credential DBs, SSH/GPG keys, "
                   "cloud creds, or crypto wallets")

    def run(self, ctx: Context) -> Iterable[Finding]:
        home = str(ctx.home)
        flagged = False
        for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
            try:
                files = proc.open_files()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if not files:
                continue
            pname = proc.info["name"] or "?"
            cmd = " ".join(proc.info["cmdline"] or [pname])
            hits: dict[str, tuple[SecretClass, str]] = {}
            for f in files:
                sc = classify_secret_path(f.path, home)
                if sc and not is_allowed_reader(sc, pname, cmd):
                    hits.setdefault(sc.label, (sc, f.path))
            if not hits:
                continue
            flagged = True
            peers = self._peers(proc)
            for label, (sc, path) in hits.items():
                detail = f"{path}  cmd: {cmd}"
                if peers:
                    detail += f"  outbound: {', '.join(peers)}"
                title = f"PID {proc.pid} ({proc.info['username']}) is reading {label}"
                if peers and sc.high:
                    title += " while connected to the network"
                sev = self.high if sc.high else self.warn
                yield sev(
                    title, detail=detail,
                    remediation="If you don't recognize this program, treat it as an "
                                "infostealer: kill it, disconnect, and rotate the "
                                "affected credentials.",
                )
        if not flagged:
            yield self.ok("No unexpected process is reading credential stores, "
                          "keys, or wallets.")

    @staticmethod
    def _peers(proc: psutil.Process) -> list[str]:
        """Established remote endpoints of the process, if visible."""
        try:
            # Process.connections() was renamed net_connections() in psutil 6.
            get = getattr(proc, "net_connections", None) or proc.connections
            conns = get(kind="inet")
        except (psutil.Error, OSError):
            return []
        return sorted({f"{c.raddr.ip}:{c.raddr.port}" for c in conns
                       if c.raddr and c.status == psutil.CONN_ESTABLISHED})
