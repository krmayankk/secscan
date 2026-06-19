"""SSH authorized_keys and risky client-config directives."""
from __future__ import annotations

import re
from typing import Iterable

from ..models import Finding
from ..registry import Check, Context, register

_RISKY = re.compile(r"ProxyCommand|LocalForward|RemoteForward|PermitLocalCommand", re.I)


@register
class SshKeysCheck(Check):
    name = "ssh.keys"
    category = "ssh"
    description = "authorized_keys (inbound logins) and risky ssh config"

    def run(self, ctx: Context) -> Iterable[Finding]:
        ak = ctx.home / ".ssh/authorized_keys"
        if ak.is_file():
            keys = [l for l in ak.read_text(errors="replace").splitlines()
                    if l.strip() and not l.strip().startswith("#")]
            if keys:
                yield self.warn(
                    f"{len(keys)} key(s) can log into this account — confirm you recognize each",
                    detail="; ".join(self._fingerprint(k) for k in keys),
                    remediation="Remove any key you don't recognize from ~/.ssh/authorized_keys.",
                )
            else:
                yield self.ok("authorized_keys present but empty.")
        else:
            yield self.ok("No ~/.ssh/authorized_keys (no inbound key logins).")

        cfg = ctx.home / ".ssh/config"
        if cfg.is_file():
            for i, line in enumerate(cfg.read_text(errors="replace").splitlines(), 1):
                if _RISKY.search(line):
                    yield self.warn(f"ssh config directive worth reviewing (line {i})",
                                    detail=line.strip())

    @staticmethod
    def _fingerprint(key: str) -> str:
        parts = key.split()
        kind = parts[0] if parts else "?"
        comment = parts[-1] if len(parts) > 2 else "(no comment)"
        return f"{kind} {comment}"
