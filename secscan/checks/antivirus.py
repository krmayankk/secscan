"""Detect installed AV/rootkit scanners and suggest how to run them."""
from __future__ import annotations

import shutil
from typing import Iterable

from ..models import Finding
from ..registry import Check, Context, register

_TOOLS = {
    "clamscan": ("clamav", "clamscan -r -i --bell ~  (run 'sudo freshclam' first)"),
    "rkhunter": ("rkhunter", "sudo rkhunter --update && sudo rkhunter --check --sk"),
    "chkrootkit": ("chkrootkit", "sudo chkrootkit"),
}


@register
class AvToolingCheck(Check):
    name = "av.tooling"
    category = "antivirus"
    description = "Presence of clamav / rkhunter / chkrootkit"

    def run(self, ctx: Context) -> Iterable[Finding]:
        for binary, (pkg, howto) in _TOOLS.items():
            if shutil.which(binary):
                yield self.ok(f"{binary} installed.", detail=f"deep scan: {howto}")
            else:
                yield self.info(f"{binary} not installed.",
                                remediation=f"sudo apt install {pkg}")
