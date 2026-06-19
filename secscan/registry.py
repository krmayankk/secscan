"""Check base class, shared scan context, and the check registry."""
from __future__ import annotations

import getpass
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Type

from .models import Finding, Severity


@dataclass
class Context:
    """Shared state handed to every check."""

    home: Path = field(default_factory=lambda: Path.home())
    user: str = field(default_factory=getpass.getuser)
    host: str = field(default_factory=socket.gethostname)
    is_root: bool = field(default_factory=lambda: os.geteuid() == 0)
    quick: bool = False  # skip slow filesystem walks
    # high-risk locations the malware content scan targets. Relative entries are
    # resolved under `home`; absolute entries are used as-is. Overridable so the
    # scan can be pointed at a single directory (and so tests stay isolated).
    risk_dirs: list[str] = field(
        default_factory=lambda: ["Downloads", "/tmp", "/var/tmp", "/dev/shm"]
    )


class Check:
    """Base class. Subclasses set `name`/`category` and implement `run`."""

    name: str = "unnamed"
    category: str = "general"
    description: str = ""

    def run(self, ctx: Context) -> Iterable[Finding]:  # pragma: no cover - abstract
        raise NotImplementedError

    # convenience factories so check code stays terse
    def _f(self, sev: Severity, title: str, detail: str | None = None,
           remediation: str | None = None) -> Finding:
        return Finding(check=self.name, severity=sev, title=title,
                       detail=detail, remediation=remediation)

    def high(self, title, detail=None, remediation=None):
        return self._f(Severity.HIGH, title, detail, remediation)

    def warn(self, title, detail=None, remediation=None):
        return self._f(Severity.WARN, title, detail, remediation)

    def info(self, title, detail=None, remediation=None):
        return self._f(Severity.INFO, title, detail, remediation)

    def ok(self, title, detail=None):
        return self._f(Severity.OK, title, detail)


_REGISTRY: list[Type[Check]] = []


def register(cls: Type[Check]) -> Type[Check]:
    """Class decorator to add a check to the global registry."""
    _REGISTRY.append(cls)
    return cls


def all_checks() -> list[Check]:
    return [cls() for cls in _REGISTRY]


def categories() -> list[str]:
    seen: list[str] = []
    for cls in _REGISTRY:
        if cls.category not in seen:
            seen.append(cls.category)
    return seen
