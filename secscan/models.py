"""Typed, validated data model for scan findings."""
from __future__ import annotations

import enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(enum.IntEnum):
    """Ordered so we can sort/threshold numerically (higher = worse)."""

    OK = 0
    INFO = 1
    WARN = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name

    @property
    def color(self) -> str:
        return {
            Severity.OK: "green",
            Severity.INFO: "cyan",
            Severity.WARN: "yellow",
            Severity.HIGH: "bold red",
        }[self]


class Finding(BaseModel):
    """A single observation from a check."""

    check: str = Field(..., description="Name of the check that produced this.")
    severity: Severity
    title: str
    detail: Optional[str] = None
    remediation: Optional[str] = None

    def __str__(self) -> str:  # plain-text fallback
        s = f"[{self.severity.label}] {self.title}"
        if self.detail:
            s += f"\n    {self.detail}"
        if self.remediation:
            s += f"\n    -> {self.remediation}"
        return s


class ScanReport(BaseModel):
    """Aggregate result of a scan run."""

    host: str
    user: str
    started_at: str
    findings: list[Finding] = Field(default_factory=list)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def count(self, sev: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == sev)

    @property
    def worst(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.OK)

    @property
    def exit_code(self) -> int:
        return 1 if self.count(Severity.HIGH) > 0 else 0
