"""Command-line entry point."""
from __future__ import annotations

import argparse
import datetime as _dt
import sys

from rich.console import Console

from . import __version__, checks  # noqa: F401  (import registers checks)
from .models import ScanReport
from .registry import Context, all_checks, categories
from .report import render_console, render_json


def _build_report(ctx: Context, only: list[str] | None) -> ScanReport:
    report = ScanReport(
        host=ctx.host, user=ctx.user,
        started_at=_dt.datetime.now().isoformat(timespec="seconds"),
    )
    for check in all_checks():
        if only and check.category not in only:
            continue
        try:
            for finding in check.run(ctx):
                report.add(finding)
        except Exception as exc:  # one broken check must not kill the scan
            report.add(check.warn(f"check '{check.name}' errored", detail=repr(exc)))
    return report


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    # fix-* subcommands are the only thing secscan ever writes; they live in
    # their own module and are dispatched before scan-flag parsing.
    from .fix import _COMMANDS, main as fix_main
    if argv and argv[0] in _COMMANDS:
        return fix_main(argv)

    parser = argparse.ArgumentParser(
        prog="secscan",
        description="Host security & spam scanner for Linux desktops (read-only).",
        epilog="cleanup subcommands (dry-run unless --yes): "
               + "; ".join(f"{c} — {h}" for c, (_, h) in _COMMANDS.items()),
    )
    parser.add_argument("--version", action="version", version=f"secscan {__version__}")
    parser.add_argument("--quick", action="store_true",
                        help="skip slow filesystem walks (world-writable, SUID).")
    parser.add_argument("--category", action="append", metavar="CAT",
                        help=f"only run a category (repeatable). Available: {', '.join(categories())}")
    parser.add_argument("--target", action="append", metavar="DIR",
                        help="malware content scan: directory to scan (repeatable). "
                             "Overrides the default Downloads/tmp set.")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table.")
    parser.add_argument("--list", action="store_true", help="list all checks and exit.")
    args = parser.parse_args(argv)

    if args.list:
        for check in all_checks():
            print(f"{check.category:12} {check.name:24} {check.description}")
        return 0

    ctx = Context(quick=args.quick)
    if args.target:
        ctx.risk_dirs = args.target
    report = _build_report(ctx, args.category)

    if args.json:
        print(render_json(report))
    else:
        render_console(report, Console())
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
