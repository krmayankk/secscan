# secscan

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

A host security & spam scanner for Ubuntu/Linux desktops. It looks for the
everyday ways a personal machine gets compromised — browser push-notification
spam, keyloggers, reverse shells, crypto-miners, rogue startup entries,
tampered config, and known malware — and reports what it finds in one place.

**Read-only by design.** secscan inspects and reports; it never deletes or
modifies anything on your system. (The one optional write — clearing a spam
notification grant — is a separate, explicit subcommand.)

## Who it's for & why it exists

secscan is for **people who run a Linux desktop and want to keep it clean** —
Ubuntu/Pop!_OS/Mint/Debian/Fedora/Arch users, tinkerers, and home-lab
enthusiasts who treat their machine as their own and want to *know* it's healthy
rather than hope it is.

It was born from an ordinary mishap: clicking a sketchy link and ending up with a
browser spamming fake "your PC is infected" notifications. Cleaning that up by
hand meant digging through Chrome's `Preferences` JSON, checking cron and systemd
for persistence, eyeballing processes for a keylogger, and grepping shell configs
for reverse shells — the same manual checklist every time. secscan turns that
checklist into one repeatable, read-only command.

**Reach for it when:**

- you clicked something you shouldn't have and want a fast once-over,
- you just want a periodic health check (drop it in cron — see below),
- you're handing a machine to someone, or got one secondhand, and want a baseline,
- something *feels* off — fans spinning, network busy — and you want to rule out the obvious.

It is **not** an enterprise EDR or a managed antivirus. It's the tool a careful
hobbyist would write for themselves: transparent (every check is a few dozen
readable lines), dependency-light, read-only, and honest about what it can and
can't see.

## How it works

It combines three detection strategies that cover each other's blind spots:

1. **Behavioral / configuration checks** — system *state* that signals
   compromise (a process holding your keyboard, a rogue cron job, an unknown
   SSH key, an `ld.so.preload` hook). Signature scanners can't see these.
2. **Heuristic content scanning** — matches malicious *techniques* in file
   contents (reverse shells, droppers, webshells, miner configs), so it catches
   brand-new/custom malware that has no signature yet.
3. **ClamAV** *(optional)* — if installed, secscan runs the engine for
   signature detection of known malware families.

---

## Install

Requires Python 3.10+.

```bash
git clone https://github.com/krmayankk/secscan.git   # or your fork
cd secscan
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"        # drop [dev] if you don't want pytest
```

This installs the `secscan` command into the virtualenv.

### Optional: enable signature-based virus scanning

```bash
sudo apt install clamav clamav-daemon
sudo freshclam                 # download the signature database
```

secscan auto-detects ClamAV and runs it as part of the `malware` category. It
uses the `clamd` daemon when it's running (fast, via `--fdpass`) and otherwise
falls back to standalone `clamscan`, so it works whether or not you enable the
daemon. If a scan *errors*, secscan reports a WARN — it never passes off a failed
scan as a clean result.

---

## Quickstart

```bash
secscan                 # full scan of the whole machine
secscan --quick         # skip slow filesystem walks (world-writable, SUID)
secscan --list          # show every check
```

Exit code is **`1`** when any HIGH finding is present (else `0`) — handy for
cron, CI, or alerting.

---

## Usage

```
secscan [--quick] [--category CAT ...] [--target DIR ...] [--json] [--list]

--quick            skip slow filesystem walks (world-writable, SUID)
--category CAT     only run the given category (repeatable)
--target DIR       directory for the malware content scan (repeatable;
                   overrides the default Downloads/tmp set)
--json             machine-readable output (diff scans over time, feed a SIEM)
--list             list all checks and exit
--version          print version
```

Examples:

```bash
secscan --category browser --category network   # just those two areas
secscan --category malware --target ~/Downloads # virus-scan one folder
secscan --json > scan-$(date +%F).json          # archive for diffing
```

### Run it on a schedule

A ready-made cron wrapper is included: [`scripts/secscan-weekly.sh`](scripts/secscan-weekly.sh).
It runs one scan, archives a JSON report + text summary under
`~/.local/state/secscan/` (keeping the last 12), updates `latest.json`/`latest.txt`
pointers, and fires a desktop notification if anything HIGH is found.

Install a weekly run (Mondays 09:00):

```bash
(crontab -l 2>/dev/null; echo "0 9 * * 1 $HOME/src/secscan/scripts/secscan-weekly.sh") | crontab -
```

**Seeing the results.** Desktop notifications from cron are best-effort (they
need a live GUI session). For a reliable nudge, add this to your `~/.bashrc` so
new shells warn you only when the last scan found HIGH items (silent when clean):

```bash
if [ -f "$HOME/.local/state/secscan/latest.json" ]; then
  _ss_high=$(grep -c '"severity": 3' "$HOME/.local/state/secscan/latest.json" 2>/dev/null)
  [ "${_ss_high:-0}" -gt 0 ] && \
    printf '\033[1;31m⚠️  secscan: %s HIGH finding(s) — cat %s\033[0m\n' \
      "$_ss_high" "$HOME/.local/state/secscan/latest.txt"
  unset _ss_high
fi
```

Read the latest report any time with `cat ~/.local/state/secscan/latest.txt`.

---

## What it scans

| Category    | Checks |
|-------------|--------|
| browser     | web push-notification spam grants (Chrome/Chromium/Firefox); extension inventory |
| persistence | user crontab; per-user systemd units; XDG autostart; shell-rc payload patterns; `ld.so.preload`/`LD_PRELOAD` hijacks |
| keylogger   | processes holding raw `/dev/input` keyboard handles; known keylogger libraries |
| process     | binaries running from a deleted/anonymous path; crypto-miner signatures; temp/hidden-dir execution |
| network     | listening sockets (flags all-interface binds); established outbound peers; `/etc/hosts` tampering |
| ssh         | `authorized_keys` (inbound logins); risky client-config directives |
| filesystem  | recent executables/installers in `~/Downloads`; world-writable files; non-standard SUID/SGID binaries |
| malware     | content scan for reverse shells, droppers, webshells, miner configs, EICAR + dropped ELF binaries; runs ClamAV if installed |
| antivirus   | presence of `clamav`/`rkhunter`/`chkrootkit` + how to run a deep scan |

### Severity levels

- **HIGH** — act on it (spam notification grant, deleted-binary process, reverse shell, miner, ClamAV hit). Drives the non-zero exit code.
- **WARN** — review; usually benign (autostart entries, SUID outside the allowlist, world-writable files).
- **INFO** — context only.
- **OK** — checked, nothing wrong.

---

## How it's built

- **[psutil](https://github.com/giampaolo/psutil)** — process & network introspection (no fragile parsing of `ps`/`ss`).
- **[pydantic](https://docs.pydantic.dev)** — typed, validated `Finding`/`ScanReport` models; powers `--json`.
- **[rich](https://github.com/Textualize/rich)** — terminal tables and color.

```
secscan/
  models.py        Severity, Finding, ScanReport (pydantic)
  registry.py      Check base class, Context, @register registry
  report.py        rich console + JSON renderers
  cli.py           argparse entry point
  checks/          one module per area; each yields Finding objects
tests/             pytest suite
```

### Add your own check

```python
from ..registry import Check, Context, register

@register
class MyCheck(Check):
    name = "mycat.mything"
    category = "mycat"
    description = "what it looks for"

    def run(self, ctx: Context):
        if something_bad:
            yield self.high("title", detail="...", remediation="how to fix")
        else:
            yield self.ok("looks fine")
```

Then import it in `secscan/checks/__init__.py`. It's picked up automatically and
appears in `--list`, the report, and the `--category` filter.

---

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

Checks are unit-tested against synthetic fixtures (e.g. a temp dir seeded with a
reverse-shell snippet and the EICAR test string) so detection logic is verified
without touching real malware.

---

## Scope & disclaimer

secscan is a **triage tool for personal Linux desktops**, not a replacement for a
managed EDR/AV product or an incident-response process. A clean scan reduces
risk but cannot prove a machine is uncompromised, and findings are heuristics
that benefit from human review. If you suspect an active compromise, isolate the
machine and consult a professional.

---

## Contributing

Issues and pull requests welcome. New checks should:

- be **read-only** (no destructive side effects in a `run()`),
- ship with a unit test, and
- aim for low false-positive noise (prefer WARN/INFO over HIGH unless confident).

---

## License

[MIT](LICENSE) © 2026 Mayank
