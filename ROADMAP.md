# secscan roadmap

## Guiding principle: stay relevant without constant updates

secscan should detect **real, current threats** without us hand-patching it every
time a new malware family appears. We get there by preferring detection that
ages well:

1. **Behavioral / technique-based checks** — key on *what malicious code does*
   (reads your SSH keys, opens a reverse shell, unlinks its own binary), not on
   a specific sample. Techniques change far slower than payloads, so these keep
   working on threats that didn't exist when the check was written.
2. **Self-updating signature sources** — lean on feeds that update themselves
   rather than code we maintain:
   - **ClamAV** signatures via `freshclam` (already wired in).
   - **YARA** rules pulled from a community ruleset (planned) so signature
     coverage refreshes without code changes.
3. **Extensible by construction** — every check is a small, self-contained
   `Check` subclass registered with `@register`. Adding coverage is "drop a new
   module in `secscan/checks/`", never a rewrite. Keep that property as the tool
   grows; consider entry-point/plugin discovery so third parties can ship checks
   out-of-tree.

The test for any new feature: *does it broaden coverage of a class of threats,
or just one sample?* Prefer the former.

## Known gaps (prioritised)

Today secscan is a strong triage tool for the common 80% (browser spam,
persistence, loud malware, config tampering, known-signature malware). These are
the real-world gaps to close, roughly in impact order:

### P1 — Infostealer / credential-theft canary  *(highest real-world impact)*
The #1 actual threat today: malware that copies and exfiltrates secrets, often
leaving no persistent artifact. Detect processes (outside an allowlist) reading:
browser cookie/login DBs, `~/.ssh/`, `~/.aws/credentials`, `~/.config/gcloud`,
`~/.kube/config`, `.env` files, crypto wallets. Behavioral, fits the existing
psutil `open_files()` model. Pairs well with flagging outbound connections from
the same PID.

### P2 — Malicious browser extension analysis
We inventory extensions but don't judge them. Flag extensions that request
high-risk permissions (`<all_urls>`, `webRequest`, `cookies`, `proxy`,
`nativeMessaging`), are side-loaded / not from the Web Store, or were installed
outside the normal UI. Extensions are a top consumer attack vector.

### P3 — Browser integrity
Detect hijack indicators: unexpected `--load-extension`/`--proxy-server` launch
flags, tampered `Secure Preferences` (HMAC mismatch), changed default search
engine / homepage / proxy, rogue managed-policy files.

### P4 — Supply-chain / package risk
Surface recently installed or postinstall-scripted `npm`/`pip` packages, new AUR
builds, and VS Code extensions. Can't fully solve, but recent-change visibility
helps.

### P5 — YARA integration
Optional `yara-python` check that runs a community ruleset over the same
high-risk dirs. Auto-refreshing rules = coverage without code churn.

### P6 — `sudo` / system-wide mode
With elevated privileges: scan `/etc/cron.*`, root systemd units, all users'
authorized_keys, `setuid` changes against a package-manager baseline.

### P7 — Rootkit / fileless hardening
Deeper integration with `rkhunter`/`chkrootkit`; cross-check `/proc` against
`ps`; flag processes with no on-disk backing. (Userland tools can't beat a
kernel rootkit — be honest about the ceiling.)

## Non-goals

- Not an EDR or AV replacement; not real-time protection.
- Won't claim to stop targeted or root-level attackers.
- Won't reproduce a managed-product feature set — stays a transparent,
  auditable triage tool.

## Contributing a check

See the "Add your own check" section in the [README](README.md#add-your-own-check).
A good check is read-only, technique-based, unit-tested, and low-noise.
