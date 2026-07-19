# Weekly email reports & ad-hoc scans — step by step

This is the hands-on guide: get the weekly scan emailed to you, run a scan
whenever you want, and read the full report (every severity level, not just
the bad news).

Throughout, replace `you@gmail.com` with your address and `~/src/secscan`
with wherever you cloned the repo.

---

## 1. Configure email (one time, ~5 minutes)

The weekly wrapper emails the report when (a) it knows who to send it to and
(b) the machine has a way to send mail. Two independent steps:

### Step 1a — tell secscan where to send the report

```bash
mkdir -p ~/.config/secscan
echo you@gmail.com > ~/.config/secscan/email
```

That's the whole recipient config. (Alternative: set `SECSCAN_EMAIL` in the
environment of whatever runs the script.)

### Step 1b — give the machine a mail transport (msmtp + Gmail)

A fresh Ubuntu desktop can't send email. The simplest reliable setup is
`msmtp` relaying through your Gmail account:

1. **Install the transport:**

   ```bash
   sudo apt install msmtp-mta
   ```

2. **Create a Gmail app password** (Google blocks normal passwords for SMTP):
   - Go to https://myaccount.google.com/apppasswords
     (you must have 2-Step Verification turned on; enable it under
     *Google Account → Security* if you haven't).
   - Name it e.g. `secscan`, click **Create**, and copy the 16-character
     password it shows you.

3. **Write the msmtp config** — create `~/.msmtprc` with exactly this,
   substituting your address and the app password:

   ```
   defaults
   auth on
   tls on
   tls_trust_file /etc/ssl/certs/ca-certificates.crt
   account gmail
   host smtp.gmail.com
   port 587
   from you@gmail.com
   user you@gmail.com
   password abcd efgh ijkl mnop
   account default : gmail
   ```

   (The app password works with or without the spaces Google displays.)

4. **Lock it down** (msmtp refuses group/world-readable config):

   ```bash
   chmod 600 ~/.msmtprc
   ```

5. **Send a test message:**

   ```bash
   echo "test from secscan" | msmtp you@gmail.com
   ```

   If it lands in your inbox, you're done — the weekly run now emails
   automatically. If it errors, `cat ~/.msmtp.log` usually says why
   (typo in the app password is the usual suspect).

### What the email looks like

- **Subject:** `secscan weekly [clean] on <hostname>` — or `[N WARN]` /
  `[⚠ N HIGH]` so triage happens in your inbox list.
- **Body:** the totals line plus every finding, grouped by severity —
  HIGH, WARN, INFO, and OK are all listed.

If the transport is missing or broken the scan still runs and archives
normally; the skipped email is noted in that run's `.err` file under
`~/.local/state/secscan/`.

---

## 2. Run a scan ad hoc

Two ways, depending on what you want:

### Just scan and read it in the terminal

```bash
cd ~/src/secscan && . .venv/bin/activate
secscan            # full scan (filesystem walks + ClamAV if installed)
secscan --quick    # ~seconds; skips the slow filesystem walks
```

Every check prints its findings at all levels — OK (green), INFO (cyan),
WARN (yellow), HIGH (red) — followed by a summary table. Exit code is `1`
if anything HIGH was found, else `0`.

Useful variants:

```bash
secscan --category stealer --category browser   # only some areas
secscan --json                                  # machine-readable
secscan --list                                  # what checks exist
```

### Full weekly pipeline, right now (archive + email included)

```bash
~/src/secscan/scripts/secscan-weekly.sh
```

This does exactly what the Monday timer does: full scan → JSON + text report
archived under `~/.local/state/secscan/` → email sent (if configured) →
desktop notification on HIGH. Run it after finishing the email setup above
to see the real email arrive.

---

## 3. See the report — all levels

The archived text report includes **every** finding, grouped
HIGH → WARN → INFO → OK:

```bash
cat ~/.local/state/secscan/latest.txt     # most recent run, human-readable
cat ~/.local/state/secscan/latest.json    # same run, machine-readable
ls ~/.local/state/secscan/                # history (last 12 runs kept)
```

To diff what changed since the previous run:

```bash
cd ~/.local/state/secscan
diff <(ls -1t scan-*.txt | sed -n 2p | xargs cat) latest.txt
```

Severity meanings, so the report reads at a glance:

| Level | Meaning |
|-------|---------|
| HIGH  | Act on it — this is what the exit code, email subject ⚠, and desktop notification key on. |
| WARN  | Review it; often benign but worth a look (powerful extension, world-writable file). |
| INFO  | Context only (open ports, top CPU users, extension inventory). |
| OK    | The check ran and found nothing wrong — listed so you know what was covered. |

### When something is HIGH

Each finding carries a `->` remediation line telling you what to do. The two
safe cleanups are automated (dry-run first, `--yes` to apply):

```bash
secscan fix-autostart --yes       # broken autostart leftovers
secscan fix-notifications --yes   # spam notification grants (browser closed)
```

Everything else (killing a process, removing an extension, deleting a file)
is deliberately left to you — the remediation text says how.

---

## 4. Confirm the weekly schedule is alive

```bash
systemctl --user list-timers secscan.timer   # shows next/last run
systemctl --user start secscan.service       # force a scheduled-style run now
```
