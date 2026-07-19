#!/usr/bin/env bash
#
# secscan-weekly.sh — cron wrapper for an unattended weekly scan.
#
# Runs secscan once, archives a JSON report + a text summary under
# ~/.local/state/secscan/, keeps the last 12, and fires a desktop notification
# if any HIGH finding is present. Designed for cron's minimal environment
# (absolute paths, no assumed PATH/venv).
#
# Install (weekly, Mondays 09:00):
#   (crontab -l 2>/dev/null; echo "0 9 * * 1 $HOME/src/secscan/scripts/secscan-weekly.sh") | crontab -
set -u

SECSCAN_DIR="${SECSCAN_DIR:-$HOME/src/secscan}"
SECSCAN_BIN="$SECSCAN_DIR/.venv/bin/secscan"
STATE_DIR="${SECSCAN_STATE_DIR:-$HOME/.local/state/secscan}"
KEEP=12

mkdir -p "$STATE_DIR"
ts="$(date +%Y%m%d-%H%M%S)"
json="$STATE_DIR/scan-$ts.json"
summary="$STATE_DIR/scan-$ts.txt"

if [[ ! -x "$SECSCAN_BIN" ]]; then
  echo "secscan binary not found at $SECSCAN_BIN" >&2
  exit 127
fi

# Single scan -> JSON (machine-readable, diffable). Exit 1 == HIGH findings.
"$SECSCAN_BIN" --json >"$json" 2>"$STATE_DIR/scan-$ts.err"
code=$?

# Derive a human-readable summary from the JSON (no second scan).
python3 - "$json" >"$summary" 2>/dev/null <<'PY'
import json, sys
sev = {3: "HIGH", 2: "WARN", 1: "INFO", 0: "OK"}
d = json.load(open(sys.argv[1]))
f = d["findings"]
from collections import Counter
c = Counter(x["severity"] for x in f)
print(f"secscan {d['started_at']}  host={d['host']}")
print("TOTALS:", "  ".join(f"{sev[k]}={c.get(k,0)}" for k in (3, 2, 1, 0)))
for level in (3, 2, 1, 0):
    rows = [x for x in f if x["severity"] == level]
    if rows:
        print(f"\n{sev[level]}:")
        for x in rows:
            print(f"  - {x['title']}" + (f"  [{x['detail']}]" if x.get("detail") else ""))
PY

# Stable pointers to the most recent run (used by the shell login banner).
ln -sf "$(basename "$json")" "$STATE_DIR/latest.json"
ln -sf "$(basename "$summary")" "$STATE_DIR/latest.txt"

high=$(grep -c '"severity": 3' "$json" 2>/dev/null || echo 0)
warn=$(grep -c '"severity": 2' "$json" 2>/dev/null || echo 0)

# Email the summary (optional). Recipient comes from $SECSCAN_EMAIL or the
# first line of ~/.config/secscan/email. Delivery uses any sendmail-compatible
# transport (msmtp-mta recommended — see README "Email the weekly report").
EMAIL_TO="${SECSCAN_EMAIL:-}"
if [[ -z "$EMAIL_TO" && -f "$HOME/.config/secscan/email" ]]; then
  EMAIL_TO="$(head -n1 "$HOME/.config/secscan/email")"
fi
if [[ -n "$EMAIL_TO" ]]; then
  sendmail_bin=""
  for c in msmtp /usr/sbin/sendmail /usr/lib/sendmail sendmail; do
    if command -v "$c" >/dev/null 2>&1; then sendmail_bin="$c"; break; fi
  done
  if [[ -n "$sendmail_bin" ]]; then
    if [[ "$high" -gt 0 ]]; then verdict="⚠ $high HIGH"
    elif [[ "$warn" -gt 0 ]]; then verdict="$warn WARN"
    else verdict="clean"; fi
    { printf 'To: %s\n' "$EMAIL_TO"
      printf 'Subject: secscan weekly [%s] on %s\n' "$verdict" "$(hostname)"
      printf 'Content-Type: text/plain; charset=utf-8\n\n'
      cat "$summary"
    } | "$sendmail_bin" -t 2>>"$STATE_DIR/scan-$ts.err" \
      || echo "email to $EMAIL_TO failed via $sendmail_bin" >>"$STATE_DIR/scan-$ts.err"
  else
    echo "email recipient set ($EMAIL_TO) but no mail transport found —" \
         "install one: sudo apt install msmtp-mta" >>"$STATE_DIR/scan-$ts.err"
  fi
fi

# Desktop notification on HIGH (best-effort; works when a GUI session is up).
if [[ "$code" -eq 1 && "$high" -gt 0 ]]; then
  if command -v notify-send >/dev/null 2>&1; then
    DISPLAY="${DISPLAY:-:0}" \
    DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=/run/user/$(id -u)/bus}" \
      notify-send -u critical "secscan: $high HIGH finding(s)" "Review: $summary" 2>/dev/null || true
  fi
fi

# Rotate: keep the most recent $KEEP of each artifact.
for ext in json txt err; do
  ls -1t "$STATE_DIR"/scan-*."$ext" 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -f
done

exit "$code"
