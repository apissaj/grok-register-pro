"""
CPA auto-refresh daemon for 9Router pool.

Keeps the grok-cli CPA pool alive by periodically refreshing expired/expiring
tokens (xAI access tokens live ~6h / expires_in=21600). Reuses the refresh
logic from scripts/refresh_9router_tokens.py (find_9router_db, refresh_token,
is_expired_or_expiring) WITHOUT touching that script's CLI.

Windows-friendly: no daemonize — just a sleep loop. Can be run via:
  - Hermes cronjob / Windows Task Scheduler with --once
  - a background terminal / hermes terminal(background=true)

Usage:
    python scripts/cpa_auto_refresh_daemon.py                 # loop, every 30 min
    python scripts/cpa_auto_refresh_daemon.py --once          # single pass (cron)
    python scripts/cpa_auto_refresh_daemon.py --dry-run       # never refresh (read-only)
    python scripts/cpa_auto_refresh_daemon.py --interval-minutes 60
    python scripts/cpa_auto_refresh_daemon.py --buffer-minutes 30
    python scripts/cpa_auto_refresh_daemon.py --force

Exit codes: 0 = ok, 2 = 9Router DB not found.
"""
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone

# Make the sibling refresh module importable regardless of cwd.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import refresh_9router_tokens as r9  # noqa: E402  (reuses find_9router_db, refresh_token, is_expired_or_expiring, format_time_left)

DEFAULT_INTERVAL_MINUTES = 30
DEFAULT_BUFFER_MINUTES = 10
LOG_DIR = os.path.join(os.path.dirname(_HERE), "log")
LOG_FILE = os.path.join(LOG_DIR, "cpa_auto_refresh.log")
SUMMARY_FILE = os.path.join(LOG_DIR, "cpa_auto_refresh.json")
LOCK_RETRY_DELAY = 2.0  # seconds between lock-retry attempts
BUSY_TIMEOUT_MS = 5000


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _now_local() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _log_line(msg: str) -> None:
    """Append a timestamped line to log/cpa_auto_refresh.log."""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{_now_local()}] {msg}\n")
    except OSError as e:
        print(f"[CPA refresh] WARN: cannot write log {LOG_FILE}: {e}")


def _write_summary(summary: dict) -> None:
    """Write last-run summary JSON (optional but cheap)."""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(SUMMARY_FILE, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
    except OSError as e:
        print(f"[CPA refresh] WARN: cannot write summary {SUMMARY_FILE}: {e}")


def _connect_with_guard(db_path: str) -> sqlite3.Connection:
    """Open DB with busy_timeout; retry once if locked by 9Router (WAL)."""
    for attempt in (1, 2):
        try:
            conn = sqlite3.connect(db_path, timeout=BUSY_TIMEOUT_MS / 1000.0)
            conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            return conn
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower() and attempt == 1:
                print(f"[CPA refresh] DB locked (attempt {attempt}), retrying in {LOCK_RETRY_DELAY}s...")
                _log_line(f"DB locked, retrying in {LOCK_RETRY_DELAY}s...")
                time.sleep(LOCK_RETRY_DELAY)
                continue
            raise
    raise sqlite3.OperationalError("database is locked (retries exhausted)")


def run_pass(buffer_minutes: int, force: bool, dry_run: bool) -> dict:
    """
    One refresh pass over active grok-cli connections.

    Returns summary dict: {checked, refreshed, failed, skipped, db_path, ...}
    Mirrors refresh_9router_tokens.main() but returns instead of sys.exit().
    """
    summary = {
        "timestamp": _now_iso(),
        "buffer_minutes": buffer_minutes,
        "force": force,
        "dry_run": dry_run,
        "db_path": "",
        "checked": 0,
        "refreshed": 0,
        "failed": 0,
        "skipped": 0,
    }

    db_path = r9.find_9router_db()
    if not os.path.isfile(db_path):
        raise FileNotFoundError(f"9Router DB not found: {db_path}")
    summary["db_path"] = db_path

    conn = _connect_with_guard(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT * FROM providerConnections WHERE provider = 'grok-cli' AND isActive = 1"
        )
        rows = cursor.fetchall()
        summary["checked"] = len(rows)

        for row in rows:
            d = dict(row)
            data = json.loads(d["data"])
            email = d.get("email") or data.get("providerSpecificData", {}).get("email", "unknown")
            expires_at = data.get("expiresAt", "")
            refresh_tok = data.get("refreshToken", "")

            needs_refresh = force or r9.is_expired_or_expiring(expires_at, buffer_minutes)

            if not needs_refresh:
                summary["skipped"] += 1
                continue

            if not refresh_tok:
                print(f"  [!!] {email:45} {r9.format_time_left(expires_at):20} — NO refresh token")
                summary["failed"] += 1
                continue

            print(f"  [>>] {email:45} {r9.format_time_left(expires_at):20} — refreshing...")

            if dry_run:
                print("       (dry-run, would refresh)")
                summary["skipped"] += 1
                continue

            result = r9.refresh_token(refresh_tok)

            if not result or "error" in result:
                error = result.get("error", "unknown") if result else "no response"
                print(f"       [FAIL] Refresh failed: {error}")
                if result and result.get("error") == "invalid_grant":
                    print("       [DEAD] Refresh token revoked, deactivating...")
                    data["testStatus"] = "token_revoked"
                    data["lastError"] = f"refresh_token revoked: {result.get('detail', '')[:100]}"
                    data["lastErrorAt"] = _now_iso()
                    cursor.execute(
                        "UPDATE providerConnections SET data = ?, updatedAt = ? WHERE id = ?",
                        (json.dumps(data), _now_iso(), d["id"]),
                    )
                    conn.commit()
                summary["failed"] += 1
                continue

            # Update tokens in DB
            now = _now_iso()
            new_expires_in = result.get("expires_in", 21600)
            try:
                new_expires_at = datetime.fromtimestamp(
                    time.time() + new_expires_in, tz=timezone.utc
                ).isoformat()
            except (ValueError, TypeError):
                new_expires_at = now

            data["accessToken"] = result["access_token"]
            if result.get("refresh_token"):
                data["refreshToken"] = result["refresh_token"]
            data["expiresAt"] = new_expires_at
            data["expiresIn"] = new_expires_in
            data["lastRefreshAt"] = now
            data["backoffLevel"] = 0
            data["testStatus"] = "active"
            data.pop("lastError", None)
            data.pop("lastErrorAt", None)
            if result.get("id_token"):
                data["idToken"] = result["id_token"]

            cursor.execute(
                "UPDATE providerConnections SET data = ?, updatedAt = ? WHERE id = ?",
                (json.dumps(data), now, d["id"]),
            )
            conn.commit()

            new_status = r9.format_time_left(new_expires_at)
            print(f"       [OK] Refreshed! New expiry: {new_status} (token len={len(result['access_token'])})")
            summary["refreshed"] += 1
    finally:
        conn.close()

    return summary


def main() -> int:
    # --- arg parsing (flag-aware, mirrors refresh script style) ---
    interval_minutes = DEFAULT_INTERVAL_MINUTES
    buffer_minutes = DEFAULT_BUFFER_MINUTES
    force = False
    dry_run = False
    once = False

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--interval-minutes" and i + 1 < len(args):
            interval_minutes = int(args[i + 1])
            i += 2
        elif args[i] == "--buffer-minutes" and i + 1 < len(args):
            buffer_minutes = int(args[i + 1])
            i += 2
        elif args[i] == "--force":
            force = True
            i += 1
        elif args[i] == "--dry-run":
            dry_run = True
            i += 1
        elif args[i] == "--once":
            once = True
            i += 1
        else:
            i += 1

    if interval_minutes < 1:
        print("[CPA refresh] ERROR: --interval-minutes must be >= 1")
        return 2

    print(
        f"[CPA refresh] daemon start | interval={interval_minutes}min "
        f"| buffer={buffer_minutes}min | force={force} | dry_run={dry_run} | once={once}"
    )
    _log_line(
        f"daemon start | interval={interval_minutes}min | buffer={buffer_minutes}min "
        f"| force={force} | dry_run={dry_run} | once={once}"
    )

    last_summary: dict = {}
    try:
        while True:
            pass_start = time.time()
            try:
                summary = run_pass(buffer_minutes, force, dry_run)
            except FileNotFoundError as e:
                print(f"[CPA refresh] ERROR: {e}")
                _log_line(f"ERROR: {e}")
                return 2  # DB not found
            except sqlite3.OperationalError as e:
                summary = {
                    "timestamp": _now_iso(),
                    "buffer_minutes": buffer_minutes,
                    "force": force,
                    "dry_run": dry_run,
                    "db_path": r9.find_9router_db(),
                    "checked": 0,
                    "refreshed": 0,
                    "failed": 0,
                    "skipped": 0,
                    "error": str(e),
                }
                print(f"[CPA refresh] ERROR: DB access failed: {e}")
                _log_line(f"ERROR: DB access failed: {e}")

            last_summary = summary
            _write_summary(summary)

            line = (
                f"[CPA refresh] checked={summary['checked']} "
                f"refreshed={summary['refreshed']} failed={summary['failed']} "
                f"skipped={summary['skipped']}"
            )
            elapsed = time.time() - pass_start
            print(f"{line} ({(elapsed / 60):.1f}min)")
            _log_line(line)

            if once:
                break

            # Cap sleep so Ctrl+C / shutdown is responsive; total = interval.
            remaining = interval_minutes * 60
            while remaining > 0:
                step = min(remaining, 30)
                time.sleep(step)
                remaining -= step

    except KeyboardInterrupt:
        print("\n[CPA refresh] interrupted by user")
        _log_line("interrupted by user")
        if last_summary:
            print(
                f"[CPA refresh] final summary: checked={last_summary['checked']} "
                f"refreshed={last_summary['refreshed']} failed={last_summary['failed']} "
                f"skipped={last_summary['skipped']}"
            )

    print("[CPA refresh] daemon exit")
    _log_line("daemon exit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
