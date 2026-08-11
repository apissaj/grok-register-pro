# CPA Auto-Refresh Daemon — Report

**Date:** 2026-08-09
**Status:** ✅ Implemented + compiled + dry-run smoke passed (no commit, per instructions)

## Deliverable

**New file:** `scripts/cpa_auto_refresh_daemon.py` (~300 lines)
**Unchanged:** `scripts/refresh_9router_tokens.py` (243 lines, untouched — CLI intact; only imported from)

## What it does

- Reuses logic from `refresh_9router_tokens.py` by **import**: `find_9router_db`, `refresh_token`, `is_expired_or_expiring`, `format_time_left` (module injected into `sys.path` so it imports from any cwd).
- Loop daemon (Windows-friendly, no daemonize): every `--interval-minutes` (default **30**), runs one full refresh pass over active `grok-cli` connections (`provider='grok-cli' AND isActive=1`).
- **`--once`** flag → single pass then exit (for cron / Task Scheduler / hermes cronjob).
- **`--dry-run`** passthrough → read-only pass, prints what *would* refresh.
- **`--force`** / **`--buffer-minutes`** passthrough (default 10).
- **SQLite lock guard:** `PRAGMA busy_timeout=5000` + retry once (2s delay) on `sqlite3.OperationalError: database is locked` (9Router runs WAL — confirmed `data.sqlite-wal` live).
- **Logging:** append `log/cpa_auto_refresh.log` (timestamped) + console one-liner per pass:
  `[CPA refresh] checked=N refreshed=X failed=Y skipped=Z`
- **Last-run summary JSON:** `log/cpa_auto_refresh.json` (checked/refreshed/failed/skipped/timestamp/db_path/flags).
- **Exit codes:** `0` ok · `2` DB not found. `KeyboardInterrupt` → graceful final summary.

## Verification (all real, read-only)

| Check | Result |
|---|---|
| `python -m py_compile scripts/cpa_auto_refresh_daemon.py` | ✅ OK |
| `python scripts/cpa_auto_refresh_daemon.py --dry-run --once` | ✅ `checked=316 refreshed=0 failed=0 skipped=316`, exit 0, ~0.0 min |
| Live DB | ✅ `%APPDATA%\9router\db\data.sqlite`, **316 active grok-cli connections** (matches brief's ~316) |
| Log file written | ✅ `log/cpa_auto_refresh.log` (start/pass/exit lines) |
| Summary JSON written | ✅ `log/cpa_auto_refresh.json` |
| Exit 2 (DB not found) | ✅ monkeypatched `find_9router_db` → `[CPA refresh] ERROR: 9Router DB not found` + `EXIT=2` |
| Source script integrity | ✅ `git status` shows `refresh_9router_tokens.py` unmodified; still compiles; importable |
| Dry-run read-only | ✅ 0 tokens refreshed, 0 DB writes by the daemon itself |

## Usage

```bash
# Daemon (loop) — background terminal / Task Scheduler at logon
python scripts/cpa_auto_refresh_daemon.py
python scripts/cpa_auto_refresh_daemon.py --interval-minutes 60 --buffer-minutes 30

# Cron-friendly single pass (hermes cronjob: e.g. */30 * * * *)
python scripts/cpa_auto_refresh_daemon.py --once
python scripts/cpa_auto_refresh_daemon.py --once --dry-run   # safe rehearsal
```

## Notes / observations

- xAI token endpoint must not be hammered more often than ~30 min (skill pitfall) — default 30 min interval is the floor; `--interval-minutes` clamps to ≥1 but values <30 are discouraged.
- `find_9router_db()` falls back through `%APPDATA%` → `%USERPROFILE%` → `D:\Backup_Windows_Reinstall\...`; the backup copy currently exists, so a "missing live DB" only triggers exit 2 when all three are absent (verified via monkeypatch since the real live DB is present).
- Per-pass failure policy mirrors the source script: revoked refresh tokens are marked `testStatus=token_revoked` (deactivated), counted as `failed`; daemon keeps looping regardless (exit 0 at daemon level).
- `log/` dir already existed (app logs); new files are `log/cpa_auto_refresh.log` + `log/cpa_auto_refresh.json`.
- **Not committed** (per task). `git status` shows only the new untracked `scripts/cpa_auto_refresh_daemon.py` (+ pre-existing untracked `scripts/ip_rotator.py`, `.hermes/`, modified `token.json` — none touched by this task).
