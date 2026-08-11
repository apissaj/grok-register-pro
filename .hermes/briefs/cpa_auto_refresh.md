# Task: CPA auto-refresh scheduler (keep 9Router pool alive)

## Goal
Pool 9Router (grok-cli CPA, ~316 akun) mati pelan-pelan karena token expires ~6 jam (`expires_in=21600`). Buat scheduler/daemon yang refresh otomatis.

## Context
- `scripts/refresh_9router_tokens.py` SUDAH ADA dan berfungsi (243 baris): refresh_token → xAI OAuth2 `https://auth.x.ai/oauth2/token`, update DB `providerConnections` (provider='grok-cli', isActive=1). Flags: `--buffer-minutes 10`, `--force`, `--dry-run`. Uses urllib only. DB auto-detect `%APPDATA%\9router\db\data.sqlite`.
- Yang kurang: tidak ada scheduling otomatis + tidak ada report ringkas + tidak ada guard kalau DB dikunci 9Router (sqlite WAL/locked).
- Windows: no cron daemon built-in; gunakan loop dengan `time.sleep` + bisa dipanggil via hermes cronjob / task scheduler / `terminal background`.

## Requirements
1. New `scripts/cpa_auto_refresh_daemon.py`:
   - Loop: setiap `--interval-minutes` (default 30), panggil refresh logic (import & reuse functions from refresh_9router_tokens.py: find_9router_db, refresh_token, is_expired_or_expiring — refactor minimal: keep refresh_9router_tokens.py importable, don't break its CLI main)
   - `--once` flag: run single pass and exit (for cron)
   - `--dry-run` passthrough
   - sqlite lock guard: try connect, `PRAGMA busy_timeout=5000`, retry once on `sqlite3.OperationalError: database is locked`
   - Log to `log/cpa_auto_refresh.log` (append, timestamp) + console print ringkas per pass: `[CPA refresh] checked=N refreshed=X failed=Y skipped=Z`
   - Exit codes: 0 ok, 2 if DB not found
2. Optional: write `log/cpa_auto_refresh.json` last-run summary (checked/refreshed/failed/skipped/timestamp).
3. Windows-compatible (no daemonize; just loop). Graceful KeyboardInterrupt → final summary.
4. `python -m py_compile scripts/cpa_auto_refresh_daemon.py` + quick `--dry-run --once` smoke (read-only; do NOT actually refresh tokens unless obviously needed — dry-run only).
5. Do NOT modify refresh_9router_tokens.py CLI behavior; import from it.

## Report
`.hermes/briefs/cpa_auto_refresh.report.md`