# Report: Auto IP rotation (WARP) with risk detection

**Date:** 2026-08-09
**Status:** ✅ Implemented & verified live (rotation executed against real WARP)

## Summary

Implemented WARP-based auto IP rotation with risk detection for the
grok-register pipeline. Both scripts compile (`py_compile`), unit logic
verified, and a **real end-to-end rotation was executed**: risk detected →
`warp-cli disconnect` → `connect` → exit IP changed (IPv6 `2a09:...` →
IPv4 `103.78.115.203`), recorded in `log/ip_rotations.log`.

## Files

| File | Purpose |
|---|---|
| `scripts/ip_rotator.py` | Core: IP check, WARP rotation, risk heuristics, tail-watch CLI |
| `scripts/auto_ip_rotate_monitor.py` | Daemon monitor of progress JSON + worker temp logs → auto-rotate |
| `log/ip_rotations.log` | Rotation event log (created during verification) |

No existing files modified. Not committed.

## API (scripts/ip_rotator.py)

- `get_current_ip(timeout=8) -> str` — `curl https://www.cloudflare.com/cdn-cgi/trace`, parses `ip=`. Returns `''` on failure.
- `rotate_ip(timeout=60, reason='') -> bool` — `warp-cli disconnect` → sleep 2 → `connect` → poll IP every 2s until changed or timeout. Verifies via `get_current_ip`. Logs result (with reason) to `log/ip_rotations.log`. Windows-safe: subprocess only, `CREATE_NO_WINDOW`, no signals.
- `detect_risk(lines, window=20, threshold=5) -> (bool, reason)` — counts lines matching `SSO超时 | Turnstile | 注册失败 | 超时` in the last N lines; `>= threshold` → risky.
- `should_rotate(progress_snapshot, fail_rate=0.40, window=10) -> bool` — accepts aggregate counters (`success`/`fail` or `ok`/`fail`) or a `recent` event list; fail rate > 40% → True.

## CLI usage

```bash
# Print current IP, WARP status, risk summary (exit 1 if HIGH)
python scripts/ip_rotator.py check [--log FILE|GLOB] [--window 20] [--threshold 5]

# Rotate once
python scripts/ip_rotator.py rotate [--timeout 60]

# Tail a log (or glob) and auto-rotate on risk; --once exits after 1 rotation
python scripts/ip_rotator.py watch --log "log/app_*.log" \
    --window 20 --threshold 5 --interval 5 --cooldown 120 --once

# Daemon: progress JSON (GROK_BATCH_PROGRESS_FILE, fallback log/monitor_stats.json)
# + worker temp logs (<tmp>/grok_worker_*/**/*.log)
python scripts/auto_ip_rotate_monitor.py --interval 20 --cooldown 180 \
    --window 20 --threshold 5 --fail-rate 0.40 [--once]
```

## Verification (all executed)

1. `python -m py_compile scripts/ip_rotator.py scripts/auto_ip_rotate_monitor.py` → OK
2. Unit checks: `detect_risk` (5×`SSO超时`→HIGH, clean log→LOW, mixed 3/5→HIGH), `should_rotate` (50% fail→True, 10%→False, zero→False) → all pass
3. Live `python scripts/ip_rotator.py check` → prints real IPv6 + `WARP: Connected` + risk summary
4. Live `rotate` → `IP changed: 2a09:bac5:55fc:25d7::3c5:5 -> 2a09:bac5:55fc:18d2::279:37` → SUCCESS
5. E2E `watch` on synthetic log (5 risky lines appended after tail start) → `RISK DETECTED` → rotated → exited with `--once`
6. Monitor smoke: boots, reads `log/monitor_stats.json` + worker logs, reports `ok` every interval

## Notes / pitfalls

- `detect_risk` substring overlap: `SSO超时` also matches the generic `超时` pattern (intended — double-counts only in the per-pattern breakdown, line count is per-line).
- `watch` tails from **end-of-file** — it only reacts to lines appended after startup (correct for live batch logs). To replay a whole file, use `check --log`.
- MSYS `/tmp` ≠ native Windows temp: worker-log scanning uses `$TMPDIR/$TEMP/$TMP` env (resolves to the real Windows temp), and glob args must be repo-relative paths, not `/tmp/...`.
- `warp-cli` reconnects fast (2–4s); poll interval 2s with 60s timeout is ample. If WARP drops entirely, `rotate_ip` returns False after timeout so callers can retry.
- Rotation events are logged with timestamp, status (`ROTATED`/`FAILED`), new IP, and reason → `log/ip_rotations.log`.
