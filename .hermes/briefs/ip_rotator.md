# Task: Auto IP rotation (WARP reconnect)

## Goal
Auto-detect xAI risk/IP burnout during batch and rotate WARP IP automatically.

## Context
- WARP CLI: `/c/Program Files/Cloudflare/Cloudflare WARP/warp-cli` (`warp-cli disconnect` / `warp-cli connect`). On Windows: `net stop/start CloudflareWARP` needs admin → use `warp-cli` only.
- IP check: `curl -s https://www.cloudflare.com/cdn-cgi/trace | grep "^ip="` (IPv6 like `2a09:bac5:55fb:25af::3c1:45`).
- Risk signals seen in logs: burst of `SSO超时` / `Turnstile` slow / `注册失败` spikes / SSO→CPA convert 0/N.
- New file: `scripts/ip_rotator.py` + optional `scripts/auto_ip_rotate_monitor.py`.

## Requirements
1. `scripts/ip_rotator.py`:
   - `get_current_ip() -> str` (via curl trace, timeout 8s)
   - `rotate_ip(timeout=60) -> bool` — warp-cli disconnect, sleep 2, connect, poll IP until changed or timeout; verify via get_current_ip; return success
   - `detect_risk(lines: list[str], window: int = 20) -> tuple[bool, str]` — heuristic: count `SSO超时|Turnstile|注册失败|超时` in last N lines; if >= threshold (e.g. 5/20) → risky; return (True, reason)
   - `should_rotate(progress_snapshot) -> bool` — if recent fail rate > 40% over last 10 events → True
   - CLI: `python scripts/ip_rotator.py check` (print IP + risk summary), `rotate` (rotate once), `watch --window 20 --threshold 5` (tail a log file, auto-rotate when risk detected)
2. Optional `auto_ip_rotate_monitor.py`: monitor progress JSON (`GROK_BATCH_PROGRESS_FILE`) + worker temp logs; on risk → rotate → log rotation events to `log/ip_rotations.log`.
3. Windows-compatible (no signal, use subprocess).
4. `python -m py_compile` both files.

## Report
`.hermes/briefs/ip_rotator.report.md` — summary, files, how to use, verification (ran `check` at least once).