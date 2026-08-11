# Task: Pipeline orchestration upgrades

## File
`scripts/gro_register_to_9router.py` primarily (main batch entry user runs)

## Goal
Add: live progress, adaptive workers, mid-batch inject, preflight, per-worker hang timeout.

## Context
- Multi-worker uses `run_single_worker` with `communicate(timeout=3600)` — too long; stdout only after finish → parent looks frozen.
- Need line-by-line streaming + heartbeat.
- Mid-batch: periodically copy CPA from worker temp dirs + inject SSO/CPA without waiting all workers.
- Preflight: CloudMail login, 9Router DB exists, optional grok2api ping, camoufox/python exists.
- Adaptive workers: if user passes high workers, start min(requested, 4) then can bump — OR simpler: clamp default max 4, recommend adaptive based on recent fail rate within run.

## Requirements (must implement)
1. **Preflight** `run_preflight() -> list[str] errors`:
   - config.json loads
   - CloudMail login via API if provider cloudmail (use curl_cffi or urllib)
   - 9Router DB file exists/writable
   - VENV_PYTHON exists
   - Print OK/FAIL lines; abort main if critical fail (cloudmail/db/python)
2. **Streaming worker output**: replace communicate with readline loop; flush each line; update last_activity.
3. **Per-worker hang timeout**: env/default `WORKER_ACCOUNT_TIMEOUT` or `--worker-timeout 300` seconds of no new output → kill process, mark failed, log TIMEOUT hang.
4. **Live progress board** every 15s in a monitor thread:
   `[progress] success≈N fail≈M workers_alive=K elapsed=Xs`
   Parse lines containing `注册成功` / `失败` for counters.
5. **Mid-batch inject** every 60s or every 5 new CPA files:
   - scan worker temp `grok_worker_*/cpa_auths/*.json` + main cpa_auths
   - inject new CPA to 9Router
   - merge any new SSO from worker token/accounts into main + try grok2api
   - track already-injected emails to avoid spam
6. **Adaptive workers**:
   - `--workers` max raise to 8 (currently capped 5 at main)
   - if `--adaptive`: start with min(4, workers); if after first wave success_rate high keep; document in help
   - simpler solid approach: function `choose_workers(requested, adaptive=True)` returns min(requested, 4) initially when adaptive; or scale: requested if <=4 else 4 with log message explaining stability
7. Flags:
   - `--inject-only` (if missing, add: only inject existing cpa/sso)
   - `--preflight-only`
   - `--no-preflight`
   - `--mid-inject` default True
   - `--adaptive` default True for workers>4
   - `--worker-timeout SEC` default 300
8. `--count` allow up to 500 not just 100
9. Keep existing CLI working: `--count N --workers W`
10. `python -m py_compile scripts/gro_register_to_9router.py`

## Report
`.hermes/briefs/pipeline_orchestration.report.md`