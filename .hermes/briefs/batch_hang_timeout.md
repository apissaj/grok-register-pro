# Task: Hang timeout + progress enrichment in batch_supervisor

## File
`batch_supervisor.py` primarily. Optionally tiny hooks only if needed.

## Goal
Improve hang detection beyond idle stdout timeout; enrich progress JSON.

## Requirements
1. Progress JSON fields (extend mark_slot_completed / initialize_progress):
   - completed, target, updated_at (existing)
   - success, fail (optional counters via new helpers)
   - last_error (string, truncated)
   - last_heartbeat (time.time())
2. Add `mark_progress_event(kind, detail="")` or similar:
   - kind in success|fail|heartbeat|error
3. Idle timeout: also treat lines with only whitespace as no activity (already last_output on any line - OK).
4. Add optional `account_stall_timeout` env `GROK_BATCH_ACCOUNT_STALL_SEC` default 240:
   - if progress `updated_at` / last success not advancing AND process alive longer than stall while completed < target, restart with reason `account stall`.
5. Log clearer progress lines: `[supervisor] progress completed=X/Y restarts=Z`
6. Keep API of `run_supervisor` backward compatible; new params optional with defaults.
7. `python -m py_compile batch_supervisor.py`

## Report
`.hermes/briefs/batch_hang_timeout.report.md`