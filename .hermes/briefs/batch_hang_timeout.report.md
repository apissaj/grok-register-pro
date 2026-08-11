# Report: batch hang timeout + progress enrichment

## Status
**Done** — compile + tests pass. No commit.

## Changes

### `batch_supervisor.py`
1. **Progress JSON enrichment** (`initialize_progress` / `mark_slot_completed`):
   - Existing: `completed`, `target`, `updated_at`
   - New: `success`, `fail`, `last_error` (truncated to 500 chars), `last_heartbeat`
2. **`mark_progress_event(kind, detail="")`**
   - Kinds: `success` | `fail` | `heartbeat` | `error`
   - Updates counters / `last_error` / `last_heartbeat` under the same file lock as slot marks
3. **Idle timeout**
   - Whitespace-only stdout lines no longer reset `last_output` (do not count as activity)
4. **Account stall timeout**
   - Env: `GROK_BATCH_ACCOUNT_STALL_SEC` (default **240**)
   - Optional param: `account_stall_timeout=` on `run_supervisor` (overrides env; `None` → env/default)
   - If child is alive, `completed < target`, and progress `updated_at` has not advanced for ≥ stall seconds → restart with reason **`account stall`**
5. **Clearer progress logs**
   - `[supervisor] progress completed=X/Y restarts=Z` on completed advances / clean exit path
6. **API**
   - `run_supervisor(...)` remains backward compatible; new param optional with default
   - Helpers: `read_progress`, `ACCOUNT_STALL_ENV`, `DEFAULT_ACCOUNT_STALL_TIMEOUT`

### `tests/test_batch_supervisor.py`
- `test_progress_enrichment_and_events`
- `test_supervisor_restarts_on_account_stall`

## Verification
```text
python -m py_compile batch_supervisor.py
python tests/test_batch_supervisor.py
# → OK batch supervisor
```

## Notes
- Stall timer baselines from each child launch’s progress snapshot so a fresh child is not immediately considered stalled.
- Heartbeat events refresh `last_heartbeat` only (do not advance stall-breaking `updated_at`); success/fail/error and slot completion do advance progress timestamps.
