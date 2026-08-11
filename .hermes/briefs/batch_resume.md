# Task: Batch resume (continue from last progress)

## Goal
Batch crash di tengah → tinggal jalankan ulang, otomatis lanjut dari posisi terakhir, tanpa hitung manual.

## Context
- Progress JSON sudah ada: `GROK_BATCH_PROGRESS_FILE` env, fields `completed/target/updated_at/success/fail/last_error/last_heartbeat` (batch_supervisor.py: initialize_progress, read_progress, mark_slot_completed, mark_progress_event).
- Main entry: `scripts/gro_register_to_9router.py` (`run_grok_register(count, workers, ...)` at line ~599; main() parses args). Worker dirs: `%TEMP%\grok_worker_<i>\` created by create_worker_dir; CPA at `grok_worker_<i>\cpa_auths\`, SSO merged into worker token.json / accounts.
- Persist batch state at `log/batch_state.json` (dir `log/` exists).

## Requirements
1. New helpers in `scripts/batch_state.py` (or inside gro_register_to_9router.py if simpler):
   - `save_batch_state(state: dict)` / `load_batch_state() -> dict | None` / `clear_batch_state()` → file `log/batch_state.json`
   - state: `{"target": N, "completed": M, "batch_id": ..., "started_at": ..., "updated_at": ..., "workers": W}`
   - `remaining(state) -> int` = target - completed
2. In `main()` of gro_register_to_9router.py:
   - `--resume` flag: load state; if exists → set count = remaining; print `[resume] continuing target=100 completed=43 remaining=57`
   - after each mid-batch inject / at end: update state completed = CPA files count / progress completed
   - `--clear-state` flag to reset
   - On completion (count done): clear state automatically
3. Edge: if state missing + `--resume` → print warning and use --count.
4. Progress file passed to workers stays same; completed counted from worker artifacts (cpa_auths files + token.json SSO count delta).
5. `python -m py_compile scripts/gro_register_to_9router.py scripts/batch_state.py` + `scripts/run_tests.sh` still passes (at least no regressions).

## Report
`.hermes/briefs/batch_resume.report.md`