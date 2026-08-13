"""
run_stage.py — chained batch runner for the grok-register pipeline.

Runs N batches of <size> accounts sequentially (4 workers each), rotating the
WARP IP between batches, and auto-stops when yield drops below a threshold
(IP burnout detection). Progress is written to log/run_stage.json so the
dashboard/CLI can show stage-level progress.

Usage:
    python scripts/run_stage.py --size 50 --batches 4 [--min-yield 0.30]
                                 [--rotate-between] [--dry-run]

Examples:
    # Stage 1: 200 accounts as 4 x 50-batches, rotate WARP between each
    python scripts/run_stage.py --size 50 --batches 4

    # Stage 2: 300 accounts as 6 x 50, stricter stop at 40% yield
    python scripts/run_stage.py --size 50 --batches 6 --min-yield 0.40

    # Preview without running anything
    python scripts/run_stage.py --size 50 --batches 4 --dry-run
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_FILE = os.path.join(_REPO_ROOT, "log", "run_stage.json")
PROGRESS_FILE = os.path.join(_REPO_ROOT, "log", "batch_progress.json")

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _load_state() -> dict:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_state(state: dict) -> None:
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    os.replace(tmp, STATE_FILE)


def _read_progress() -> dict:
    try:
        with open(PROGRESS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def rotate_warp(timeout: float = 60.0) -> bool:
    """Rotate WARP via the ip_rotator module (same dir)."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        from ip_rotator import rotate_ip
    except ImportError:
        print("[run_stage] WARN: ip_rotator not importable, skipping rotation")
        return False
    return rotate_ip(timeout=timeout, reason="run_stage between batches")


def run_batch(size: int, workers: int = 4) -> int:
    """Run one gro_register_to_9router.py batch. Returns exit code."""
    cmd = [
        sys.executable,
        os.path.join(_REPO_ROOT, "scripts", "gro_register_to_9router.py"),
        "--count", str(size),
        "--workers", str(workers),
    ]
    print(f"[run_stage] >>> batch: {' '.join(cmd)}")
    proc = subprocess.run(cmd, cwd=_REPO_ROOT, creationflags=_CREATE_NO_WINDOW)
    return proc.returncode


def batch_yield(completed: int, failed: int) -> float:
    total = completed + failed
    if total <= 0:
        return 1.0
    return completed / total


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--size", type=int, default=50, help="accounts per batch")
    p.add_argument("--batches", type=int, default=4, help="number of batches")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--safe-mode", action="store_true",
                   help="use 10 accounts/batch and 2 workers to reduce per-IP risk")
    p.add_argument("--min-yield", type=float, default=0.30,
                   help="stop if batch yield (success/total) < this")
    p.add_argument("--rotate-between", action="store_true",
                   help="rotate WARP IP between batches")
    p.add_argument("--dry-run", action="store_true",
                   help="print plan only, don't execute")
    p.add_argument("--resume", action="store_true",
                   help="resume from saved run_stage.json state")
    args = p.parse_args(argv)

    state = _load_state() if args.resume else {}
    if args.resume and state.get("running"):
        print(f"[run_stage] resuming stage: {state}")
        start_batch = state.get("batch_index", 0)
        done = state.get("done", 0)
    else:
        start_batch = 0
        done = 0
        state = {
            "size": args.size,
            "batches": args.batches,
            "workers": args.workers,
            "min_yield": args.min_yield,
            "batch_index": 0,
            "done": 0,
            "failed": 0,
            "rotations": 0,
            "started_at": time.time(),
            "running": True,
        }
        _save_state(state)

    if args.safe_mode:
        # Override defaults so each WARP IP is touched by fewer accounts:
        # rate-limit kicks in around 10-15 accounts/IP as 'sso_timeout' with
        # no sso cookie issued. 2 workers + 10 accounts/batch keeps well below.
        if args.size > 10:
            print(f"[run_stage] safe-mode: clamping --size {args.size} -> 10")
            args.size = 10
        if args.workers > 2:
            print(f"[run_stage] safe-mode: clamping --workers {args.workers} -> 2")
            args.workers = 2
        if not args.rotate_between:
            print("[run_stage] safe-mode: forcing --rotate-between")
            args.rotate_between = True

    print(f"[run_stage] plan: {args.batches} batches x {args.size} accounts "
          f"(workers={args.workers}, min_yield={args.min_yield:.0%})")
    if args.dry_run:
        print("[run_stage] DRY-RUN — not executing")
        return 0

    stop_reason = ""
    for b in range(start_batch, args.batches):
        state["batch_index"] = b
        _save_state(state)
        print(f"\n[run_stage] ==== batch {b + 1}/{args.batches} "
              f"(done={done} so far) ====")

        if args.rotate_between and b > start_batch:
            print("[run_stage] rotating WARP IP before batch...")
            ok = rotate_warp()
            if ok:
                state["rotations"] = state.get("rotations", 0) + 1
                _save_state(state)

        rc = run_batch(args.size, workers=args.workers)
        print(f"[run_stage] batch {b + 1} exit={rc}")

        prog = _read_progress()
        comp = int(prog.get("completed", 0) or 0)
        fail = int(prog.get("failed", 0) or 0)
        done += comp
        state["done"] = done
        state["failed"] = state.get("failed", 0) + fail
        state["last_batch"] = {
            "completed": comp,
            "failed": fail,
            "exit": rc,
            "at": time.time(),
        }
        _save_state(state)

        y = batch_yield(comp, fail)
        print(f"[run_stage] batch yield: {comp}/{comp + fail} = {y:.0%}")
        if y < args.min_yield:
            stop_reason = f"yield {y:.0%} < {args.min_yield:.0%} (IP burnout?)"
            break

    state["running"] = False
    state["finished_at"] = time.time()
    state["stop_reason"] = stop_reason
    _save_state(state)

    print(f"\n[run_stage] DONE: {done} accounts, "
          f"rotations={state.get('rotations', 0)}")
    if stop_reason:
        print(f"[run_stage] STOPPED EARLY: {stop_reason}")
        return 3
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    sys.exit(main())
