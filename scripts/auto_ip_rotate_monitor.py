"""
Daemon monitor: watches the batch pipeline's progress JSON + worker temp logs,
and rotates the WARP IP when xAI risk / IP burnout signals are detected.

Sources:
  1. Progress JSON — path from env GROK_BATCH_PROGRESS_FILE, else
     <repo>/log/monitor_stats.json (fallback: <repo>/log/progress.json).
     Aggregate fail rate > 40% over last 10 events -> rotate.
  2. Worker temp logs (<tmp>/grok_worker_*/**/*.log) — heuristic scan
     (SSO超时 / Turnstile / 注册失败 / 超时) over the last N lines.

Rotation events are appended to <repo>/log/ip_rotations.log.

Usage:
    python scripts/auto_ip_rotate_monitor.py [--interval 20] [--cooldown 180]
        [--window 20] [--threshold 5] [--fail-rate 0.40] [--once]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

# Import the shared logic from ip_rotator.py (same directory).
try:
    from ip_rotator import (  # type: ignore
        ROTATION_LOG,
        detect_risk,
        get_current_ip,
        log_rotation,
        read_worker_logs,
        rotate_ip,
        should_rotate,
        warp_status,
    )
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from ip_rotator import (  # type: ignore
        ROTATION_LOG,
        detect_risk,
        get_current_ip,
        log_rotation,
        read_worker_logs,
        rotate_ip,
        should_rotate,
        warp_status,
    )

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _progress_file() -> str:
    """Resolve the progress JSON path (env override first)."""
    env = os.environ.get("GROK_BATCH_PROGRESS_FILE")
    if env and os.path.isfile(env):
        return env
    for candidate in (
        os.path.join(_REPO_ROOT, "log", "batch_progress.json"),
        os.path.join(_REPO_ROOT, "log", "monitor_stats.json"),
        os.path.join(_REPO_ROOT, "log", "progress.json"),
    ):
        if os.path.isfile(candidate):
            return candidate
    return os.path.join(_REPO_ROOT, "log", "monitor_stats.json")


def _read_progress(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _format_snapshot(data: dict) -> str:
    recent = data.get("recent")
    if isinstance(recent, list):
        ok = sum(1 for e in recent if str(e.get("status", "")).lower() == "ok")
        fail = sum(1 for e in recent if str(e.get("status", "")).lower() in ("fail", "failed", "error"))
        return f"recent ok={ok} fail={fail}"
    return f"success={data.get('success', data.get('ok', 0))} fail={data.get('fail', 0)}"


def monitor(
    interval: float = 20.0,
    cooldown: float = 180.0,
    window: int = 20,
    threshold: int = 5,
    fail_rate: float = 0.40,
    once: bool = False,
) -> int:
    """Poll loop: risk -> rotate WARP. Returns number of rotations."""
    progress_path = _progress_file()
    print(f"[ipmon] progress JSON: {progress_path} (exists={os.path.isfile(progress_path)})")
    print(f"[ipmon] rotation log:  {ROTATION_LOG}")
    print(f"[ipmon] WARP status:   {warp_status()}")
    print(f"[ipmon] interval={interval:.0f}s cooldown={cooldown:.0f}s "
          f"window={window} threshold={threshold} fail_rate={fail_rate:.0%}")

    rotations = 0
    last_rotation = 0.0

    try:
        while True:
            reasons: list = []

            # 1) Progress JSON snapshot -> fail-rate check
            snapshot = _read_progress(progress_path)
            if snapshot:
                if should_rotate(snapshot, fail_rate=fail_rate):
                    reasons.append(f"progress fail rate > {fail_rate:.0%} "
                                   f"({_format_snapshot(snapshot)})")
            else:
                print(f"[ipmon] progress file missing/empty: {progress_path}")

            # 2) Worker temp logs -> heuristic risk scan
            lines = read_worker_logs()
            if lines:
                risky, reason = detect_risk(lines, window=window, threshold=threshold)
                if risky:
                    reasons.append(f"log heuristic: {reason}")

            if reasons and (time.monotonic() - last_rotation) >= cooldown:
                combined = "; ".join(reasons)
                print(f"[ipmon] RISK DETECTED: {combined}")
                ok = rotate_ip(reason=f"monitor: {combined}")
                rotations += 1
                last_rotation = time.monotonic()
                if once:
                    print(f"[ipmon] --once: stopping after {rotations} rotation(s)")
                    return rotations
            else:
                print(f"[ipmon] ok (rotations={rotations}, "
                      f"workers_log_lines={len(lines)})")

            time.sleep(max(1.0, float(interval)))
    except KeyboardInterrupt:
        print("\n[ipmon] stopped by user")
        return rotations


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--interval", type=float, default=20.0, help="poll interval seconds")
    p.add_argument("--cooldown", type=float, default=180.0, help="min seconds between rotations")
    p.add_argument("--window", type=int, default=20, help="log lines window for heuristic")
    p.add_argument("--threshold", type=int, default=5, help="risky lines needed in window")
    p.add_argument("--fail-rate", type=float, default=0.40, help="progress fail rate that triggers")
    p.add_argument("--once", action="store_true", help="exit after first rotation")
    args = p.parse_args(argv)
    monitor(
        interval=args.interval,
        cooldown=args.cooldown,
        window=args.window,
        threshold=args.threshold,
        fail_rate=args.fail_rate,
        once=args.once,
    )
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    sys.exit(main())
