"""
Auto IP rotation (WARP) with risk detection for the grok-register pipeline.

Detects xAI risk / IP burnout signals in worker/batch logs and rotates the
Cloudflare WARP tunnel to get a fresh exit IP.

Windows-compatible: no signals, plain subprocess + polling.

Commands:
    python scripts/ip_rotator.py check [--log FILE|GLOB] [--window N] [--threshold N]
    python scripts/ip_rotator.py rotate [--timeout SEC]
    python scripts/ip_rotator.py watch --log FILE|GLOB [--window N] [--threshold N]
                              [--interval SEC] [--cooldown SEC] [--once]

Rotation events are appended to <repo>/log/ip_rotations.log.
"""
from __future__ import annotations

import argparse
import glob as globmod
import os
import re
import subprocess
import sys
import time
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WARP_CLI = r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli"
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"

# Risk signals seen in logs: SSO timeouts, Turnstile slowness, registration
# failures, generic timeouts. Lines matching ANY pattern count once.
RISK_PATTERNS: Tuple[str, ...] = (
    "SSO超时",
    "Turnstile",
    "注册失败",
    "注册风控",
    "botFlagSource",
    "risk=",
    "超时",
)

IP_RE = re.compile(r"^ip=(.*)$", re.MULTILINE)

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROTATION_LOG = os.path.join(_REPO_ROOT, "log", "ip_rotations.log")

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(cmd: List[str], timeout: float = 30.0) -> Tuple[int, str]:
    """Run a command, return (returncode, stdout+stderr). No shell, no signal."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=_CREATE_NO_WINDOW,
        )
    except FileNotFoundError:
        return 127, f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout:.0f}s: {' '.join(cmd)}"
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out.strip()


def log_rotation(ip: str, reason: str, ok: bool) -> None:
    """Append one rotation event to log/ip_rotations.log."""
    try:
        os.makedirs(os.path.dirname(ROTATION_LOG), exist_ok=True)
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        status = "ROTATED" if ok else "FAILED"
        with open(ROTATION_LOG, "a", encoding="utf-8") as fh:
            fh.write(f"{ts} [{status}] ip={ip} reason={reason}\n")
    except OSError as exc:
        print(f"[ip_rotator] cannot write rotation log: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Core API
# ---------------------------------------------------------------------------

def get_current_ip(timeout: float = 8.0) -> str:
    """Return the current public IP via Cloudflare trace, or '' on failure."""
    try:
        proc = subprocess.run(
            ["curl", "-s", "--max-time", str(int(timeout)), TRACE_URL],
            capture_output=True,
            text=True,
            timeout=timeout + 3.0,
            creationflags=_CREATE_NO_WINDOW,
        )
        m = IP_RE.search(proc.stdout or "")
        if m:
            return m.group(1).strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return ""


def warp_status() -> str:
    """Return WARP CLI status line, or error text."""
    rc, out = _run([WARP_CLI, "status"])
    if rc != 0:
        return f"error({rc}): {out[:120]}"
    return out.splitlines()[0] if out else f"ok({rc})"


def rotate_ip(timeout: float = 60.0, reason: str = "") -> bool:
    """Disconnect + reconnect WARP and poll until the exit IP changes.

    Returns True if the IP changed (or WARP was down and a NEW valid IP came
    up); False on timeout/failure. `reason` is recorded in the rotation log.
    """
    old_ip = get_current_ip()
    print(f"[ip_rotator] current IP: {old_ip or '(unknown)'}")

    rc, out = _run([WARP_CLI, "disconnect"], timeout=30)
    print(f"[ip_rotator] disconnect -> rc={rc} {out[:80]}")
    time.sleep(2)

    rc, out = _run([WARP_CLI, "connect"], timeout=30)
    print(f"[ip_rotator] connect -> rc={rc} {out[:80]}")

    deadline = time.monotonic() + max(10.0, float(timeout))
    seen: set = set()
    while time.monotonic() < deadline:
        new_ip = get_current_ip()
        if new_ip:
            seen.add(new_ip)
            if new_ip != old_ip:
                print(f"[ip_rotator] IP changed: {old_ip or '(none)'} -> {new_ip}")
                why = reason or f"rotate_ip (was {old_ip or 'none'})"
                log_rotation(new_ip, why, True)
                return True
        time.sleep(2)

    # WARP fully down -> no IP at all; report failure so callers can retry.
    print(f"[ip_rotator] FAILED: IP did not change within {timeout:.0f}s "
          f"(old={old_ip or 'none'}, seen={sorted(seen)[:5]})")
    log_rotation("", reason or "rotate_ip timeout", False)
    return False


def detect_risk(lines: List[str], window: int = 20, threshold: int = 5) -> Tuple[bool, str]:
    """Heuristic risk detection over the last `window` log lines.

    A line is risky if it matches any RISK_PATTERNS entry. If >= `threshold`
    risky lines in the window -> (True, reason).
    """
    window = max(1, int(window))
    threshold = max(1, int(threshold))
    tail = [ln for ln in (lines or []) if ln][-window:]

    counts = {p: 0 for p in RISK_PATTERNS}
    risky_lines = 0
    for ln in tail:
        hit = [p for p in RISK_PATTERNS if p in ln]
        if hit:
            risky_lines += 1
            for p in hit:
                counts[p] += 1

    if risky_lines >= threshold:
        detail = ", ".join(f"{p}x{counts[p]}" for p in RISK_PATTERNS if counts[p])
        return True, f"{risky_lines}/{window} risky lines ({detail})"
    return False, f"{risky_lines}/{window} risky lines (ok)"


def should_rotate(progress_snapshot: dict, fail_rate: float = 0.40, window: int = 10) -> bool:
    """Decide from a progress snapshot whether to rotate.

    Accepts either aggregate counters (success/fail or ok/fail) or a list of
    recent events under the 'recent' key. Rotate when recent fail rate > 40%.
    """
    recent = progress_snapshot.get("recent") if isinstance(progress_snapshot, dict) else None
    if isinstance(recent, list) and recent:
        tail = recent[-int(window):]
        fails = sum(1 for e in tail if str(e.get("status", "")).lower() in ("fail", "failed", "error"))
        total = len(tail)
    else:
        ok = progress_snapshot.get("success", progress_snapshot.get("ok", 0))
        fails = progress_snapshot.get("fail", 0)
        total = int(ok) + int(fails)
    if total <= 0:
        return False
    rate = fails / total
    return rate > float(fail_rate)


def read_worker_logs() -> List[str]:
    """Gather recent lines from worker temp logs (grok_worker_*/**/*.log)."""
    tmp = os.environ.get("TMPDIR") or os.environ.get("TEMP") or os.environ.get("TMP") or "/tmp"
    lines: List[str] = []
    for pattern in (os.path.join(tmp, "grok_worker_*", "*.log"),
                    os.path.join(tmp, "grok_worker_*", "log", "*.log")):
        for path in globmod.glob(pattern):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    lines.extend(fh.read().splitlines()[-200:])
            except OSError:
                continue
    return lines


# ---------------------------------------------------------------------------
# Tail-watching (for `watch`)
# ---------------------------------------------------------------------------

class _FileTail:
    """Tracks appended lines of one file; handles truncation/rotation."""

    def __init__(self, path: str, start_at_end: bool = True):
        self.path = path
        self._fh = open(path, "rb")
        self._fh.seek(0, 2 if start_at_end else 0)

    def read_new(self) -> List[str]:
        size = os.path.getsize(self.path)
        pos = self._fh.tell()
        # File truncated/rotated -> restart from the beginning
        if size < pos:
            self._fh.seek(0)
            pos = 0
        data = self._fh.read()
        if not data:
            return []
        return data.decode("utf-8", errors="replace").splitlines()

    def close(self) -> None:
        try:
            self._fh.close()
        except OSError:
            pass


def _expand_logs(spec: str) -> List[str]:
    """Expand a log file or glob into existing file paths."""
    if os.path.isfile(spec):
        return [spec]
    return sorted(globmod.glob(spec))


def watch(
    log_spec: str,
    window: int = 20,
    threshold: int = 5,
    interval: float = 5.0,
    cooldown: float = 120.0,
    once: bool = False,
    max_rotations: int = 0,
) -> int:
    """Tail log file(s); when risk is detected, rotate WARP. Returns rotations done."""
    tails: dict = {}
    rotations = 0
    last_rotation = 0.0
    print(f"[ip_rotator] watching {log_spec} (window={window}, threshold={threshold}, "
          f"interval={interval:.0f}s, cooldown={cooldown:.0f}s, once={once})")

    try:
        while True:
            # Refresh file set (new app_*.log files appear as batch runs start)
            current = _expand_logs(log_spec)
            for p in current:
                if p not in tails:
                    try:
                        tails[p] = _FileTail(p)
                        print(f"[ip_rotator] tailing {p}")
                    except OSError:
                        continue
            for p in list(tails):
                if p not in current:
                    tails.pop(p).close()

            new_lines: List[str] = []
            for p, t in list(tails.items()):
                new_lines.extend(t.read_new())

            if new_lines:
                risky, reason = detect_risk(new_lines, window=window, threshold=threshold)
                if risky and (time.monotonic() - last_rotation) >= cooldown:
                    print(f"[ip_rotator] RISK DETECTED: {reason} -> rotating WARP")
                    ok = rotate_ip(reason=f"watch {reason}")
                    rotations += 1
                    last_rotation = time.monotonic()
                    if once or (max_rotations and rotations >= max_rotations):
                        print(f"[ip_rotator] stopping after {rotations} rotation(s)")
                        return rotations

            time.sleep(max(0.5, float(interval)))
    except KeyboardInterrupt:
        print("\n[ip_rotator] watch stopped by user")
        return rotations
    finally:
        for t in tails.values():
            t.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ip_rotator.py", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="print current IP + risk summary")
    c.add_argument("--log", help="log file or glob to scan for risk signals")
    c.add_argument("--window", type=int, default=20)
    c.add_argument("--threshold", type=int, default=5)

    r = sub.add_parser("rotate", help="rotate WARP IP once")
    r.add_argument("--timeout", type=float, default=60.0)

    w = sub.add_parser("watch", help="tail log(s) and auto-rotate on risk")
    w.add_argument("--log", required=True, help="log file or glob (repeatable)")
    w.add_argument("--window", type=int, default=20)
    w.add_argument("--threshold", type=int, default=5)
    w.add_argument("--interval", type=float, default=5.0)
    w.add_argument("--cooldown", type=float, default=120.0)
    w.add_argument("--once", action="store_true", help="exit after first rotation")
    w.add_argument("--max-rotations", type=int, default=0, help="0 = unlimited")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.cmd == "check":
        ip = get_current_ip()
        print(f"IP:            {ip or '(unreachable)'}")
        print(f"WARP:          {warp_status()}")
        lines: List[str] = []
        if getattr(args, "log", None):
            for p in _expand_logs(args.log):
                try:
                    with open(p, "r", encoding="utf-8", errors="replace") as fh:
                        lines.extend(fh.read().splitlines())
                except OSError as exc:
                    print(f"  (skip {p}: {exc})")
        if not lines:
            lines = read_worker_logs()
        risky, reason = detect_risk(lines, window=args.window, threshold=args.threshold)
        print(f"Risk:          {'HIGH — ' if risky else 'LOW — '}{reason}")
        return 1 if risky else 0

    if args.cmd == "rotate":
        ok = rotate_ip(timeout=args.timeout)
        print(f"Rotate:        {'SUCCESS' if ok else 'FAILED'}")
        return 0 if ok else 1

    if args.cmd == "watch":
        watch(
            args.log,
            window=args.window,
            threshold=args.threshold,
            interval=args.interval,
            cooldown=args.cooldown,
            once=args.once,
            max_rotations=args.max_rotations,
        )
        return 0

    return 2


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    sys.exit(main())
