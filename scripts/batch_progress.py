"""
Shared helpers for gro_register_to_9router pipeline orchestration:
  - live progress counters
  - streaming worker stdout with hang timeout
  - mid-batch CPA/SSO discovery
"""
from __future__ import annotations

import glob
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional


SUCCESS_MARKERS = ("注册成功", "registration success", "SSO saved", "CPA exported")
FAIL_MARKERS = ("失败", "FAILED", "ERROR:", "TIMEOUT", "registration failed")


@dataclass
class ProgressState:
    """Thread-safe live counters for the progress board."""

    success: int = 0
    fail: int = 0
    lines_seen: int = 0
    workers_alive: int = 0
    workers_total: int = 0
    started_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def note_line(self, line: str) -> None:
        text = line or ""
        with self.lock:
            self.lines_seen += 1
            self.last_activity = time.time()
            lower = text.lower()
            if any(m in text for m in SUCCESS_MARKERS) or "注册成功" in text:
                self.success += 1
            elif any(m in text for m in FAIL_MARKERS) or "失败" in text:
                # Avoid double-counting pure progress lines that mention both
                if "注册成功" not in text:
                    self.fail += 1

    def set_workers_alive(self, n: int) -> None:
        with self.lock:
            self.workers_alive = max(0, int(n))

    def bump_worker_done(self, ok: bool) -> None:
        with self.lock:
            self.workers_alive = max(0, self.workers_alive - 1)
            if ok:
                self.success += 1
            else:
                self.fail += 1

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "success": self.success,
                "fail": self.fail,
                "lines_seen": self.lines_seen,
                "workers_alive": self.workers_alive,
                "workers_total": self.workers_total,
                "elapsed": max(0.0, time.time() - self.started_at),
                "last_activity": self.last_activity,
            }

    def format_board(self) -> str:
        s = self.snapshot()
        return (
            f"[progress] success≈{s['success']} fail≈{s['fail']} "
            f"workers_alive={s['workers_alive']}/{s['workers_total']} "
            f"elapsed={s['elapsed']:.0f}s"
        )


def start_progress_monitor(
    state: ProgressState,
    stop_event: threading.Event,
    interval: float = 15.0,
    log_fn: Optional[Callable[[str], None]] = None,
) -> threading.Thread:
    """Daemon thread that prints a progress board every `interval` seconds."""

    def _emit(msg: str) -> None:
        if log_fn:
            log_fn(msg)
        else:
            print(f"  {msg}", flush=True)

    def _run() -> None:
        while not stop_event.wait(timeout=max(1.0, float(interval))):
            _emit(state.format_board())

    t = threading.Thread(target=_run, name="progress-monitor", daemon=True)
    t.start()
    return t


def start_batch_progress_writer(
    state: ProgressState,
    stop_event: threading.Event,
    *,
    target: int = 0,
    workers: int = 1,
    batch_id: str = "",
    interval: float = 4.0,
    progress_file: str = "",
) -> threading.Thread:
    """Daemon thread that writes log/batch_progress.json every `interval` secs.

    The web dashboard reads this file to show live progress (completed/target).
    """
    import json
    import os
    import time as _time
    from pathlib import Path

    if not progress_file:
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        progress_file = os.path.join(repo, "log", "batch_progress.json")
    progress_path = Path(progress_file)
    progress_path.parent.mkdir(parents=True, exist_ok=True)
    started_at = _time.time()

    def _write() -> None:
        snap = state.snapshot()
        data = {
            "target": max(0, int(target)),
            "completed": max(0, int(snap["success"])),
            "failed": max(0, int(snap["fail"])),
            "workers": max(1, int(workers)),
            "workers_alive": max(0, int(snap["workers_alive"])),
            "workers_total": max(0, int(snap["workers_total"])),
            "batch_id": batch_id or "",
            "started_at": started_at,
            "updated_at": _time.time(),
            "running": True,
        }
        tmp = f"{progress_path}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, progress_path)
        except OSError:
            pass

    def _run() -> None:
        _write()
        while not stop_event.wait(timeout=max(1.0, float(interval))):
            _write()

    t = threading.Thread(target=_run, name="batch-progress-writer", daemon=True)
    t.start()
    return t


def stream_process_output(
    proc,
    *,
    prefix: str = "",
    hang_timeout: float = 300.0,
    on_line: Optional[Callable[[str], None]] = None,
    log_fn: Optional[Callable[[str], None]] = None,
    stdin_payload: Optional[str] = None,
) -> tuple[int, bool]:
    """
    Read proc.stdout line-by-line, flushing each line.
    If no new output for `hang_timeout` seconds, kill the process.

    Returns (returncode, timed_out).
    """

    def _emit(msg: str) -> None:
        if log_fn:
            log_fn(msg)
        else:
            print(f"  {msg}", flush=True)

    if stdin_payload is not None and proc.stdin is not None:
        try:
            proc.stdin.write(stdin_payload)
            proc.stdin.flush()
            proc.stdin.close()
        except (OSError, BrokenPipeError, ValueError):
            pass

    last_activity = time.monotonic()
    timed_out = False
    line_queue: list[str] = []
    queue_lock = threading.Lock()
    reader_done = threading.Event()

    def _reader() -> None:
        try:
            if proc.stdout is None:
                return
            for raw in proc.stdout:
                line = raw.rstrip("\r\n")
                with queue_lock:
                    line_queue.append(line)
        except (OSError, ValueError):
            pass
        finally:
            reader_done.set()

    reader = threading.Thread(target=_reader, name=f"stdout-{prefix or 'proc'}", daemon=True)
    reader.start()

    hang = max(30.0, float(hang_timeout or 300.0))

    while True:
        drained = False
        with queue_lock:
            while line_queue:
                line = line_queue.pop(0)
                drained = True
                last_activity = time.monotonic()
                tagged = f"{prefix} {line}".strip() if prefix else line
                _emit(tagged)
                if on_line:
                    try:
                        on_line(line)
                    except Exception:
                        pass

        if proc.poll() is not None and reader_done.is_set() and not drained:
            # Final drain
            with queue_lock:
                leftover = list(line_queue)
                line_queue.clear()
            for line in leftover:
                tagged = f"{prefix} {line}".strip() if prefix else line
                _emit(tagged)
                if on_line:
                    try:
                        on_line(line)
                    except Exception:
                        pass
            break

        idle = time.monotonic() - last_activity
        if idle >= hang and proc.poll() is None:
            timed_out = True
            _emit(f"{prefix} TIMEOUT hang ({hang:.0f}s no output) — killing process".strip())
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
            break

        time.sleep(0.15)

    reader.join(timeout=2)
    rc = proc.poll()
    if rc is None:
        try:
            proc.kill()
        except OSError:
            pass
        rc = proc.poll()
    return (rc if rc is not None else -1, timed_out)


def choose_workers(requested: int, adaptive: bool = True, soft_cap: int = 4, hard_cap: int = 8) -> int:
    """
    Clamp worker count for stability.
    When adaptive and requested > soft_cap, start at soft_cap (default 4).
    Hard cap is 8.
    """
    req = max(1, min(int(requested or 1), int(hard_cap)))
    if not adaptive:
        return req
    if req <= soft_cap:
        return req
    return max(1, min(int(soft_cap), req))


def discover_cpa_files(temp_dir: str, main_cpa_dir: str) -> list[str]:
    """Scan worker temp dirs + main cpa_auths for xai-*.json CPA files."""
    found: list[str] = []
    seen: set[str] = set()

    patterns = [
        os.path.join(temp_dir, "grok_worker_*", "cpa_auths", "xai-*.json"),
        os.path.join(main_cpa_dir, "xai-*.json"),
    ]
    for pat in patterns:
        for path in glob.glob(pat):
            key = os.path.basename(path).lower()
            if key in seen:
                continue
            seen.add(key)
            found.append(path)
    return found


def discover_sso_tokens(temp_dir: str, main_token_json: str) -> list[str]:
    """Collect SSO tokens from worker token.json / accounts + main token.json."""
    import json

    tokens: list[str] = []
    seen: set[str] = set()

    def _add(tok: str) -> None:
        t = (tok or "").strip()
        if t and t not in seen:
            seen.add(t)
            tokens.append(t)

    # Main token.json
    if os.path.isfile(main_token_json):
        try:
            with open(main_token_json, encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("ssoBasic", []) or []:
                _add(entry.get("token", ""))
        except (json.JSONDecodeError, OSError):
            pass

    # Worker token.json files
    for path in glob.glob(os.path.join(temp_dir, "grok_worker_*", "token.json")):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("ssoBasic", []) or []:
                _add(entry.get("token", ""))
        except (json.JSONDecodeError, OSError):
            pass

    # Worker accounts/*.txt  (email----password----sso)
    for accf in glob.glob(os.path.join(temp_dir, "grok_worker_*", "accounts", "*.txt")):
        name = os.path.basename(accf)
        if name in ("mail_credentials.txt", "sso_pending.txt", "sso_risk_rejected.txt"):
            continue
        try:
            with open(accf, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if "----" in line:
                        _add(line.split("----")[-1])
        except OSError:
            pass

    return tokens


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def cpa_email_from_file(path: str) -> str:
    import json

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        email = str(data.get("email", "") or "").strip()
        if email:
            return email
    except (json.JSONDecodeError, OSError):
        pass
    m = _EMAIL_RE.search(os.path.basename(path))
    return m.group(0) if m else os.path.basename(path)
