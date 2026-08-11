"""Supervise headless registration batches and recover crashed browser drivers."""

from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from runtime_platform import popen_group_kwargs
from secure_files import atomic_write_json, exclusive_file_lock


PROGRESS_ENV = "GROK_BATCH_PROGRESS_FILE"
ACCOUNT_STALL_ENV = "GROK_BATCH_ACCOUNT_STALL_SEC"
DEFAULT_IDLE_TIMEOUT = 360
DEFAULT_MAX_RESTARTS = 8
DEFAULT_ACCOUNT_STALL_TIMEOUT = 240
_LAST_ERROR_MAX_LEN = 500
_PROGRESS_EVENT_KINDS = frozenset({"success", "fail", "heartbeat", "error"})

_PROGRESS_LOCK = threading.Lock()
_DRIVER_CRASH_MARKERS = (
    "Cannot read properties of undefined (reading '_getChildFrames')",
    "Cannot read properties of undefined (reading 'childFrames')",
    "Connection closed while reading from the driver",
    "Playwright driver unexpectedly exited",
)


def is_driver_crash_line(line: str) -> bool:
    text = str(line or "")
    return any(marker in text for marker in _DRIVER_CRASH_MARKERS)


def _default_progress(target: int = 0) -> dict[str, Any]:
    now = time.time()
    return {
        "completed": 0,
        "target": max(0, int(target)),
        "updated_at": now,
        "success": 0,
        "fail": 0,
        "last_error": "",
        "last_heartbeat": now,
    }


def _coerce_progress(data: Any, *, target: int | None = None) -> dict[str, Any]:
    base = _default_progress(0 if target is None else target)
    if not isinstance(data, dict):
        return base
    try:
        completed = max(0, int(data.get("completed", 0) or 0))
    except (TypeError, ValueError):
        completed = 0
    try:
        stored_target = max(0, int(data.get("target", 0) or 0))
    except (TypeError, ValueError):
        stored_target = 0
    if target is not None:
        stored_target = max(0, int(target))
    try:
        updated_at = float(data.get("updated_at", 0) or 0)
    except (TypeError, ValueError):
        updated_at = 0.0
    try:
        success = max(0, int(data.get("success", 0) or 0))
    except (TypeError, ValueError):
        success = 0
    try:
        fail = max(0, int(data.get("fail", 0) or 0))
    except (TypeError, ValueError):
        fail = 0
    last_error = str(data.get("last_error", "") or "")
    if len(last_error) > _LAST_ERROR_MAX_LEN:
        last_error = last_error[:_LAST_ERROR_MAX_LEN]
    try:
        last_heartbeat = float(data.get("last_heartbeat", 0) or 0)
    except (TypeError, ValueError):
        last_heartbeat = 0.0
    if not last_heartbeat:
        last_heartbeat = updated_at or time.time()
    if not updated_at:
        updated_at = last_heartbeat or time.time()
    return {
        "completed": completed,
        "target": stored_target,
        "updated_at": updated_at,
        "success": success,
        "fail": fail,
        "last_error": last_error,
        "last_heartbeat": last_heartbeat,
    }


def _read_progress_unlocked(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        data = {}
    return _coerce_progress(data)


def _write_progress_unlocked(path: Path, data: Mapping[str, Any]) -> None:
    payload = _coerce_progress(dict(data))
    atomic_write_json(path, payload)


def _with_progress_lock(path: Path, mutator: Callable[[dict[str, Any]], dict[str, Any]]) -> dict[str, Any]:
    lock_path = path.with_name(f"{path.name}.lock")
    with _PROGRESS_LOCK:
        with exclusive_file_lock(lock_path):
            data = _read_progress_unlocked(path)
            updated = mutator(data)
            _write_progress_unlocked(path, updated)
            return _coerce_progress(updated)


def read_completed(path: str | os.PathLike[str]) -> int:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return max(0, int(data.get("completed", 0) or 0))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return 0


def read_progress(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Read full progress payload (best-effort; no file lock)."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        data = {}
    return _coerce_progress(data)


def initialize_progress(path: str | os.PathLike[str], target: int) -> Path:
    progress_path = Path(path)
    atomic_write_json(progress_path, _default_progress(target))
    return progress_path


def mark_slot_completed(slots: int = 1) -> None:
    """Persist completed task slots for the supervising parent process."""
    raw_path = str(os.environ.get(PROGRESS_ENV, "") or "").strip()
    if not raw_path:
        return
    increment = max(0, int(slots or 0))
    if increment <= 0:
        return

    path = Path(raw_path)

    def _mutate(data: dict[str, Any]) -> dict[str, Any]:
        now = time.time()
        completed = max(0, int(data.get("completed", 0) or 0)) + increment
        target = max(0, int(data.get("target", 0) or 0))
        if target:
            completed = min(completed, target)
        success = max(0, int(data.get("success", 0) or 0)) + increment
        data["completed"] = completed
        data["target"] = target
        data["success"] = success
        data["updated_at"] = now
        data["last_heartbeat"] = now
        return data

    _with_progress_lock(path, _mutate)


def mark_progress_event(kind: str, detail: str = "") -> None:
    """Record a progress side-channel event (success|fail|heartbeat|error)."""
    event = str(kind or "").strip().lower()
    if event not in _PROGRESS_EVENT_KINDS:
        raise ValueError(f"unsupported progress event kind: {kind!r}")
    raw_path = str(os.environ.get(PROGRESS_ENV, "") or "").strip()
    if not raw_path:
        return

    path = Path(raw_path)
    detail_text = str(detail or "")
    if len(detail_text) > _LAST_ERROR_MAX_LEN:
        detail_text = detail_text[:_LAST_ERROR_MAX_LEN]

    def _mutate(data: dict[str, Any]) -> dict[str, Any]:
        now = time.time()
        data["last_heartbeat"] = now
        if event == "heartbeat":
            # Heartbeats keep last_heartbeat fresh without claiming account progress.
            return data
        if event == "success":
            data["success"] = max(0, int(data.get("success", 0) or 0)) + 1
            data["updated_at"] = now
            return data
        if event == "fail":
            data["fail"] = max(0, int(data.get("fail", 0) or 0)) + 1
            data["updated_at"] = now
            if detail_text:
                data["last_error"] = detail_text
            return data
        # error
        data["updated_at"] = now
        if detail_text:
            data["last_error"] = detail_text
        return data

    _with_progress_lock(path, _mutate)


def _resolve_account_stall_timeout(account_stall_timeout: float | None) -> float:
    if account_stall_timeout is not None:
        return max(0.0, float(account_stall_timeout))
    raw = str(os.environ.get(ACCOUNT_STALL_ENV, "") or "").strip()
    if raw:
        try:
            return max(0.0, float(raw))
        except ValueError:
            pass
    return float(DEFAULT_ACCOUNT_STALL_TIMEOUT)


def _terminate_process_group(process: subprocess.Popen, grace_seconds: float = 5.0) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:  # pragma: no cover - Windows fallback
            process.terminate()
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=max(0.1, grace_seconds))
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover - Windows fallback
            process.kill()
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass


def run_supervisor(
    count: int,
    workers: int,
    child_command_builder: Callable[[int, int], Sequence[str]],
    *,
    progress_file: str | os.PathLike[str],
    idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
    max_restarts: int = DEFAULT_MAX_RESTARTS,
    child_env: Mapping[str, str] | None = None,
    account_stall_timeout: float | None = None,
) -> int:
    """Run a batch child and restart the remaining work after a driver crash."""
    target = max(1, int(count))
    worker_count = max(1, min(24, int(workers), target))
    progress_path = initialize_progress(progress_file, target)
    stop_requested = False
    active_process: subprocess.Popen | None = None
    restarts = 0
    stall_timeout = _resolve_account_stall_timeout(account_stall_timeout)
    last_logged_completed = -1

    def request_stop(_signum, _frame):
        nonlocal stop_requested
        stop_requested = True

    can_install_signals = threading.current_thread() is threading.main_thread()
    previous_handlers: dict[int, object] = {}
    if can_install_signals:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, request_stop)

    try:
        while not stop_requested:
            completed = read_completed(progress_path)
            remaining = max(0, target - completed)
            if remaining <= 0:
                print(
                    f"[supervisor] batch complete completed={completed}/{target} restarts={restarts}",
                    flush=True,
                )
                return 0
            if restarts > max(0, int(max_restarts)):
                print(
                    f"[supervisor] restart limit reached remaining={remaining} restarts={restarts}",
                    flush=True,
                )
                return 1

            command = [str(part) for part in child_command_builder(remaining, worker_count)]
            env = {**os.environ, **dict(child_env or {})}
            env[PROGRESS_ENV] = str(progress_path)
            print(
                f"[supervisor] starting child remaining={remaining} workers={worker_count} restart={restarts}",
                flush=True,
            )
            active_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
                **popen_group_kwargs(),
            )
            assert active_process.stdout is not None
            stdout_lines: "queue.Queue[str]" = queue.Queue()
            last_output = time.monotonic()
            child_started = time.monotonic()
            # Baseline progress wall-clock so stall is measured from this child launch.
            progress_snapshot = read_progress(progress_path)
            last_progress_wall = float(progress_snapshot.get("updated_at") or time.time())
            last_completed_seen = int(progress_snapshot.get("completed") or 0)
            restart_reason = ""

            def _stdout_pump() -> None:
                assert active_process.stdout is not None
                try:
                    for line in active_process.stdout:
                        stdout_lines.put(line)
                except (OSError, ValueError):
                    pass

            pump = threading.Thread(target=_stdout_pump, daemon=True)
            pump.start()

            def _handle_line(line: str) -> bool:
                nonlocal last_output, restart_reason
                if not line:
                    return False
                # Whitespace-only lines are not meaningful activity for idle timeout.
                if line.strip():
                    last_output = time.monotonic()
                print(line, end="", flush=True)
                if is_driver_crash_line(line):
                    restart_reason = "playwright driver crashed"
                    return True
                return False

            try:
                while not stop_requested:
                    while True:
                        try:
                            line = stdout_lines.get_nowait()
                        except queue.Empty:
                            break
                        if _handle_line(line):
                            break
                    if restart_reason:
                        break
                    return_code = active_process.poll()
                    if return_code is not None:
                        while True:
                            try:
                                line = stdout_lines.get_nowait()
                            except queue.Empty:
                                break
                            _handle_line(line)
                        break
                    if time.monotonic() - last_output > max(1.0, float(idle_timeout)):
                        restart_reason = f"no child output for {int(idle_timeout)}s"
                        break

                    # Account stall: process alive, completed < target, progress not advancing.
                    if stall_timeout > 0:
                        snap = read_progress(progress_path)
                        snap_completed = int(snap.get("completed") or 0)
                        snap_updated = float(snap.get("updated_at") or 0.0)
                        if snap_completed > last_completed_seen:
                            last_completed_seen = snap_completed
                            last_progress_wall = snap_updated or time.time()
                            if snap_completed != last_logged_completed:
                                last_logged_completed = snap_completed
                                print(
                                    f"[supervisor] progress completed={snap_completed}/{target} restarts={restarts}",
                                    flush=True,
                                )
                        elif snap_updated > last_progress_wall:
                            # success/fail events bump updated_at without completed change.
                            last_progress_wall = snap_updated

                        alive_for = time.monotonic() - child_started
                        stalled_for = time.time() - last_progress_wall if last_progress_wall else alive_for
                        if (
                            snap_completed < target
                            and alive_for >= stall_timeout
                            and stalled_for >= stall_timeout
                        ):
                            restart_reason = "account stall"
                            break

                    time.sleep(0.1)
            finally:
                pump.join(timeout=2.0)

            if stop_requested:
                _terminate_process_group(active_process)
                return 130

            return_code = active_process.poll()
            if restart_reason:
                _terminate_process_group(active_process)
                restarts += 1
                remaining = max(0, target - read_completed(progress_path))
                print(
                    f"[supervisor] {restart_reason}; restarting remaining={remaining} attempt={restarts}/{max_restarts}",
                    flush=True,
                )
                time.sleep(min(1.0 * restarts, 5.0))
                continue

            completed = read_completed(progress_path)
            if completed != last_logged_completed:
                last_logged_completed = completed
                print(
                    f"[supervisor] progress completed={completed}/{target} restarts={restarts}",
                    flush=True,
                )
            if return_code == 0 and completed >= target:
                print(
                    f"[supervisor] child exited cleanly completed={completed}/{target}",
                    flush=True,
                )
                return 0

            restarts += 1
            remaining = max(0, target - completed)
            print(
                f"[supervisor] child exited rc={return_code} completed={completed}/{target}; "
                f"restarting remaining={remaining} attempt={restarts}/{max_restarts}",
                flush=True,
            )
            time.sleep(min(1.0 * restarts, 5.0))
    finally:
        if active_process is not None and active_process.poll() is None:
            _terminate_process_group(active_process)
        if can_install_signals:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
        for path in (progress_path, progress_path.with_name(f"{progress_path.name}.lock")):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass

    return 130
