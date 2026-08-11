"""Batch resume state — simpan/load posisi batch supaya bisa lanjut setelah crash.

State file: <REPO>/log/batch_state.json
Fields:
    target      — jumlah akun target batch
    completed   — berapa akun yang sudah selesai (CPA + SSO terhitung)
    batch_id    — id batch (timestamp)
    started_at  — waktu mulai
    updated_at  — update terakhir
    workers     — worker yang dipakai
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_FILE = os.path.join(REPO, "log", "batch_state.json")


def _state_path() -> str:
    """Path ke batch state (bisa di-override env utk test)."""
    return os.environ.get("GROK_BATCH_STATE_FILE", STATE_FILE)


def save_batch_state(
    target: int,
    completed: int,
    *,
    workers: int = 1,
    batch_id: str = "",
) -> dict:
    """Simpan state batch (atomik via write-then-rename)."""
    os.makedirs(os.path.dirname(_state_path()), exist_ok=True)
    now = time.time()
    state = {
        "target": max(0, int(target)),
        "completed": max(0, int(completed)),
        "batch_id": batch_id or time.strftime("%Y%m%d_%H%M%S"),
        "started_at": now,
        "updated_at": now,
        "workers": max(1, int(workers)),
    }
    tmp = f"{_state_path()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, _state_path())
    return state


def update_batch_state(completed: int | None = None, **overrides) -> dict | None:
    """Update state yang sudah ada; return None kalau belum ada state."""
    current = load_batch_state()
    if current is None:
        return None
    if completed is not None:
        current["completed"] = max(0, int(completed))
    for key, val in overrides.items():
        current[key] = val
    current["updated_at"] = time.time()
    try:
        with open(_state_path(), "w", encoding="utf-8") as f:
            json.dump(current, f, indent=2)
    except OSError:
        return None
    return current


def load_batch_state() -> dict | None:
    """Load state; return None kalau tidak ada / corrupt."""
    path = _state_path()
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None
        data.setdefault("target", 0)
        data.setdefault("completed", 0)
        data.setdefault("workers", 1)
        return data
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def clear_batch_state() -> bool:
    """Hapus state file (setelah batch selesai / --clear-state)."""
    try:
        os.remove(_state_path())
        return True
    except OSError:
        return False


def remaining(state: dict | None) -> int:
    """Sisa akun = target - completed (min 0)."""
    if not state:
        return 0
    return max(0, int(state.get("target", 0)) - int(state.get("completed", 0)))
