#!/usr/bin/env python3
"""Grok register batch live monitor — bind Tailscale, control + blacklist panel."""
from __future__ import annotations

import json
import ipaddress
import os
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secure_files import atomic_write_json, ensure_private_dir
from runtime_platform import (
    batch_launch_command,
    batch_runtime_error,
    popen_group_kwargs,
    runtime_python,
)

try:
    from webui.blacklist_store import read_blacklist as read_blacklist_state
    from webui.proxy_store import (
        delete_proxy,
        import_legacy_proxies,
        import_proxies,
        read_proxy_pool,
        start_proxy_tests,
        update_proxy,
    )
    from webui.email_domain_store import (
        delete_domain,
        import_domains,
        read_email_domain_pool,
        reset_domain,
        update_domain,
        update_settings as update_email_domain_settings,
    )
    from webui.email_provider_store import (
        read_email_provider_config,
        save_email_provider_config,
        test_email_provider_config,
    )
    from webui.process_utils import (
        find_managed_processes,
        terminate_managed_processes,
        write_pid_file,
    )
    from webui.recovery_ops import recovery_status, start_recovery, stop_recovery
    from webui.security_utils import (
        check_token_optional_read,
        expected_token,
        mask_email,
        redact_log_line,
        redact_proxy,
    )
except ImportError:  # running as script from webui/
    from blacklist_store import read_blacklist as read_blacklist_state  # type: ignore
    from proxy_store import (  # type: ignore
        delete_proxy,
        import_legacy_proxies,
        import_proxies,
        read_proxy_pool,
        start_proxy_tests,
        update_proxy,
    )
    from email_domain_store import (  # type: ignore
        delete_domain,
        import_domains,
        read_email_domain_pool,
        reset_domain,
        update_domain,
        update_settings as update_email_domain_settings,
    )
    from email_provider_store import (  # type: ignore
        read_email_provider_config,
        save_email_provider_config,
        test_email_provider_config,
    )
    from process_utils import (  # type: ignore
        find_managed_processes,
        terminate_managed_processes,
        write_pid_file,
    )
    from recovery_ops import recovery_status, start_recovery, stop_recovery  # type: ignore
    from security_utils import (  # type: ignore
        check_token_optional_read,
        expected_token,
        mask_email,
        redact_log_line,
        redact_proxy,
    )
LOG_DIR = ROOT / "log"


def _config_cpa_dir():
    try:
        cfg = json.loads((ROOT / "config.json").read_text(encoding="utf-8") or "{}")
        raw = str(cfg.get("cpa_auth_dir") or "").strip()
        if raw:
            path = Path(raw).expanduser()
            if not path.is_absolute():
                path = ROOT / path
            return path
    except Exception:
        pass
    return ROOT / "cpa_auth"


CPA_DIR = Path(os.environ.get("CPA_AUTH_DIR", str(_config_cpa_dir())))
ASSET_DIR = Path(__file__).resolve().parent / "assets"
FONT_ASSETS = {
    "/assets/geist.woff2": ASSET_DIR / "geist-latin-wght-normal.woff2",
    "/assets/geist-mono.woff2": ASSET_DIR / "geist-mono-latin-wght-normal.woff2",
}
MONITOR_TOKEN_ENV = "MONITOR_TOKEN"
PANEL_INCLUDE_TAIL = os.environ.get("PANEL_INCLUDE_TAIL", "0").strip() in ("1", "true", "yes")

BATCH_STATE_FILE = LOG_DIR / "batch_state.json"
BATCH_PROGRESS_FILE = LOG_DIR / "batch_progress.json"


def read_batch_state_live() -> dict:
    """Read gro_register_to_9router batch state + live progress for dashboard.

    Returns dict with keys: exists, target, completed, remaining, pct,
    updated_at, started_at, workers, batch_id, running, running_age_s.
    """
    out = {
        "exists": False,
        "target": 0,
        "completed": 0,
        "remaining": 0,
        "pct": 0.0,
        "updated_at": None,
        "started_at": None,
        "workers": 1,
        "batch_id": "",
        "running": False,
        "running_age_s": 0,
    }
    try:
        if BATCH_STATE_FILE.is_file():
            data = json.loads(BATCH_STATE_FILE.read_text(encoding="utf-8") or "{}")
            if isinstance(data, dict):
                target = max(0, int(data.get("target", 0) or 0))
                completed = max(0, int(data.get("completed", 0) or 0))
                out.update(
                    {
                        "exists": True,
                        "target": target,
                        "completed": completed,
                        "remaining": max(0, target - completed),
                        "pct": round(100.0 * completed / target, 2) if target else 0.0,
                        "updated_at": data.get("updated_at"),
                        "started_at": data.get("started_at"),
                        "workers": int(data.get("workers", 1) or 1),
                        "batch_id": str(data.get("batch_id", "") or ""),
                    }
                )
        # Running detection: progress file fresh (updated within 90s) OR managed process
        if BATCH_PROGRESS_FILE.is_file():
            try:
                pdata = json.loads(BATCH_PROGRESS_FILE.read_text(encoding="utf-8") or "{}")
                if isinstance(pdata, dict) and pdata.get("completed") is not None:
                    comp = max(0, int(pdata.get("completed", 0) or 0))
                    target = max(0, int(pdata.get("target", 0) or 0))
                    if target:
                        out["completed"] = max(out["completed"], comp)
                        out["remaining"] = max(0, target - out["completed"])
                        out["pct"] = round(100.0 * out["completed"] / target, 2)
                        out["target"] = target
                        out["exists"] = True
            except Exception:
                pass
        # running = progress file fresh (updated within 90s) OR batch_state fresh
        p_updated = None
        if BATCH_PROGRESS_FILE.is_file():
            try:
                pdata = json.loads(BATCH_PROGRESS_FILE.read_text(encoding="utf-8") or "{}")
                if isinstance(pdata, dict):
                    p_updated = pdata.get("updated_at")
                    comp = max(0, int(pdata.get("completed", 0) or 0))
                    tgt = max(0, int(pdata.get("target", 0) or 0))
                    if tgt:
                        out["completed"] = max(out["completed"], comp)
                        out["remaining"] = max(0, tgt - out["completed"])
                        out["pct"] = round(100.0 * out["completed"] / tgt, 2)
                        out["target"] = tgt
                        out["exists"] = True
            except Exception:
                pass
        now = time.time()
        p_age = (now - p_updated) if isinstance(p_updated, (int, float)) and p_updated > 0 else 999
        b_updated = out.get("updated_at")
        b_age = (now - b_updated) if isinstance(b_updated, (int, float)) and b_updated > 0 else 999
        alive = p_age < 90 or b_age < 90
        ref = p_updated if isinstance(p_updated, (int, float)) else b_updated
        out["running"] = alive
        out["running_age_s"] = max(0, int(now - ref)) if ref else 0
    except Exception:
        pass
    return out


BASE_FILE = LOG_DIR / "batch1000.base"
ORCH_PID = LOG_DIR / "orch100.pid"
BATCH_PID = LOG_DIR / "batch100.pid"
CONTROL_FILE = LOG_DIR / "monitor_control.json"
STATS_CACHE = LOG_DIR / "monitor_stats.json"
BIND_HOST = os.environ.get("MONITOR_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("MONITOR_PORT", "8787"))
VENV_PY = runtime_python(ROOT)
ORCH_SCRIPT = ROOT / "run_until_100.py"
CONTROL_LOCK = threading.RLock()
START_LOCK = threading.Lock()
MAX_REQUEST_BODY = 64 * 1024

RE_OK = re.compile(r"\[\+\] 注册成功")
RE_FAIL = re.compile(r"\[-\] 失败")
RE_DOMAIN = re.compile(r"\[-\] 域名拒绝")
RE_SKIP = re.compile(r"\[-\] 卡住跳过")
RE_BOT0 = re.compile(r"botFlagSource=0")
RE_BOT1 = re.compile(r"botFlagSource=1")
RE_EMAIL_OK = re.compile(r"\[\+\] 注册成功(?:（[^）]*）)?:\s*(\S+)")
RE_FAIL_KIND = re.compile(r"\[-\] 失败 \[([^\]]+)\]:\s*(.*)")
RE_WORKER = re.compile(r"\[W(\d+)\]")
RE_BATCH = re.compile(r"\[batch\] count=(\d+) workers=(\d+)")
RE_START = re.compile(r"终端模式启动，目标数量:\s*(\d+)\s*\|\s*并发:\s*(\d+)")
RE_END = re.compile(r"任务结束。成功\s*(\d+)\s*\|\s*失败\s*(\d+)")
RE_ADDED_BL = re.compile(r"ADDED blacklist AS(\d+)")
RE_LOOKUP_FAIL = re.compile(r"lookup fail", re.I)
RE_ANALYZE_ERR = re.compile(r"analyze error", re.I)


def _read_json(path: Path, default=None):
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8") or "{}")
    except Exception:
        pass
    return default if default is not None else {}


def _write_json(path: Path, data: dict):
    atomic_write_json(path, data)


def load_control() -> dict:
    with CONTROL_LOCK:
        c = _read_json(CONTROL_FILE, {})
        c.setdefault("workers", 3)
        c.setdefault("risk_pause", 10)
        c.setdefault("batch_count", 40)
        c.setdefault("add_count", 40)  # 再跑 N 个
        c.setdefault("mode", "orch")  # orch | batch
        return c


def save_control(updates: dict) -> dict:
    allowed = {
        "workers",
        "risk_pause",
        "batch_count",
        "add_count",
        "mode",
        "base_cpa",
        "target_cpa",
    }
    with CONTROL_LOCK:
        c = load_control()
        c.update({key: value for key, value in (updates or {}).items() if key in allowed})
        try:
            c["workers"] = max(1, min(24, int(c.get("workers", 3))))
        except Exception:
            c["workers"] = 3
        try:
            c["risk_pause"] = max(1, min(50, int(c.get("risk_pause", 10))))
        except Exception:
            c["risk_pause"] = 10
        try:
            c["batch_count"] = max(1, min(200, int(c.get("batch_count", 40))))
        except Exception:
            c["batch_count"] = 40
        try:
            c["add_count"] = max(1, min(500, int(c.get("add_count", 40))))
        except Exception:
            c["add_count"] = 40
        c["mode"] = c.get("mode") if c.get("mode") in ("orch", "batch") else "orch"
        for key in ("base_cpa", "target_cpa"):
            if c.get(key) is None or str(c.get(key)).strip() == "":
                c.pop(key, None)
                continue
            try:
                c[key] = max(0, int(c[key]))
            except Exception:
                c.pop(key, None)
        c["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        _write_json(CONTROL_FILE, c)
        return c


def discover_log():
    env = os.environ.get("BATCH_LOG")
    if env and Path(env).is_file():
        return Path(env)
    cands = sorted(LOG_DIR.glob("batch*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    cands = [p for p in cands if "sticky" not in p.name and "rotate" not in p.name]
    return cands[0] if cands else None


def read_base():
    """Prefer control.base_cpa; fall back to batch1000.base file if present."""
    try:
        c = load_control()
        if c.get("base_cpa") is not None and str(c.get("base_cpa")).strip() != "":
            return int(c["base_cpa"])
    except Exception:
        pass
    try:
        return int(BASE_FILE.read_text().strip())
    except Exception:
        return 0


def process_running():
    """Detect orch and/or batch workers."""
    info = {
        "running": False,
        "pid": None,
        "etime": None,
        "cmd": None,
        "orch_running": False,
        "orch_pid": None,
        "orch_etime": None,
        "batch_running": False,
        "batch_pid": None,
        "batch_etime": None,
    }
    orch = find_managed_processes(ROOT, ("run_until_100.py",))
    batch = find_managed_processes(ROOT, ("run_batch_headless.py",))

    def primary(items):
        if not items:
            return None
        return next((item for item in items if item.get("pgid") == item.get("pid")), items[0])

    orch_item = primary(orch)
    batch_item = primary(batch)
    if orch_item:
        info["orch_running"] = True
        info["orch_pid"] = orch_item["pid"]
        info["orch_etime"] = orch_item.get("etime")
        info["running"] = True
        info["pid"] = orch_item["pid"]
        info["etime"] = orch_item.get("etime")
        info["cmd"] = orch_item.get("cmd")
    if batch_item:
        info["batch_running"] = True
        info["batch_pid"] = batch_item["pid"]
        info["batch_etime"] = batch_item.get("etime")
        if not info["running"]:
            info["running"] = True
            info["pid"] = batch_item["pid"]
            info["etime"] = batch_item.get("etime")
            info["cmd"] = batch_item.get("cmd")
    return info


def parse_log(path, max_tail=400_000):
    if not path or not path.is_file():
        return {"error": "no log"}
    size = path.stat().st_size
    with path.open("rb") as f:
        if size > max_tail:
            f.seek(size - max_tail)
            f.readline()
        text = f.read().decode("utf-8", errors="replace")

    lines = text.splitlines()
    ok = fail = domain = skip = bot0 = bot1 = 0
    count = workers = None
    ended = None
    recent_ok = []
    recent_fail = []
    fail_kinds = {}
    worker_ok = {}
    worker_fail = {}

    for line in lines:
        m = RE_BATCH.search(line) or RE_START.search(line)
        if m:
            count, workers = int(m.group(1)), int(m.group(2))
        m = RE_END.search(line)
        if m:
            ended = {"success": int(m.group(1)), "fail": int(m.group(2))}

        if RE_OK.search(line):
            ok += 1
            em = RE_EMAIL_OK.search(line)
            email = em.group(1) if em else ""
            wm = RE_WORKER.search(line)
            w = f"W{wm.group(1)}" if wm else "?"
            worker_ok[w] = worker_ok.get(w, 0) + 1
            ts = line[1:9] if line.startswith("[") else ""
            recent_ok.append({"t": ts, "w": w, "email": mask_email(email)})
        if RE_FAIL.search(line):
            fail += 1
            fm = RE_FAIL_KIND.search(line)
            kind = fm.group(1) if fm else "其它"
            msg = fm.group(2) if fm else line[-120:]
            if "inputs=none" in msg:
                kind = "空页UI"
            if "Turnstile" in msg or "Turnstile" in kind:
                kind = "资料页Turnstile" if "Turnstile" in msg else kind
            fail_kinds[kind] = fail_kinds.get(kind, 0) + 1
            wm = RE_WORKER.search(line)
            w = f"W{wm.group(1)}" if wm else "?"
            worker_fail[w] = worker_fail.get(w, 0) + 1
            ts = line[1:9] if line.startswith("[") else ""
            recent_fail.append({"t": ts, "w": w, "kind": kind, "msg": redact_log_line(msg[:160])})
        if RE_DOMAIN.search(line):
            domain += 1
        if RE_SKIP.search(line):
            skip += 1
        if RE_BOT0.search(line):
            bot0 += 1
        if RE_BOT1.search(line):
            bot1 += 1

    last_lines = lines[-40:]
    if size > max_tail:
        def gcount(pat):
            r = subprocess.run(["grep", "-c", pat, str(path)], capture_output=True, text=True)
            try:
                return int(r.stdout.strip() or 0)
            except Exception:
                return 0

        ok = gcount("注册成功")
        fail = gcount(r"\[-\] 失败")
        bot0 = gcount("botFlagSource=0")
        bot1 = gcount("botFlagSource=1")

    return {
        "log": path.name,
        "log_name": path.name,
        "log_size": size,
        "mtime": path.stat().st_mtime,
        "count_target": count,
        "workers": workers,
        "ok": ok,
        "fail": fail,
        "domain": domain,
        "skip": skip,
        "bot0": bot0,
        "bot1": bot1,
        "ended": ended,
        "fail_kinds": fail_kinds,
        "worker_ok": worker_ok,
        "worker_fail": worker_fail,
        "recent_ok": recent_ok[-25:][::-1],
        "recent_fail": recent_fail[-25:][::-1],
        "tail": [redact_log_line(line) for line in last_lines],
    }


def cpa_count():
    try:
        return sum(1 for p in CPA_DIR.iterdir() if p.is_file() and p.name.startswith("xai-"))
    except Exception:
        try:
            return sum(1 for _ in CPA_DIR.iterdir() if _.is_file())
        except Exception:
            return 0


def read_blacklist():
    return read_blacklist_state()


def blacklist_update_errors():
    """Count blacklist expansion / ASN lookup errors from orch logs."""
    added = []
    lookup_fails = 0
    analyze_errors = 0
    hit_pause = 0
    try:
        logs = sorted(LOG_DIR.glob("orch100*.log"), key=lambda p: p.stat().st_mtime, reverse=True)[:8]
        logs += sorted(LOG_DIR.glob("orch100-stdout.log"), key=lambda p: p.stat().st_mtime, reverse=True)[:1]
        seen = set()
        for path in logs:
            if str(path) in seen or not path.is_file():
                continue
            seen.add(str(path))
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for line in text.splitlines():
                m = RE_ADDED_BL.search(line)
                if m:
                    added.append({"asn": int(m.group(1)), "line": line[-120:], "log": path.name})
                if RE_LOOKUP_FAIL.search(line):
                    lookup_fails += 1
                if RE_ANALYZE_ERR.search(line):
                    analyze_errors += 1
                if "pause+blacklist" in line or "HIT" in line and "注册风控" in line:
                    hit_pause += 1
    except Exception:
        pass
    # unique recent added (last 30)
    uniq = []
    seen_a = set()
    for a in reversed(added):
        if a["asn"] in seen_a:
            continue
        seen_a.add(a["asn"])
        uniq.append(a)
        if len(uniq) >= 30:
            break
    uniq.reverse()
    return {
        "lookup_fail_count": lookup_fails,
        "analyze_error_count": analyze_errors,
        "error_count": lookup_fails + analyze_errors,
        "hit_pause_count": hit_pause,
        "recent_added": uniq[-15:],
        "added_total": len(added),
    }


def success_stats():
    """Aggregate success stats: CPA + jsonl + time-window rates + latest batch."""
    from datetime import datetime, timezone, timedelta

    cpa = cpa_count()
    configured_base = read_base()
    base_stale = configured_base < 0 or configured_base > cpa
    base = cpa if base_stale else configured_base
    jsonl_ok = 0
    jsonl_risk = 0
    jsonl_fail = 0
    by_day = {}
    results = LOG_DIR / "register_results.jsonl"

    # windows in hours -> counters
    windows_h = (1, 3, 12)
    now = datetime.now(timezone.utc)
    win = {
        h: {"ok": 0, "fail": 0, "risk": 0, "total": 0, "since": (now - timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        for h in windows_h
    }

    def _parse_ts(ts: str):
        if not ts:
            return None
        s = str(ts).strip()
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            return None

    try:
        if results.exists():
            size = results.stat().st_size
            # last 8MB covers 12h under high volume
            with results.open("rb") as f:
                if size > 8_000_000:
                    f.seek(size - 8_000_000)
                    f.readline()
                for line in f:
                    try:
                        o = json.loads(line.decode("utf-8", errors="replace"))
                    except Exception:
                        continue
                    st = o.get("status")
                    day = (o.get("ts") or "")[:10]
                    if day:
                        by_day.setdefault(day, {"ok": 0, "risk": 0, "fail": 0})
                    if st == "ok":
                        jsonl_ok += 1
                        if day:
                            by_day[day]["ok"] += 1
                    elif st == "risk":
                        jsonl_risk += 1
                        if day:
                            by_day[day]["risk"] += 1
                    elif st:
                        jsonl_fail += 1
                        if day:
                            by_day[day]["fail"] += 1

                    dt = _parse_ts(o.get("ts") or "")
                    if not dt:
                        continue
                    age = now - dt
                    for h in windows_h:
                        if age <= timedelta(hours=h):
                            bucket = win[h]
                            if st == "ok":
                                bucket["ok"] += 1
                            elif st == "risk":
                                bucket["risk"] += 1
                            elif st:
                                bucket["fail"] += 1
                            if st in ("ok", "risk", "fail", "sso_timeout", "browser", "other"):
                                bucket["total"] += 1
                            elif st:
                                bucket["total"] += 1
    except Exception:
        pass

    # normalize window rates
    rates = {}
    for h, b in win.items():
        # total attempts that finished with a status
        total = int(b["ok"]) + int(b["fail"]) + int(b["risk"])
        ok = int(b["ok"])
        rate = round(100.0 * ok / total, 1) if total else None
        rates[f"{h}h"] = {
            "hours": h,
            "ok": ok,
            "fail": int(b["fail"]),
            "risk": int(b["risk"]),
            "total": total,
            "success_rate": rate,
            "since": b["since"],
        }

    log = discover_log()
    parsed = parse_log(log) if log else {}
    batch_ok = parsed.get("ok") or 0
    batch_fail = parsed.get("fail") or 0
    data = {
        "cpa": cpa,
        "base_cpa": base,
        "base_cpa_stale": base_stale,
        "cpa_delta": cpa - base,
        "jsonl_ok": jsonl_ok,
        "jsonl_risk": jsonl_risk,
        "jsonl_fail": jsonl_fail,
        "batch_ok": batch_ok,
        "batch_fail": batch_fail,
        "batch_log": parsed.get("log_name"),
        "by_day": by_day,
        "rates": rates,
        "refreshed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    try:
        _write_json(STATS_CACHE, data)
    except Exception:
        pass
    return data




def _parse_etime(s):
    if not s:
        return None
    s = s.strip()
    try:
        days = 0
        if "-" in s:
            d, s = s.split("-", 1)
            days = int(d)
        parts = [int(x) for x in s.split(":")]
        if len(parts) == 3:
            h, m, sec = parts
        elif len(parts) == 2:
            h = 0
            m, sec = parts
        else:
            return None
        return days * 86400 + h * 3600 + m * 60 + sec
    except Exception:
        return None


def kill_all():
    """Stop only orchestrator and batch processes under this project root."""
    killed = terminate_managed_processes(
        ROOT,
        ("run_until_100.py", "run_batch_headless.py"),
    )
    return {"ok": True, "killed": killed}


def _runtime_prerequisite_error() -> str | None:
    if not VENV_PY.is_file():
        return f"missing runtime python: {VENV_PY}"
    if not (ROOT / "config.json").is_file():
        return f"missing config: {ROOT / 'config.json'}"
    launch_error = batch_runtime_error()
    if launch_error:
        return launch_error
    return None


def _start_orch_unlocked():
    proc = process_running()
    if proc.get("orch_running") or proc.get("batch_running"):
        return {"ok": False, "error": "already running", "process": proc}
    if find_managed_processes(ROOT, ("sso_to_auth_json.py",)):
        return {"ok": False, "error": "account recovery is running"}
    prerequisite_error = _runtime_prerequisite_error()
    if prerequisite_error:
        return {"ok": False, "error": prerequisite_error}
    c = load_control()
    now = cpa_count()
    add_count = c.get("add_count")
    try:
        add_count = int(add_count) if add_count is not None else 0
    except Exception:
        add_count = 0
    target = c.get("target_cpa")
    try:
        target = int(target) if target is not None else None
    except Exception:
        target = None
    if add_count > 0:
        c["base_cpa"] = now
        c["target_cpa"] = now + add_count
    elif target is None or target <= now:
        n = int(c.get("batch_count") or 40)
        c["add_count"] = n
        c["base_cpa"] = now
        c["target_cpa"] = now + n
        add_count = n
    c = save_control(c)
    need = int(c.get("target_cpa") or 0) - now
    ensure_private_dir(LOG_DIR)
    stdout_path = LOG_DIR / "orch100-stdout.log"
    fd = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except (OSError, AttributeError):
        pass
    stdout = os.fdopen(fd, "a", encoding="utf-8")
    stdout.write(
        f"\n--- monitor start {time.strftime('%Y-%m-%dT%H:%M:%SZ')} "
        f"workers={c.get('workers')} cpa={now} target={c.get('target_cpa')} need={need} ---\n"
    )
    stdout.flush()
    try:
        p = subprocess.Popen(
            [str(VENV_PY), "-u", str(ORCH_SCRIPT)],
            cwd=str(ROOT),
            stdout=stdout,
            stderr=subprocess.STDOUT,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
            **popen_group_kwargs(),
        )
    finally:
        stdout.close()
    write_pid_file(ORCH_PID, p.pid)
    return {
        "ok": True,
        "pid": p.pid,
        "mode": "orch",
        "workers": c.get("workers"),
        "cpa_now": now,
        "target_cpa": c.get("target_cpa"),
        "need": need,
        "add_count": add_count or c.get("add_count"),
        "control": c,
        "message": f"已启动 orch pid={p.pid} 目标 CPA {c.get('target_cpa')} (再跑 {need})",
    }


def start_orch():
    with START_LOCK:
        return _start_orch_unlocked()



def _start_batch_only_unlocked():
    proc = process_running()
    if proc.get("batch_running") or proc.get("orch_running"):
        return {"ok": False, "error": "already running", "process": proc}
    if find_managed_processes(ROOT, ("sso_to_auth_json.py",)):
        return {"ok": False, "error": "account recovery is running"}
    prerequisite_error = _runtime_prerequisite_error()
    if prerequisite_error:
        return {"ok": False, "error": prerequisite_error}
    c = load_control()
    workers = int(c.get("workers") or 3)
    count = int(c.get("batch_count") or 40)
    now = cpa_count()
    c["base_cpa"] = now
    c["target_cpa"] = now + count
    c = save_control(c)
    logname = LOG_DIR / f"batch-orch-{time.strftime('%Y%m%d-%H%M%S')}-n{count}.log"
    ensure_private_dir(LOG_DIR)
    fd = os.open(logname, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except (OSError, AttributeError):
        pass
    fout = os.fdopen(fd, "w", encoding="utf-8")
    try:
        p = subprocess.Popen(
            batch_launch_command(
                ROOT,
                count,
                workers,
                python_path=VENV_PY,
            ),
            cwd=str(ROOT),
            stdout=fout,
            stderr=subprocess.STDOUT,
            **popen_group_kwargs(),
        )
    finally:
        fout.close()
    write_pid_file(BATCH_PID, p.pid)
    return {
        "ok": True,
        "pid": p.pid,
        "mode": "batch",
        "workers": workers,
        "count": count,
        "log": logname.name,
    }


def start_batch_only():
    with START_LOCK:
        return _start_batch_only_unlocked()


def snapshot():
    log = discover_log()
    parsed = parse_log(log) if log else {"error": "no log"}
    cpa = cpa_count()
    configured_base = read_base()
    base_stale = configured_base < 0 or configured_base > cpa
    base = cpa if base_stale else configured_base
    proc = process_running()
    control = load_control()
    bl = read_blacklist()
    bl_err = blacklist_update_errors()
    try:
        rates = success_stats().get("rates") or {}
    except Exception:
        rates = {}
    target = parsed.get("count_target") or control.get("batch_count") or 40
    ok = parsed.get("ok") or 0
    fail = parsed.get("fail") or 0
    done = ok + fail
    pct = round(100.0 * ok / target, 2) if target else 0
    eta = None
    rate_per_min = None
    etime = proc.get("etime") or proc.get("batch_etime") or ""
    secs = _parse_etime(etime)
    if secs and ok > 0:
        rate_per_min = round(ok / (secs / 60.0), 2)
        remain = max(target - ok, 0)
        if rate_per_min > 0:
            eta_min = remain / rate_per_min
            eta = f"{int(eta_min)}m" if eta_min < 120 else f"{eta_min/60:.1f}h"
    workers_show = parsed.get("workers") or control.get("workers")
    try:
        batch_live = read_batch_state_live()
    except Exception:
        batch_live = {"exists": False}
    return {
        "ts": time.time(),
        "ts_human": time.strftime("%Y-%m-%d %H:%M:%S"),
        "base_cpa": base,
        "base_cpa_stale": base_stale,
        "cpa": cpa,
        "cpa_delta": cpa - base,
        "process": proc,
        "control": control,
        "target": target,
        "done_attempts": done,
        "progress_pct": pct,
        "success_rate": round(100.0 * ok / done, 1) if done else None,
        "rate_per_min": rate_per_min,
        "eta": eta,
        "batch_live": batch_live,
        "blacklist": {
            "count": bl.get("count"),
            "asns": bl.get("asns"),
            "items": bl.get("items"),
            "isp_keywords": bl.get("isp_keywords"),
            "mtime_human": bl.get("mtime_human"),
            "ok": bl.get("ok"),
            "error": bl.get("error"),
            "errors": bl.get("errors"),
        },
        "blacklist_update": bl_err,
        "rates": rates,
        **{k: v for k, v in parsed.items() if k != "tail"},
        "workers": workers_show,
        "tail": (parsed.get("tail") or []) if PANEL_INCLUDE_TAIL else ["(raw log tail disabled; set PANEL_INCLUDE_TAIL=1)"],
    }


HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="theme-color" content="#f3f4f1" id="theme-color"/>
<title>GrokRegister</title>
<script>
  (function () {
    const key = "GROK_REGISTER_THEME";
    let theme = "";
    try { theme = localStorage.getItem(key) || ""; } catch (e) {}
    if (theme !== "light" && theme !== "dark") {
      theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }
    document.documentElement.dataset.theme = theme;
    document.getElementById("theme-color").content = theme === "dark" ? "#171815" : "#f3f4f1";
  })();
</script>
<style>
  @font-face {
    font-family: "Geist";
    src: url("/assets/geist.woff2") format("woff2");
    font-style: normal;
    font-weight: 100 900;
    font-display: swap;
  }
  @font-face {
    font-family: "Geist Mono";
    src: url("/assets/geist-mono.woff2") format("woff2");
    font-style: normal;
    font-weight: 100 900;
    font-display: swap;
  }
  :root {
    color-scheme: light;
    --bg: #f3f4f1;
    --surface: #e9eae6;
    --surface-raised: #f8f9f6;
    --surface-soft: #eff0ec;
    --surface-deep: #d9dad5;
    --border: rgba(21, 22, 19, .16);
    --border-strong: rgba(21, 22, 19, .46);
    --text: #151613;
    --text-secondary: #383a35;
    --muted: #696b64;
    --placeholder: #85877f;
    --ok: #237a57;
    --fail: #b83f3f;
    --warn: #8a6400;
    --accent: #b93b28;
    --accent-hover: #9f2f1f;
    --accent-ink: #f8f9f6;
    --focus: #b93b28;
    --button: #f8f9f6;
    --button-hover: #e1e2dd;
    --hover-border: rgba(21, 22, 19, .46);
    --focus-shadow: rgba(185, 59, 40, .16);
    --primary-bg: #151613;
    --primary-text: #f8f9f6;
    --primary-hover: #2e302b;
    --danger-border: rgba(184, 63, 63, .45);
    --danger-hover-bg: rgba(184, 63, 63, .08);
    --danger-hover-border: rgba(184, 63, 63, .72);
    --header: rgba(243, 244, 241, .88);
    --progress-track: #d9dad5;
    --row-hover: rgba(21, 22, 19, .035);
    --tail-bg: #151613;
    --tail-text: #d3d5ce;
    --grid-line: rgba(21, 22, 19, .055);
  }
  * { box-sizing: border-box; }
  [hidden] { display: none !important; }
  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }
  html {
    background: var(--bg);
    transition: background-color 180ms ease, color 180ms ease;
  }
  body {
    margin: 0;
    min-height: 100dvh;
    background-color: var(--bg);
    background-image:
      linear-gradient(to right, var(--grid-line) 1px, transparent 1px),
      linear-gradient(to bottom, var(--grid-line) 1px, transparent 1px);
    background-size: 40px 40px;
    background-attachment: fixed;
    color: var(--text);
    font-family: "Geist", "Noto Sans CJK SC", "Noto Sans SC", "PingFang SC", "Microsoft YaHei", system-ui, sans-serif;
    font-size: 14px;
    line-height: 1.45;
    letter-spacing: 0;
    transition: background-color 180ms ease, color 180ms ease;
  }
  ::selection { background: var(--accent); color: var(--accent-ink); }
  header {
    position: sticky;
    top: 0;
    z-index: 10;
    border-bottom: 1px solid var(--border);
    background: var(--header);
    backdrop-filter: blur(18px) saturate(118%);
    -webkit-backdrop-filter: blur(18px) saturate(118%);
    transition: background-color 180ms ease, border-color 180ms ease;
  }
  .topbar {
    width: min(calc(100% - 64px), 1480px);
    height: 68px;
    margin: 0 auto;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
  }
  .brand { min-width: 0; }
  h1 {
    margin: 0;
    color: var(--text);
    font-size: 17px;
    line-height: 1.2;
    font-weight: 800;
  }
  h1::after {
    content: "";
    width: 5px;
    height: 5px;
    display: inline-block;
    margin-left: 5px;
    background: var(--accent);
    transition: background-color 180ms ease;
  }
  .page-heading {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 20px;
    margin: 2px 0 20px;
  }
  .page-heading > div { min-width: 0; }
  .page-title { margin: 0; color: var(--text); font-size: 28px; line-height: 1.18; font-weight: 680; }
  .brand-subtitle {
    margin-top: 7px;
    color: var(--muted);
    font-size: 11px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .status-cluster {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 8px;
    flex-wrap: nowrap;
  }
  .badge {
    min-height: 28px;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 4px 10px;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: transparent;
    color: var(--text-secondary);
    font-size: 12px;
    font-weight: 560;
    white-space: nowrap;
  }
  .dot { width: 7px; height: 7px; flex: 0 0 auto; border-radius: 50%; background: var(--muted); }
  .dot.on { background: var(--ok); }
  .dot.done { background: var(--ok); }
  .dot.off { background: var(--muted); }
  main { width: min(calc(100% - 64px), 1480px); margin: 0 auto; padding: 28px 0 48px; }
  .panel-gap { margin-top: 14px; }
  .card {
    min-width: 0;
    background: var(--surface-raised);
    border: 1px solid var(--border);
    border-radius: 0;
    padding: 16px;
    transition: background-color 180ms ease, border-color 180ms ease, color 180ms ease, transform 180ms cubic-bezier(.16, 1, .3, 1);
  }
  @media (hover: hover) {
    .card:hover { border-color: var(--border-strong); transform: translateY(-2px); }
  }
  .panel { margin-top: 14px; }
  .panel.no-margin { margin-top: 0; }
  .panel h2, .card h2 {
    margin: 0;
    color: var(--text);
    font-size: 13px;
    font-weight: 620;
  }
  .ok { color: var(--ok); } .fail { color: var(--fail); } .warn { color: var(--warn); } .accent { color: var(--accent); }
  .section-head {
    min-height: 32px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    margin-bottom: 14px;
  }
  .section-meta { color: var(--muted); font-size: 12px; text-align: right; }
  .control-grid {
    display: grid;
    grid-template-columns: minmax(220px, 1.6fr) minmax(150px, .9fr) repeat(4, minmax(100px, .55fr)) minmax(258px, auto);
    gap: 12px;
    align-items: end;
  }
  .control-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }
  .control-panel { padding: 12px 16px; }
  .control-panel .section-head { min-height: 24px; margin-bottom: 8px; }
  .control-panel .msg:empty { display: none; }
  .field { min-width: 0; display: flex; flex-direction: column; gap: 6px; }
  .field label { color: var(--muted); font-size: 12px; font-weight: 560; }
  input, select, textarea, button { font: inherit; letter-spacing: 0; }
  input, select, textarea {
    width: 100%;
    min-height: 38px;
    border: 1px solid var(--border-strong);
    border-radius: 2px;
    background: var(--surface-soft);
    color: var(--text);
    padding: 8px 10px;
    outline: none;
  }
  textarea { resize: vertical; }
  input::placeholder, textarea::placeholder { color: var(--placeholder); opacity: 1; }
  input:hover, select:hover, textarea:hover { border-color: var(--hover-border); }
  input:focus, select:focus, textarea:focus { border-color: var(--focus); box-shadow: 0 0 0 3px var(--focus-shadow); }
  button {
    min-height: 38px;
    border: 1px solid var(--border-strong);
    border-radius: 2px;
    background: var(--button);
    color: var(--text);
    padding: 8px 14px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: background-color 180ms ease, border-color 180ms ease, color 180ms ease, transform 180ms cubic-bezier(.16, 1, .3, 1);
    white-space: nowrap;
  }
  button:hover { background: var(--button-hover); border-color: var(--hover-border); }
  button:active { transform: translateY(2px); }
  button:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
  button.primary { background: var(--primary-bg); border-color: var(--primary-bg); color: var(--primary-text); }
  button.primary:hover { background: var(--primary-hover); border-color: var(--primary-hover); }
  button.danger { background: transparent; border-color: var(--danger-border); color: var(--fail); }
  button.danger:hover { background: var(--danger-hover-bg); border-color: var(--danger-hover-border); }
  button:disabled { opacity: .42; cursor: not-allowed; transform: none; }
  button.view-switch {
    min-width: 68px;
    min-height: 30px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0 9px;
    border-color: var(--border);
    background: var(--surface-soft);
    color: var(--text-secondary);
    font-size: 11px;
    font-weight: 620;
    line-height: 1;
  }
  button.view-switch:hover { border-color: var(--hover-border); color: var(--text); }
  button.view-switch[data-active="true"] {
    border-color: var(--accent);
    background: var(--accent);
    color: var(--accent-ink);
  }
  .theme-switch {
    flex: 0 0 auto;
    display: inline-flex;
    align-items: center;
    gap: 2px;
    padding: 2px;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: var(--surface-soft);
  }
  button.theme-option {
    min-height: 24px;
    padding: 3px 8px;
    border: 0;
    border-radius: 1px;
    background: transparent;
    color: var(--muted);
    font-size: 11px;
    font-weight: 560;
    line-height: 1;
  }
  button.theme-option:hover { border: 0; background: var(--button-hover); color: var(--text); }
  button.theme-option[aria-pressed="true"] { background: var(--accent); color: var(--accent-ink); }
  .metric-grid {
    display: grid;
    grid-template-columns: repeat(6, minmax(0, 1fr));
    gap: 1px;
    overflow: hidden;
    border: 1px solid var(--border);
    border-radius: 0;
    background: var(--border);
  }
  #kpis { margin-top: 10px; }
  .metric {
    min-width: 0;
    padding: 10px 14px;
    background: var(--surface);
    transition: background-color 180ms ease, color 180ms ease;
  }
  .metric:hover { background: var(--surface-raised); }
  .metric .label { color: var(--muted); font-size: 11px; }
  .metric .value {
    margin-top: 4px;
    font-size: 23px;
    line-height: 1.05;
    font-weight: 730;
    font-variant-numeric: tabular-nums;
    overflow-wrap: anywhere;
  }
  .metric .sub { min-height: 16px; margin-top: 4px; color: var(--muted); font-size: 11px; }
  .rate-panel { margin-top: 10px; padding: 12px 16px 14px; }
  .rate-panel .section-head { min-height: 24px; margin-bottom: 8px; }
  .rate-panel .section-meta { font-size: 11px; }
  .rate-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    border: 1px solid var(--border);
    border-radius: 0;
    overflow: hidden;
  }
  .batch-live-grid {
    display: grid;
    grid-template-columns: repeat(6, minmax(0, 1fr));
    gap: 1px;
    overflow: hidden;
    border: 1px solid var(--border);
    border-radius: 0;
    background: var(--border);
    margin-bottom: 10px;
  }
  #batch-live-panel { margin-top: 10px; padding: 12px 16px 14px; }
  #batch-live-panel .section-head { min-height: 24px; margin-bottom: 8px; }
  #batch-live-panel .section-meta { font-size: 11px; }
  .rate-item { min-width: 0; padding: 10px 12px; background: var(--surface-soft); transition: background-color 180ms ease; }
  .rate-item + .rate-item { border-left: 1px solid var(--border); }
  .rate-top { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; }
  .rate-label { color: var(--text-secondary); font-size: 12px; }
  .rate-total { color: var(--muted); font-size: 11px; white-space: nowrap; }
  .rate-value { margin-top: 4px; font-size: 23px; line-height: 1; font-weight: 730; font-variant-numeric: tabular-nums; }
  .rate-breakdown { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 6px; color: var(--muted); font-size: 11px; }
  .progress-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; margin-bottom: 10px; }
  .bar-wrap { height: 8px; overflow: hidden; border-radius: 1px; background: var(--progress-track); }
  .bar { height: 100%; width: 0%; background: var(--accent); transition: width 420ms cubic-bezier(.16, 1, .3, 1), background-color 180ms ease; }
  .progress-sub { margin-top: 9px; color: var(--muted); font-size: 12px; }
  .two { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 14px; }
  .three { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.15fr) minmax(0, .95fr); gap: 14px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 9px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--muted); font-weight: 620; font-size: 11px; }
  td { color: var(--text-secondary); }
  tbody tr:last-child td { border-bottom: 0; }
  tr:hover td { background: var(--row-hover); }
  .table-scroll { width: 100%; overflow: auto; }
  .mono { font-family: "Geist Mono", "SFMono-Regular", Consolas, monospace; font-size: 12px; }
  .tail {
    max-height: 360px;
    overflow: auto;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: var(--tail-bg);
    padding: 12px;
    color: var(--tail-text);
    font-size: 11.5px;
    line-height: 1.55;
    white-space: pre-wrap;
    word-break: break-word;
  }
  .chips { display: flex; flex-wrap: wrap; gap: 7px; }
  .card > h2 + .chips { margin-top: 14px; }
  .chip {
    min-width: 84px;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: var(--surface-soft);
    padding: 8px 9px;
  }
  .chip b { display: block; margin-top: 2px; font-size: 17px; font-variant-numeric: tabular-nums; }
  .chip span { color: var(--muted); font-size: 11px; }
  .bl-list {
    max-height: 260px;
    overflow: auto;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: var(--surface-soft);
  }
  .bl-list table { font-size: 12px; }
  .msg { font-size: 12px; color: var(--muted); min-height: 18px; margin-top: 8px; }
  .msg.err { color: var(--fail); } .msg.ok { color: var(--ok); }
  .button-group { display: flex; align-items: center; justify-content: flex-end; gap: 7px; flex-wrap: wrap; }
  .recovery-layout { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
  .recovery-layout .chips { flex: 1 1 auto; }
  .recovery-actions { flex: 0 0 auto; }
  body.proxy-view-open { overflow: hidden; }
  body.proxy-view-open #dashboard-view > :not(#proxy-view) { display: none; }
  .proxy-view {
    position: fixed;
    inset: 68px 0 0;
    z-index: 8;
    overflow-y: auto;
    overscroll-behavior: contain;
    background-color: var(--bg);
    background-image:
      linear-gradient(to right, var(--grid-line) 1px, transparent 1px),
      linear-gradient(to bottom, var(--grid-line) 1px, transparent 1px);
    background-size: 40px 40px;
  }
  .proxy-view[hidden] { display: none; }
  .proxy-view-inner {
    width: min(calc(100% - 64px), 1280px);
    margin: 0 auto;
    padding: 28px 0 48px;
  }
  .proxy-view-heading {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 20px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
  }
  .proxy-view-subtitle { margin: 7px 0 0; color: var(--muted); font-size: 12px; }
  .proxy-summary {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    overflow: hidden;
    border: 1px solid var(--border);
    background: var(--border);
    gap: 1px;
  }
  .proxy-summary-item { min-width: 0; padding: 12px 14px; background: var(--surface); }
  .proxy-summary-label { color: var(--muted); font-size: 11px; }
  .proxy-summary-value { margin-top: 4px; font-family: "Geist Mono", monospace; font-size: 22px; line-height: 1; font-weight: 720; }
  .proxy-import {
    display: grid;
    grid-template-columns: minmax(0, 1.5fr) minmax(260px, .5fr);
    gap: 16px;
    align-items: stretch;
    margin-top: 14px;
    padding: 16px 0;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
  }
  #proxy-input {
    min-height: 126px;
    font-family: "Geist Mono", monospace;
    font-size: 12px;
    line-height: 1.55;
  }
  .proxy-import-actions { display: flex; flex-direction: column; justify-content: space-between; gap: 12px; }
  .proxy-import-actions .button-group { justify-content: flex-start; }
  .proxy-format { margin: 0; color: var(--muted); font-size: 11px; line-height: 1.6; }
  .proxy-list-section { margin-top: 18px; }
  .proxy-list-head { display: flex; align-items: center; justify-content: space-between; gap: 14px; margin-bottom: 10px; }
  .proxy-list-head h2 { margin: 0; font-size: 13px; }
  .proxy-table-wrap { overflow: auto; border: 1px solid var(--border); background: var(--surface-raised); }
  .proxy-table { min-width: 990px; table-layout: fixed; }
  .proxy-table th:nth-child(1) { width: 82px; }
  .proxy-table th:nth-child(2) { width: 260px; }
  .proxy-table th:nth-child(3) { width: 150px; }
  .proxy-table th:nth-child(4) { width: 86px; }
  .proxy-table th:nth-child(5) { width: 180px; }
  .proxy-table th:nth-child(6) { width: 96px; }
  .proxy-table th:nth-child(7) { width: 190px; }
  .proxy-endpoint { overflow-wrap: anywhere; }
  .proxy-meta { margin-top: 3px; color: var(--muted); font-size: 10px; }
  .proxy-state {
    min-height: 24px;
    display: inline-flex;
    align-items: center;
    padding: 3px 7px;
    border: 1px solid var(--border);
    border-radius: 2px;
    color: var(--text-secondary);
    font-size: 11px;
    white-space: nowrap;
  }
  .proxy-state.healthy { border-color: color-mix(in srgb, var(--ok) 55%, var(--border)); color: var(--ok); }
  .proxy-state.unhealthy { border-color: color-mix(in srgb, var(--fail) 55%, var(--border)); color: var(--fail); }
  .proxy-state.cooldown { border-color: color-mix(in srgb, var(--warn) 55%, var(--border)); color: var(--warn); }
  .proxy-state.testing { border-color: color-mix(in srgb, var(--accent) 55%, var(--border)); color: var(--accent); }
  .proxy-actions { display: flex; align-items: center; gap: 6px; }
  .proxy-actions button { min-height: 30px; padding: 5px 9px; font-size: 11px; }
  .proxy-toggle { width: 16px; height: 16px; min-height: 0; accent-color: var(--accent); }
  .proxy-empty { padding: 38px 18px !important; color: var(--muted); text-align: center; }
  .proxy-job { color: var(--muted); font-size: 11px; }
  body.domain-view-open { overflow: hidden; }
  body.domain-view-open #dashboard-view > :not(#domain-view) { display: none; }
  .domain-view {
    position: fixed;
    inset: 68px 0 0;
    z-index: 8;
    overflow-y: auto;
    overscroll-behavior: contain;
    background-color: var(--bg);
    background-image:
      linear-gradient(to right, var(--grid-line) 1px, transparent 1px),
      linear-gradient(to bottom, var(--grid-line) 1px, transparent 1px);
    background-size: 40px 40px;
  }
  .domain-view[hidden] { display: none; }
  .domain-view-inner {
    width: min(calc(100% - 64px), 1280px);
    margin: 0 auto;
    padding: 28px 0 48px;
  }
  .domain-view-heading {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 20px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
  }
  .domain-view-subtitle { margin: 7px 0 0; color: var(--muted); font-size: 12px; }
  .mail-source-kicker {
    margin-bottom: 5px;
    color: var(--accent);
    font-size: 10px;
    font-weight: 760;
    text-transform: uppercase;
  }
  .mail-provider-panel {
    padding: 18px;
    border: 1px solid var(--border-strong);
    background: var(--surface-raised);
  }
  .mail-provider-toolbar {
    display: grid;
    grid-template-columns: minmax(280px, 1fr) auto;
    align-items: end;
    gap: 18px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
  }
  .mail-provider-toolbar .field { max-width: 520px; }
  .mail-provider-status { display: flex; align-items: center; gap: 8px; min-height: 38px; }
  .mail-provider-status-label { color: var(--muted); font-size: 11px; }
  .mail-provider-fields {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 14px 16px;
    padding: 18px 0;
  }
  .mail-provider-fields .field { min-width: 0; gap: 5px; }
  .mail-provider-fields input,
  .mail-provider-fields select { width: 100%; min-height: 40px; }
  .mail-secret-wrap { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 6px; }
  .mail-secret-wrap button { min-width: 54px; min-height: 40px; padding-inline: 10px; font-size: 11px; }
  .mail-secret-wrap.pending-clear input { border-color: var(--warn); }
  .mail-secret-note { min-height: 14px; color: var(--muted); font-size: 10px; }
  .mail-secret-note.warn { color: var(--warn); }
  .mail-provider-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    padding-top: 14px;
    border-top: 1px solid var(--border);
  }
  .mail-provider-actions .mail-provider-meta { margin-left: auto; color: var(--muted); font-size: 11px; }
  .mail-provider-result { min-height: 18px; margin-top: 10px; }
  .domain-advanced { margin-top: 20px; border-top: 1px solid var(--border-strong); border-bottom: 1px solid var(--border-strong); }
  .domain-advanced > summary {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    min-height: 52px;
    padding: 10px 2px;
    color: var(--text);
    cursor: pointer;
    list-style: none;
  }
  .domain-advanced > summary::-webkit-details-marker { display: none; }
  .domain-advanced > summary::after { content: "+"; color: var(--accent); font-family: "Geist Mono", monospace; font-size: 18px; }
  .domain-advanced[open] > summary::after { content: "-"; }
  .domain-advanced-title { font-size: 13px; font-weight: 680; }
  .domain-advanced-meta { color: var(--muted); font-size: 11px; font-weight: 450; }
  .domain-advanced-body { padding: 4px 0 24px; }
  .domain-advanced-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 12px; }
  .domain-summary {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    overflow: hidden;
    border: 1px solid var(--border);
    background: var(--border);
    gap: 1px;
  }
  .domain-summary-item { min-width: 0; padding: 12px 14px; background: var(--surface); }
  .domain-summary-label { color: var(--muted); font-size: 11px; }
  .domain-summary-value { margin-top: 4px; font-family: "Geist Mono", monospace; font-size: 22px; line-height: 1; font-weight: 720; }
  .domain-import {
    display: grid;
    grid-template-columns: minmax(0, 1.25fr) minmax(300px, .75fr);
    gap: 16px;
    align-items: stretch;
    margin-top: 14px;
    padding: 16px 0;
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
  }
  #domain-input {
    min-height: 126px;
    font-family: "Geist Mono", monospace;
    font-size: 12px;
    line-height: 1.55;
  }
  .domain-import-actions { display: flex; flex-direction: column; justify-content: space-between; gap: 12px; }
  .domain-import-actions .button-group { justify-content: flex-start; }
  .domain-format { margin: 0; color: var(--muted); font-size: 11px; line-height: 1.6; }
  .domain-settings { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
  .domain-settings .field { gap: 4px; }
  .domain-settings input, .domain-settings select { min-height: 34px; }
  .domain-list-section { margin-top: 18px; }
  .domain-list-head { display: flex; align-items: center; justify-content: space-between; gap: 14px; margin-bottom: 10px; }
  .domain-list-head h2 { margin: 0; font-size: 13px; }
  .domain-table-wrap { overflow: auto; border: 1px solid var(--border); background: var(--surface-raised); }
  .domain-table { min-width: 960px; table-layout: fixed; }
  .domain-table th:nth-child(1) { width: 92px; }
  .domain-table th:nth-child(2) { width: 230px; }
  .domain-table th:nth-child(3) { width: 130px; }
  .domain-table th:nth-child(4) { width: 150px; }
  .domain-table th:nth-child(5) { width: 220px; }
  .domain-table th:nth-child(6) { width: 72px; }
  .domain-table th:nth-child(7) { width: 170px; }
  .domain-name { overflow-wrap: anywhere; }
  .domain-meta { margin-top: 3px; color: var(--muted); font-size: 10px; }
  .domain-state {
    min-height: 24px;
    display: inline-flex;
    align-items: center;
    padding: 3px 7px;
    border: 1px solid var(--border);
    border-radius: 2px;
    color: var(--text-secondary);
    font-size: 11px;
    white-space: nowrap;
  }
  .domain-state.active { border-color: color-mix(in srgb, var(--ok) 55%, var(--border)); color: var(--ok); }
  .domain-state.standby { border-color: color-mix(in srgb, var(--accent) 55%, var(--border)); color: var(--accent); }
  .domain-state.blocked { border-color: color-mix(in srgb, var(--fail) 55%, var(--border)); color: var(--fail); }
  .domain-state.disabled { border-color: var(--border); color: var(--muted); }
  .domain-actions { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
  .domain-actions button { min-height: 30px; padding: 5px 9px; font-size: 11px; }
  .domain-toggle { width: 16px; height: 16px; min-height: 0; accent-color: var(--accent); }
  .domain-empty { padding: 38px 18px !important; color: var(--muted); text-align: center; }
  .domain-job { color: var(--muted); font-size: 11px; }
  body.help-view-open { overflow: hidden; }
  body.help-view-open #dashboard-view > :not(#help-view) { display: none; }
  .help-view {
    position: fixed;
    inset: 68px 0 0;
    z-index: 8;
    overflow-y: auto;
    overscroll-behavior: contain;
    background-color: var(--bg);
    background-image:
      linear-gradient(to right, var(--grid-line) 1px, transparent 1px),
      linear-gradient(to bottom, var(--grid-line) 1px, transparent 1px);
    background-size: 40px 40px;
  }
  .help-view[hidden] { display: none; }
  .help-view-inner {
    width: min(calc(100% - 64px), 1120px);
    margin: 0 auto;
    padding: 28px 0 48px;
  }
  .help-view-heading {
    margin-bottom: 20px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
  }
  .help-view-subtitle {
    margin: 7px 0 0;
    color: var(--muted);
    font-size: 12px;
  }
  .help-body { min-width: 0; }
  .help-toolbar {
    min-height: 42px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 16px;
  }
  .help-tabs {
    display: inline-flex;
    gap: 2px;
    padding: 2px;
    border: 1px solid var(--border);
    border-radius: 2px;
    background: var(--surface-soft);
  }
  button.help-tab {
    min-height: 28px;
    padding: 5px 10px;
    border: 0;
    border-radius: 1px;
    background: transparent;
    color: var(--muted);
    font-size: 12px;
  }
  button.help-tab:hover { border: 0; color: var(--text); }
  button.help-tab[aria-selected="true"] { background: var(--accent); color: var(--accent-ink); }
  .help-guide-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 1px;
    border: 1px solid var(--border);
    background: var(--border);
  }
  .help-guide-item { min-width: 0; min-height: 132px; padding: 14px; background: var(--surface-soft); }
  .help-guide-item h3 { margin: 0; color: var(--text); font-size: 13px; font-weight: 650; }
  .help-guide-item p { margin: 9px 0 0; color: var(--text-secondary); font-size: 12px; line-height: 1.65; }
  .help-guide-item code, .faq-answer code {
    color: var(--accent);
    font-family: "Geist Mono", monospace;
    font-size: .94em;
    overflow-wrap: anywhere;
  }
  .help-note {
    margin: 14px 0 0;
    padding-top: 12px;
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 11px;
    line-height: 1.6;
  }
  .faq-tools {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 4px;
  }
  #faq-search { min-height: 36px; max-width: 360px; }
  .faq-count { flex: 0 0 auto; color: var(--muted); font-size: 11px; }
  .faq-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); column-gap: 24px; }
  .faq-item { min-width: 0; border-top: 1px solid var(--border); }
  .faq-item summary {
    padding: 13px 2px;
    color: var(--text);
    font-size: 12px;
    font-weight: 620;
    line-height: 1.45;
    cursor: pointer;
  }
  .faq-item summary::marker { color: var(--accent); }
  .faq-item[open] summary { color: var(--accent); }
  .faq-answer { padding: 0 18px 14px; color: var(--text-secondary); font-size: 12px; line-height: 1.65; }
  .faq-empty { margin: 16px 0 2px; color: var(--muted); font-size: 12px; }
  footer { margin-top: 16px; color: var(--muted); font-size: 11px; overflow-wrap: anywhere; }
  main > :not(.help-view) {
    animation: panel-enter 520ms cubic-bezier(.16, 1, .3, 1) both;
  }
  main > :nth-child(2) { animation-delay: 45ms; }
  main > :nth-child(3) { animation-delay: 90ms; }
  main > :nth-child(4) { animation-delay: 135ms; }
  main > :nth-child(5) { animation-delay: 180ms; }
  main > :nth-child(6) { animation-delay: 225ms; }
  main > :nth-child(7) { animation-delay: 270ms; }
  main > :nth-child(8) { animation-delay: 315ms; }
  main > :nth-child(9) { animation-delay: 360ms; }
  main > :nth-child(n + 10) { animation-delay: 405ms; }
  @keyframes panel-enter {
    from { opacity: 0; transform: translateY(12px); }
    to { opacity: 1; transform: translateY(0); }
  }
  @media (min-width: 1121px) {
    .control-panel .control-grid { gap: 10px; }
    .control-panel .field { gap: 4px; }
    .control-panel .field label { font-size: 11px; }
    .control-panel .control-actions { gap: 6px; }
    .control-panel input,
    .control-panel select,
    .control-panel .control-actions button {
      min-height: 34px;
      padding-block: 6px;
    }
  }
  @media (max-width: 1120px) {
    .control-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .field-token { grid-column: span 2; }
    .control-actions { grid-column: 1 / -1; padding-top: 14px; border-top: 1px solid var(--border); }
    .metric-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .three { grid-template-columns: minmax(0, 1fr); }
    .help-guide-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .mail-provider-fields { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  }
  @media (max-width: 760px) {
    .topbar { width: calc(100% - 32px); height: 60px; align-items: center; flex-direction: row; gap: 10px; }
    .brand { width: auto; }
    .status-cluster { width: auto; justify-content: flex-end; margin-left: auto; }
    #clock, #sync-label { display: none; }
    main { width: calc(100% - 24px); padding: 20px 0 34px; }
    .page-heading { margin-bottom: 16px; }
    .page-title { font-size: 22px; }
    .card { padding: 14px; }
    .control-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .field-token, .field-mode { grid-column: 1 / -1; }
    .control-actions { justify-content: stretch; }
    .control-actions button { flex: 1 1 0; padding-inline: 8px; }
    .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .metric { padding: 14px; }
    .metric .value { font-size: 23px; }
    .rate-grid, .two { grid-template-columns: minmax(0, 1fr); }
    .rate-item + .rate-item { border-left: 0; border-top: 1px solid var(--border); }
    .section-head { align-items: flex-start; }
    .section-meta { max-width: 48%; }
    .help-view { inset-block-start: 60px; }
    .help-view-inner { width: calc(100% - 24px); padding: 20px 0 34px; }
    .help-view-heading { margin-bottom: 16px; padding-bottom: 16px; }
    .help-toolbar, .faq-tools { align-items: stretch; flex-direction: column; }
    .help-toolbar { min-height: 0; }
    .help-tabs { width: 100%; }
    button.help-tab { flex: 1 1 0; }
    .help-guide-grid, .faq-grid { grid-template-columns: 1fr; }
    #faq-search { max-width: none; }
    .recovery-layout { align-items: stretch; flex-direction: column; }
    .recovery-actions { justify-content: stretch; }
    .recovery-actions button { flex: 1 1 0; }
    .proxy-view { inset-block-start: 60px; }
    .proxy-view-inner { width: calc(100% - 24px); padding: 20px 0 34px; }
    .proxy-view-heading { align-items: flex-start; flex-direction: column; margin-bottom: 16px; padding-bottom: 16px; }
    .proxy-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .proxy-summary-item:last-child { grid-column: 1 / -1; }
    .proxy-import { grid-template-columns: minmax(0, 1fr); }
    .proxy-import-actions .button-group { justify-content: stretch; }
    .proxy-import-actions button { flex: 1 1 auto; }
    .proxy-list-head { align-items: flex-start; flex-direction: column; }
    .domain-view { inset-block-start: 60px; }
    .domain-view-inner { width: calc(100% - 24px); padding: 20px 0 34px; }
    .domain-view-heading { align-items: flex-start; flex-direction: column; margin-bottom: 16px; padding-bottom: 16px; }
    .mail-provider-panel { padding: 14px; }
    .mail-provider-toolbar { grid-template-columns: minmax(0, 1fr); gap: 10px; }
<html lang="id-ID">
    .mail-provider-fields { grid-template-columns: minmax(0, 1fr); }
<meta name="theme-color" content="#f3f4f1" id="theme-color"/>
<title>GrokRegister</title>
    .mail-provider-actions .mail-provider-meta { width: 100%; margin-left: 0; }
    .domain-advanced-head { align-items: flex-start; flex-direction: column; }
    .domain-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .domain-summary-item:last-child { grid-column: 1 / -1; }
    .domain-import { grid-template-columns: minmax(0, 1fr); }
    .domain-settings { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .domain-import-actions .button-group { justify-content: stretch; }
    .domain-import-actions button { flex: 1 1 auto; }
    .domain-list-head { align-items: flex-start; flex-direction: column; }
  }
  @media (max-width: 420px) {
    .topbar { gap: 6px; }
    .brand { flex: 0 0 auto; }
    h1 { font-size: 0; }
    h1::before { content: "GR"; font-size: 15px; }
    .status-cluster { min-width: 0; gap: 4px; }
    .badge { font-size: 11px; }
    .run-status { width: 30px; min-width: 30px; justify-content: center; padding-inline: 0; }
    #run-label { display: none; }
    .card { padding: 13px; }
    .control-actions { flex-wrap: wrap; }
    .control-actions button { flex-basis: calc(50% - 4px); }
    .control-actions button:last-child { flex-basis: 100%; }
    .metric .sub { font-size: 11px; }
    .button-group { justify-content: flex-start; }
    #run-status { display: none; }
    button.view-switch { min-width: 0; padding-inline: 6px; }
    #domain-view-label, #proxy-view-label, #help-view-label { font-size: 0; }
  #domain-view-label::after { content: "Email"; font-size: 11px; }
  #proxy-view-label::after { content: "Proxy"; font-size: 11px; }
  #help-view-label::after { content: "Bantuan"; font-size: 11px; }
    #domain-view-toggle[data-active="true"] #domain-view-label::after,
    #proxy-view-toggle[data-active="true"] #proxy-view-label::after,
  #help-view-toggle[data-active="true"] #help-view-label::after { content: "Kembali"; }
    button.theme-option { padding-inline: 6px; }
    .domain-settings { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .domain-settings .field:first-child { grid-column: 1 / -1; }
  }
  @media (max-width: 340px) {
    .run-status { display: none; }
  }
  html[data-theme="dark"] {
      color-scheme: dark;
      --bg: #171815;
      --surface: #20211e;
      --surface-raised: #242622;
      --surface-soft: #1d1e1b;
      --surface-deep: #30322d;
      --border: rgba(240, 241, 237, .16);
      --border-strong: rgba(240, 241, 237, .42);
      --text: #f0f1ed;
      --text-secondary: #d3d5ce;
      --muted: #a5a79f;
      --placeholder: #777971;
      --ok: #69c493;
      --fail: #f27c71;
      --warn: #d7ae58;
      --accent: #f06449;
      --accent-hover: #ff7a60;
      --accent-ink: #171815;
      --focus: #f06449;
      --button: #242622;
      --button-hover: #30322d;
      --hover-border: rgba(240, 241, 237, .42);
      --focus-shadow: rgba(240, 100, 73, .18);
      --primary-bg: #f0f1ed;
      --primary-text: #171815;
      --primary-hover: #d3d5ce;
      --danger-border: rgba(242, 124, 113, .48);
      --danger-hover-bg: rgba(242, 124, 113, .09);
      --danger-hover-border: rgba(242, 124, 113, .75);
      --header: rgba(23, 24, 21, .88);
      --progress-track: #30322d;
      --row-hover: rgba(240, 241, 237, .035);
      --tail-bg: #11120f;
      --tail-text: #d3d5ce;
      --grid-line: rgba(240, 241, 237, .045);
  }
  @media (prefers-reduced-motion: reduce) {
    html { scroll-behavior: auto; }
    *, *::before, *::after {
      animation-duration: .01ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: .01ms !important;
    }
    .card:hover { transform: none; }
  }
</style>
</head>
<body>
<header>
  <div class="topbar">
    <div class="brand">
      <h1>GrokRegister</h1>
    </div>
    <div class="status-cluster">
    <button type="button" class="view-switch" id="domain-view-toggle" aria-label="Buka Layanan Email" title="Layanan Email" aria-controls="domain-view" onclick="toggleDomainView()">
      <span id="domain-view-label" aria-hidden="true">Email</span>
    </button>
    <button type="button" class="view-switch" id="proxy-view-toggle" aria-label="Buka Proxy Pool" title="Proxy Pool" aria-controls="proxy-view" onclick="toggleProxyView()">
      <span id="proxy-view-label" aria-hidden="true">Proxy</span>
    </button>
    <button type="button" class="view-switch" id="help-view-toggle" aria-label="Buka Bantuan" title="Bantuan" aria-controls="help-view" onclick="toggleHelpView()">
      <span id="help-view-label" aria-hidden="true">Bantuan</span>
    </button>
    <div class="theme-switch" role="group" aria-label="Tema Tampilan">
      <button type="button" class="theme-option" data-theme-choice="light" aria-pressed="false" onclick="setTheme('light')">Terang</button>
      <button type="button" class="theme-option" data-theme-choice="dark" aria-pressed="false" onclick="setTheme('dark')">Gelap</button>
      </div>
  <span class="badge run-status" id="run-status" aria-label="Status tugas: memuat" aria-live="polite" aria-atomic="true"><span class="dot"></span><span id="run-label">Memuat...</span></span>
      <span class="badge mono" id="clock">--</span>
  <span class="badge" id="sync-label">Update Real-time</span>
    </div>
  </div>
</header>
<main id="dashboard-view" aria-label="Konsol Registrasi">
  <div class="page-heading">
    <div>
  <div class="page-title">Konsol Registrasi</div>
      <div class="brand-subtitle mono" id="logname">--</div>
    </div>
  </div>
  <section class="card control-panel">
    <div class="section-head">
      <h2>Kontrol Task</h2>
      <span class="section-meta mono" id="ctrl-status"></span>
    </div>
    <div class="control-grid">
      <div class="field field-token">
      <label for="monitor-token">Token Akses</label>
        <input id="monitor-token" type="password" autocomplete="off" placeholder="MONITOR_TOKEN" onchange="getToken(); refresh(); refreshRecovery(); refreshProxies(); refreshEmailProvider(); refreshEmailDomains()" onblur="getToken()"/>
      </div>
      <div class="field field-mode">
      <label for="mode">Mode Run</label>
        <select id="mode">
      <option value="orch">Orkestrasi Kontinu</option>
      <option value="batch">Batch Tunggal</option>
        </select>
      </div>
      <div class="field"><label for="workers-input">Jumlah Worker</label>
        <input type="number" id="workers-input" min="1" max="24" value="3"/>
      </div>
      <div class="field"><label for="batch_count">Jumlah per Batch</label>
        <input type="number" id="batch_count" min="1" max="200" value="40"/>
      </div>
      <div class="field"><label for="add_count">Target Tambahan</label>
        <input type="number" id="add_count" min="1" max="500" value="40" title="Setiap start, registrasi N akun lagi dari CPA saat ini"/>
      </div>
      <div class="field"><label for="risk_pause">Threshold Risk</label>
        <input type="number" id="risk_pause" min="1" max="50" value="10"/>
      </div>
      <div class="control-actions">
    <button class="primary" id="btn-start" onclick="doStart()">Mulai Task</button>
    <button class="danger" id="btn-stop" onclick="doStop()">Hentikan Task</button>
    <button onclick="saveCtrl()">Simpan Pengaturan</button>
      </div>
    </div>
    <div class="msg" id="ctrl-msg" role="status" aria-live="polite"></div>
  </section>

  <section class="help-view" id="help-view" aria-labelledby="help-view-title" hidden>
    <div class="help-view-inner">
      <div class="help-view-heading">
      <div class="page-title" id="help-view-title">Bantuan Penggunaan</div>
      <p class="help-view-subtitle">Cara menjalankan & troubleshooting</p>
      </div>
      <div class="help-body" id="help-body">
      <div class="help-toolbar">
      <div class="help-tabs" role="tablist" aria-label="Konten bantuan" onkeydown="handleHelpTabKey(event)">
        <button type="button" class="help-tab" id="help-tab-guide" role="tab" aria-selected="true" aria-controls="help-guide" data-help-tab="guide" onclick="setHelpTab('guide')">Panduan</button>
        <button type="button" class="help-tab" id="help-tab-faq" role="tab" aria-selected="false" aria-controls="help-faq" data-help-tab="faq" onclick="setHelpTab('faq')">FAQ</button>
        </div>
      </div>

      <div id="help-guide" role="tabpanel" aria-labelledby="help-tab-guide">
        <div class="help-guide-grid">
          <div class="help-guide-item">
          <h3>Siapkan Environment</h3>
          <p>Pastikan engine Camoufox terinstall, layanan email tersedia, direktori CPA auth bisa ditulis. Kalau direct connect bisa, proxy tidak perlu.</p>
          </div>
          <div class="help-guide-item">
          <h3>Pilih Mode</h3>
          <p><code>Orkestrasi Kontinu</code> jalan beberapa ronde sesuai target tambahan; <code>Batch Tunggal</code> hanya jalan satu batch. Pertama kali saran pakai 2-3 worker.</p>
          </div>
          <div class="help-guide-item">
          <h3>Simpan & Jalankan</h3>
          <p>Masukkan token panel, simpan dulu baru jalankan. Target tambahan = berapa akun lagi ditambah dari CPA yang ada.</p>
          </div>
          <div class="help-guide-item">
          <h3>Pantau Hasil</h3>
          <p>Prioritaskan lihat risk registrasi, success rate per periode, dan log terakhir. Kalau risk terus, ganti exit IP atau domain email dulu, jangan naikkan worker.</p>
          </div>
        </div>
          <p class="help-note">Hentikan task akan mengakhiri orkestrasi dan proses batch. Reset blacklist mengembalikan aturan baseline, bukan menghapus semua penilaian risk.</p>
      </div>

      <div id="help-faq" role="tabpanel" aria-labelledby="help-tab-faq" hidden>
        <div class="faq-tools">
      <label class="sr-only" for="faq-search">Cari pertanyaan umum</label>
      <input id="faq-search" type="search" placeholder="Cari kode error atau gejala" autocomplete="off" oninput="filterFaq(this.value)"/>
      <span class="faq-count mono" id="faq-count">12 item</span>
        </div>
        <div class="faq-grid" id="faq-grid">
      <details class="faq-item" data-faq-item data-search="token token unauthorized 401 simpan pengaturan mulai">
        <summary>Token akses tidak cocok atau 401</summary>
        <div class="faq-answer">Masukkan ulang token panel dan simpan. Token hanya disimpan di localStorage browser ini; ganti port, perangkat, atau browser perlu input ulang.</div>
          </details>
      <details class="faq-item" data-faq-item data-search="mulai langsung selesai target cpa add_count target tambahan">
        <summary>Klik start langsung selesai</summary>
        <div class="faq-answer">Biasanya CPA sudah capai target lama. Naikkan "Target Tambahan" lalu start lagi; Orkestrasi Kontinu menambah N dari CPA saat ini, Batch Tunggal hanya jalan "Jumlah per Batch".</div>
          </details>
      <details class="faq-item" data-faq-item data-search="risk policy deny registration risk botFlagSource ip email domain">
        <summary>Muncul policy=deny atau risk registrasi</summary>
        <div class="faq-answer">Akun ini ditolak risk registrasi; jangan ulangi SSO yang sama. Ganti exit IP yang lebih baik dan beri waktu cooldown, pakai subdomain email yang stabil, worker 2-3 dulu.</div>
          </details>
      <details class="faq-item" data-faq-item data-search="stuck browser gagal start turnstile halaman profil kosong worker camoufox">
        <summary>Registrasi stuck di captcha, halaman profil, atau start browser</summary>
        <div class="faq-answer">Cek dulu kategori gagal dan log terakhir untuk tahu tahap mana. Kalau browser gagal start terus, turunkan worker dan cek apakah sudah jalan <code>camoufox fetch</code>; gagal di halaman profil bisa jadi Turnstile tidak lolos.</div>
          </details>
      <details class="faq-item" data-faq-item data-search="cpa tidak bertambah invalid_grant access denied 503 auth unavailable oauth inject target">
        <summary>CPA tidak bertambah, atau muncul invalid_grant / 503</summary>
        <div class="faq-answer">Cek dulu <code>cpa_auto_add</code>, direktori auth, alamat CPA remote, dan key admin. <code>invalid_grant Access denied</code> artinya refresh token tidak valid atau sesi dicabut.</div>
          </details>
          <details class="faq-item" data-faq-item data-search="permission denied access chat endpoint referrer grok build base_url oauth">
        <summary>Panggil model muncul permission-denied</summary>
        <div class="faq-answer">Penyebab umum: token tidak punya <code>referrer=grok-build</code>, atau <code>base_url</code> mengarah ke <code>api.x.ai</code>.</div>
          </details>
      <details class="faq-item" data-faq-item data-search="exit ip proxy resolve trafik residential chain dialer">
        <summary>Tidak bisa resolve exit IP, atau konsumsi trafik proxy tinggi</summary>
        <div class="faq-answer">Test dulu port proxy satu-satu. Residential proxy mungkin hitung trafik upload+download, jadi per GB tidak pasti; turunkan worker dan hindari retry gagal berulang. Chain proxy harus diset di client proxy.</div>
          </details>
      <details class="faq-item" data-faq-item data-search="email api 401 timeout cloudflare workers key auth_mode proxy">
        <summary>API email return 401 atau timeout</summary>
        <div class="faq-answer">401 → cek key dan <code>auth_mode</code> layanan email. Kalau akses workers.dev timeout, isi proxy eksplisit di config, jangan cuma andalkan HTTP_PROXY yang mungkin tidak diwarisi proses desktop.</div>
          </details>
      <details class="faq-item" data-faq-item data-search="layanan email provider cloudflare duckmail yyds mailnest cloudmail moemail a">
        <summary>Cara konfigurasi layanan email</summary>
        <div class="faq-answer">Buka "Layanan Email" di atas, pilih penyedia yang dipakai, isi konfigurasi API, simpan dan test konektivitas. Rotasi domain sendiri ada di pengaturan lanjutan halaman yang sama; hanya domain yang ditolak xAI yang dihitung gagal; error API email dan captcha tidak menghukum domain.</div>
          </details>
      <details class="faq-item" data-faq-item data-search="blacklist asn hapus reset baseline risk exit">
        <summary>Blacklist gunanya apa, bisa dihapus?</summary>
        <div class="faq-answer">Blacklist dipakai untuk hindari ASN exit IP yang terus memicu risk. Tombol "Reset" di panel mengembalikan aturan baseline circuit-breaker; kalau tidak yakin, jangan kosongkan semua aturan  -  hit berulang biasanya berarti kualitas exit IP perlu diperbaiki.</div>
          </details>
      <details class="faq-item" data-faq-item data-search="accounts txt sso import cpa json sub2api konversi">
        <summary>File accounts yang sudah ada cara import ke CPA atau sub2api?</summary>
        <div class="faq-answer">Fitur "Recovery Akun" di konsol bisa proses queue pending atau scan semua file accounts; akun yang sudah punya CPA dilewati, yang sukses dihapus dari queue. Panel tidak langsung import sub2api  -  perlu sesuaikan struktur data sistem target secara terpisah.</div>
          </details>
      <details class="faq-item" data-faq-item data-search="search model grok build 4.5 kemampuan api">
        <summary>Registrasi sukses tapi search atau model tertentu tidak bisa</summary>
        <div class="faq-answer">Registrasi sukses tidak berarti semua fitur upstream terbuka. Pastikan request lewat channel Grok Build; ketersediaan search dan model tertentu masih bisa berubah sesuai status akun dan kebijakan upstream.</div>
          </details>
      <details class="faq-item" data-faq-item data-search="kuota gratis 429 quota rate limit gratis saldo">
        <summary>Berapa kuota gratis, kalau muncul 429 bagaimana</summary>
        <div class="faq-answer">Kuota gratis dialokasikan per akun oleh upstream, panel tidak bisa hitung sisa pasti. 429 biasanya berarti kuota habis atau kena rate limit  -  tunggu pulih atau ganti auth yang masih punya kuota.</div>
          </details>
        </div>
      <p class="faq-empty" id="faq-empty" hidden>Tidak ada pertanyaan yang cocok, coba kata kunci error atau gejala lain.</p>
      </div>
      </div>
    </div>
  </section>

  <section class="proxy-view" id="proxy-view" aria-labelledby="proxy-view-title" hidden>
    <div class="proxy-view-inner">
      <div class="proxy-view-heading">
        <div>
      <div class="page-title" id="proxy-view-title">Proxy Pool Eksternal</div>
      <p class="proxy-view-subtitle">Kredensial disimpan lokal, tidak berganti exit IP saat registrasi</p>
        </div>
      <span class="proxy-job mono" id="proxy-updated">Menunggu pembacaan</span>
      </div>

      <div class="proxy-summary" id="proxy-summary" aria-label="Status Proxy Pool">
        <div class="proxy-summary-item"><div class="proxy-summary-label">Total</div><div class="proxy-summary-value">--</div></div>
        <div class="proxy-summary-item"><div class="proxy-summary-label">Tersedia</div><div class="proxy-summary-value">--</div></div>
        <div class="proxy-summary-item"><div class="proxy-summary-label">Bermasalah</div><div class="proxy-summary-value">--</div></div>
        <div class="proxy-summary-item"><div class="proxy-summary-label">Cooldown</div><div class="proxy-summary-value">--</div></div>
        <div class="proxy-summary-item"><div class="proxy-summary-label">Belum dicek</div><div class="proxy-summary-value">--</div></div>
      </div>

      <div class="proxy-import">
        <div class="field">
      <label for="proxy-input">Alamat proxy (satu per baris)</label>
          <textarea id="proxy-input" spellcheck="false" autocomplete="off" placeholder="http://user:password@host:port&#10;host:port:user:password"></textarea>
        </div>
        <div class="proxy-import-actions">
      <p class="proxy-format">Mendukung http, https, socks5, socks5h, dan host:port:user:password. Setelah import lakukan pengecekan dulu; hanya proxy sehat yang akan dipakai untuk akun baru.</p>
          <div class="button-group">
      <button class="primary" id="proxy-import-button" onclick="importProxyInput()">Import Proxy</button>
      <button id="proxy-legacy-button" onclick="importLegacyProxies()">Import proxies.txt</button>
          </div>
        </div>
      </div>
      <div class="msg" id="proxy-msg" role="status" aria-live="polite"></div>

      <div class="proxy-list-section">
        <div class="proxy-list-head">
          <div>
      <h2>Detail Proxy</h2>
      <div class="proxy-job mono" id="proxy-test-status" role="status" aria-live="polite">Belum dicek</div>
          </div>
      <button id="proxy-test-all" onclick="testProxies()">Cek Semua</button>
        </div>
        <div class="proxy-table-wrap">
          <table class="proxy-table">
      <thead><tr><th>Status</th><th>Endpoint Proxy</th><th>Exit IP / ASN</th><th>Latensi</th><th>Status Terakhir</th><th>Aktif</th><th>Aksi</th></tr></thead>
      <tbody id="proxy-body"><tr><td colspan="7" class="proxy-empty">Membaca proxy pool</td></tr></tbody>
          </table>
        </div>
      </div>
    </div>
  </section>

  <section class="domain-view" id="domain-view" aria-labelledby="domain-view-title" hidden>
    <div class="domain-view-inner">
      <div class="domain-view-heading">
        <div>
          <div class="mail-source-kicker">Mail source</div>
      <div class="page-title" id="domain-view-title">Layanan Email</div>
      <p class="domain-view-subtitle" id="mail-provider-subtitle">Membaca konfigurasi layanan email</p>
        </div>
        <span class="domain-job" id="mail-provider-heading-label">--</span>
      </div>

      <section class="mail-provider-panel" aria-labelledby="mail-provider-label">
        <div class="mail-provider-toolbar">
          <div class="field">
      <label for="mail-provider-select" id="mail-provider-label">Penyedia Email</label>
            <select id="mail-provider-select" onchange="selectEmailProvider(this.value)">
        <option value="">Membaca</option>
            </select>
          </div>
          <div class="mail-provider-status">
        <span class="mail-provider-status-label">Status Saat Ini</span>
        <span class="badge" id="mail-provider-status" role="status" aria-live="polite">Membaca</span>
          </div>
        </div>
        <div class="mail-provider-fields" id="mail-provider-fields" aria-live="polite">
        <div class="field"><label>Konfigurasi Layanan</label><input disabled value="Membaca"/></div>
        </div>
        <div class="mail-provider-actions">
      <button class="primary" id="mail-provider-save" onclick="saveEmailProviderConfig()">Simpan Konfigurasi</button>
      <button id="mail-provider-test" onclick="testEmailProviderConnection()">Test Penyedia Saat Ini</button>
      <span class="mail-provider-meta mono" id="mail-provider-updated">Belum dibaca</span>
        </div>
        <div class="msg mail-provider-result" id="mail-provider-msg" role="status" aria-live="polite"></div>
      </section>

      <details class="domain-advanced" id="domain-advanced">
        <summary>
        <span class="domain-advanced-title">Rotasi Domain <span class="domain-advanced-meta">Pengaturan Lanjutan</span></span>
        <span class="domain-advanced-meta mono" id="domain-advanced-count">0 domain</span>
        </summary>
        <div class="domain-advanced-body">
          <div class="domain-advanced-head">
        <span class="domain-advanced-meta">Hanya domain yang ditolak xAI yang dihitung gagal</span>
        <span class="domain-job mono" id="domain-updated">Menunggu pembacaan</span>
          </div>

      <div class="domain-summary" id="domain-summary" aria-label="Status rotasi domain email">
        <div class="domain-summary-item"><div class="domain-summary-label">Total</div><div class="domain-summary-value">--</div></div>
        <div class="domain-summary-item"><div class="domain-summary-label">Rotasi</div><div class="domain-summary-value">--</div></div>
        <div class="domain-summary-item"><div class="domain-summary-label">Standby</div><div class="domain-summary-value">--</div></div>
        <div class="domain-summary-item"><div class="domain-summary-label">Blocked</div><div class="domain-summary-value">--</div></div>
        <div class="domain-summary-item"><div class="domain-summary-label">Nonaktif</div><div class="domain-summary-value">--</div></div>
          </div>

          <div class="domain-import">
            <div class="field">
      <label for="domain-input">Domain atau subdomain (satu per baris)</label>
              <textarea id="domain-input" spellcheck="false" autocomplete="off" placeholder="mail.example.com&#10;inbox.example.net"></textarea>
            </div>
            <div class="domain-import-actions">
              <div class="domain-settings">
                <div class="field">
      <label for="domain-provider">Penyedia Email</label>
                  <select id="domain-provider">
                    <option value="cloudflare">Cloudflare</option>
                    <option value="cloudmail">CloudMail</option>
                    <option value="moemail">MoeMail</option>
                    <option value="yyds">YYDS</option>
                  </select>
                </div>
                <div class="field">
      <label for="domain-threshold">Threshold Tolak</label>
                  <input type="number" id="domain-threshold" min="1" max="20" value="3"/>
                </div>
                <div class="field">
      <label for="domain-max-active">Jumlah aktif per penyedia</label>
        <input type="number" id="domain-max-active" min="0" max="100" value="0" title="0 = tidak terbatas"/>
                </div>
              </div>
      <p class="domain-format">Cloudflare, CloudMail, MoeMail, YYDS bisa pakai domain sendiri; 0 = tidak batasi jumlah aktif.</p>
              <div class="button-group">
      <button class="primary" id="domain-import-button" onclick="importDomainInput()">Import Domain</button>
      <button id="domain-settings-button" onclick="saveDomainSettings()">Simpan Aturan</button>
              </div>
            </div>
          </div>
          <div class="msg" id="domain-msg" role="status" aria-live="polite"></div>

          <div class="domain-list-section">
            <div class="domain-list-head">
              <div>
      <h2>Detail Domain</h2>
      <div class="domain-job mono" id="domain-status" role="status" aria-live="polite">Belum ada domain</div>
              </div>
      <button id="domain-refresh-button" onclick="refreshEmailDomains(false)">Refresh</button>
            </div>
            <div class="domain-table-wrap">
              <table class="domain-table">
      <thead><tr><th>Status</th><th>Domain</th><th>Penyedia</th><th>Jumlah Ditolak</th><th>Status Terakhir</th><th>Aktif</th><th>Aksi</th></tr></thead>
      <tbody id="domain-body"><tr><td colspan="7" class="domain-empty">Membaca rotasi domain email</td></tr></tbody>
              </table>
            </div>
          </div>
        </div>
      </details>
    </div>
  </section>

  <section class="metric-grid panel-gap" id="kpis" aria-label="Metrik Utama"></section>

  <section class="card panel" id="batch-live-panel" aria-labelledby="batch-live-title">
    <div class="section-head">
      <h2 id="batch-live-title">Batch Live (gro_register_to_9router)</h2>
      <span class="section-meta mono" id="batch-live-meta">menunggu data…</span>
    </div>
    <div class="batch-live-grid">
      <div class="metric"><div class="label">Target</div><div class="value" id="bl-target">--</div><div class="sub">akun</div></div>
      <div class="metric"><div class="label">Selesai</div><div class="value ok" id="bl-completed">--</div><div class="sub">akun</div></div>
      <div class="metric"><div class="label">Sisa</div><div class="value" id="bl-remaining">--</div><div class="sub">akun</div></div>
      <div class="metric"><div class="label">Worker</div><div class="value" id="bl-workers">--</div><div class="sub">paralel</div></div>
      <div class="metric"><div class="label">Status</div><div class="value" id="bl-running">--</div><div class="sub">batch</div></div>
      <div class="metric"><div class="label">Batch ID</div><div class="value mono" id="bl-batch-id">--</div><div class="sub">id</div></div>
    </div>
    <div class="bar-wrap"><div class="bar" id="bl-bar"></div></div>
    <div class="progress-sub" id="bl-prog-sub"></div>
  </section>

  <section class="card panel rate-panel">
    <div class="section-head">
    <h2>Success Rate per Periode</h2>
      <span class="section-meta mono" id="rates-updated">register_results.jsonl</span>
    </div>
    <div class="rate-grid" id="rate-kpis"></div>
  </section>

  <section class="card panel">
    <div class="progress-head">
    <h2>Batch Saat Ini</h2>
      <div class="mono" id="prog-text">--</div>
    </div>
    <div class="bar-wrap"><div class="bar" id="bar"></div></div>
    <div class="progress-sub" id="prog-sub"></div>
  </section>

  <section class="card panel recovery-panel" aria-labelledby="recovery-title">
    <div class="section-head">
      <h2 id="recovery-title">Recovery Akun</h2>
      <span class="section-meta mono" id="recovery-status">Menunggu cek</span>
    </div>
    <div class="recovery-layout">
      <div class="chips" id="recovery-kpis"></div>
      <div class="button-group recovery-actions">
        <button id="recovery-pending" onclick="startRecovery('pending')">Recovery Pending</button>
        <button id="recovery-accounts" onclick="startRecovery('accounts')">Scan Semua Akun</button>
        <button class="danger" id="recovery-stop" onclick="stopRecovery()">Hentikan Recovery</button>
      </div>
    </div>
    <div class="msg" id="recovery-msg" role="status" aria-live="polite"></div>
  </section>

  <div class="three panel-gap">
    <div class="card">
      <div class="section-head">
      <h2>Statistik Sukses</h2>
      <button onclick="refreshStats()">Refresh</button>
      </div>
      <div class="chips" id="stats-chips"></div>
      <div class="msg" id="stats-msg" role="status" aria-live="polite"></div>
      <div class="table-scroll">
      <table><thead><tr><th>Tanggal</th><th>Sukses</th><th>Risk</th><th>Gagal</th></tr></thead>
        <tbody id="stats-day"></tbody></table>
      </div>
    </div>
    <div class="card">
      <div class="section-head">
      <h2>Blacklist</h2>
        <div class="button-group">
        <button onclick="refreshBlacklist()">Refresh</button>
        <button class="danger" onclick="resetBlacklist('baseline')">Reset</button>
        </div>
      </div>
      <div class="chips" id="bl-kpis"></div>
      <div class="msg" id="bl-msg" role="status" aria-live="polite"></div>
      <div class="bl-list" style="margin-top:10px">
      <table><thead><tr><th>ASN</th><th>Catatan</th></tr></thead><tbody id="bl-body"></tbody></table>
      </div>
    </div>
    <div class="card">
      <div class="section-head"><h2>Log Update Blacklist</h2></div>
      <div class="chips" id="bl-err-chips"></div>
      <div class="table-scroll">
      <table><thead><tr><th>ASN Ditambah</th><th>Sumber</th></tr></thead>
        <tbody id="bl-added"></tbody></table>
      </div>
    </div>
  </div>

  <div class="two panel-gap">
    <div class="card"><h2>Worker Sukses / Gagal</h2><div class="chips" id="workers-stats"></div></div>
    <div class="card"><h2>Kategori Gagal</h2><div class="chips" id="fails"></div></div>
  </div>
  <div class="two panel-gap">
    <div class="card">
    <div class="section-head"><h2>Sukses Terakhir</h2></div>
    <div class="table-scroll"><table><thead><tr><th>Waktu</th><th>W</th><th>Email</th></tr></thead><tbody id="ok-body"></tbody></table></div>
    </div>
    <div class="card">
    <div class="section-head"><h2>Gagal Terakhir</h2></div>
    <div class="table-scroll"><table><thead><tr><th>Waktu</th><th>W</th><th>Tipe</th><th>Ringkasan</th></tr></thead><tbody id="fail-body"></tbody></table></div>
    </div>
  </div>
  <section class="card panel">
    <div class="section-head"><h2>Log Terakhir</h2></div>
    <div class="tail mono" id="tail"></div>
  </section>
  <footer id="footer"></footer>
</main>
<script>
let last = null;
let proxyData = null;
let domainData = null;
let emailProviderData = null;
let selectedEmailProvider = "";
const clearedEmailSecrets = new Set();
const THEME_KEY = "GROK_REGISTER_THEME";
const APP_VIEW_KEY = "GROK_REGISTER_APP_VIEW";
const HELP_TAB_KEY = "GROK_REGISTER_HELP_TAB";
function syncThemeButtons() {
  const theme = document.documentElement.dataset.theme || "light";
  document.querySelectorAll("[data-theme-choice]").forEach(button => {
    button.setAttribute("aria-pressed", String(button.dataset.themeChoice === theme));
  });
  const color = document.getElementById("theme-color");
  if (color) color.content = theme === "dark" ? "#171815" : "#f3f4f1";
}
function setTheme(theme) {
  if (theme !== "light" && theme !== "dark") return;
  document.documentElement.dataset.theme = theme;
  try { localStorage.setItem(THEME_KEY, theme); } catch (e) {}
  syncThemeButtons();
}
function setAppView(view, options = {}) {
  if (view !== "dashboard" && view !== "help" && view !== "proxies" && view !== "domains") return;
  const dashboard = document.getElementById("dashboard-view");
  const help = document.getElementById("help-view");
  const proxies = document.getElementById("proxy-view");
  const domains = document.getElementById("domain-view");
  const domainToggle = document.getElementById("domain-view-toggle");
  const domainLabel = document.getElementById("domain-view-label");
  const toggle = document.getElementById("help-view-toggle");
  const label = document.getElementById("help-view-label");
  const proxyToggle = document.getElementById("proxy-view-toggle");
  const proxyLabel = document.getElementById("proxy-view-label");
  if (!dashboard || !help || !proxies || !domains || !domainToggle || !domainLabel || !toggle || !label || !proxyToggle || !proxyLabel) return;
  const isHelp = view === "help";
  const isProxies = view === "proxies";
  const isDomains = view === "domains";
  const isOverlay = isHelp || isProxies || isDomains;
  const dashboardChildren = Array.from(dashboard.children).filter(element => element !== help && element !== proxies && element !== domains);
  dashboardChildren.forEach(element => {
    element.inert = isOverlay;
    if (isOverlay) element.setAttribute("aria-hidden", "true");
    else element.removeAttribute("aria-hidden");
  });
  help.hidden = !isHelp;
  help.inert = !isHelp;
  proxies.hidden = !isProxies;
  proxies.inert = !isProxies;
  domains.hidden = !isDomains;
  domains.inert = !isDomains;
  document.body.classList.toggle("help-view-open", isHelp);
  document.body.classList.toggle("proxy-view-open", isProxies);
  document.body.classList.toggle("domain-view-open", isDomains);
  toggle.dataset.active = String(isHelp);
  toggle.setAttribute("aria-expanded", String(isHelp));
  toggle.setAttribute("aria-label", isHelp ? "Kembali" : "Buka Bantuan");
  toggle.title = isHelp ? "Kembali" : "Bantuan";
  label.textContent = isHelp ? "Kembali" : "Bantuan";
  proxyToggle.dataset.active = String(isProxies);
  proxyToggle.setAttribute("aria-expanded", String(isProxies));
  proxyToggle.setAttribute("aria-label", isProxies ? "Kembali" : "Buka Proxy Pool");
  proxyToggle.title = isProxies ? "Kembali" : "Proxy Pool";
  proxyLabel.textContent = isProxies ? "Kembali" : "Proxy Pool";
  domainToggle.dataset.active = String(isDomains);
  domainToggle.setAttribute("aria-expanded", String(isDomains));
  domainToggle.setAttribute("aria-label", isDomains ? "Kembali" : "Buka Layanan Email");
  domainToggle.title = isDomains ? "Kembali" : "Layanan Email";
  domainLabel.textContent = isDomains ? "Kembali" : "Layanan Email";
  if (options.persist !== false) {
    try { localStorage.setItem(APP_VIEW_KEY, view); } catch (e) {}
  }
  if (isProxies) refreshProxies();
  if (isDomains) {
    refreshEmailProvider();
    refreshEmailDomains();
  }
  if (options.focus) {
    requestAnimationFrame(() => {
      const target = isHelp
        ? document.querySelector('[data-help-tab][aria-selected="true"]')
        : (isProxies ? document.getElementById("proxy-input") : (isDomains ? document.getElementById("mail-provider-select") : (view === "dashboard" ? domainToggle : toggle)));
      if (target) target.focus();
    });
  }
}
function toggleAppView() {
  const isHelp = document.body.classList.contains("help-view-open");
  setAppView(isHelp ? "dashboard" : "help", { focus: true });
}
function toggleProxyView() {
  const isProxies = document.body.classList.contains("proxy-view-open");
  setAppView(isProxies ? "dashboard" : "proxies", { focus: true });
}
function toggleDomainView() {
  const isDomains = document.body.classList.contains("domain-view-open");
  setAppView(isDomains ? "dashboard" : "domains", { focus: true });
}
function setHelpTab(name) {
  if (name !== "guide" && name !== "faq") return;
  document.querySelectorAll("[data-help-tab]").forEach(button => {
    const selected = button.dataset.helpTab === name;
    button.setAttribute("aria-selected", String(selected));
    button.tabIndex = selected ? 0 : -1;
  });
  const guide = document.getElementById("help-guide");
  const faq = document.getElementById("help-faq");
  if (guide) guide.hidden = name !== "guide";
  if (faq) faq.hidden = name !== "faq";
  try { localStorage.setItem(HELP_TAB_KEY, name); } catch (e) {}
}
function handleHelpTabKey(event) {
  if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
  const tabs = Array.from(document.querySelectorAll("[data-help-tab]"));
  const current = tabs.indexOf(document.activeElement);
  if (current < 0) return;
  event.preventDefault();
  const next = event.key === "ArrowRight" ? (current + 1) % tabs.length : (current - 1 + tabs.length) % tabs.length;
  tabs[next].focus();
  setHelpTab(tabs[next].dataset.helpTab);
}
function filterFaq(value) {
  const query = String(value || "").trim().toLocaleLowerCase();
  const items = Array.from(document.querySelectorAll("[data-faq-item]"));
  const matches = [];
  items.forEach(item => {
    const haystack = ((item.dataset.search || "") + " " + item.textContent).toLocaleLowerCase();
    const matched = !query || haystack.includes(query);
    item.hidden = !matched;
    if (matched) matches.push(item);
  });
  if (query && matches.length === 1) matches[0].open = true;
  const count = document.getElementById("faq-count");
  const empty = document.getElementById("faq-empty");
  if (count) count.textContent = matches.length + " item";
  if (empty) empty.hidden = matches.length > 0;
}
function showHelpFor(query) {
  setAppView("help", { focus: false });
  setHelpTab("faq");
  const search = document.getElementById("faq-search");
  if (search) search.value = query || "";
  filterFaq(query || "");
  if (search) requestAnimationFrame(() => search.focus());
}
function initHelp() {
  let view = "dashboard";
  let tab = "guide";
  try {
    view = localStorage.getItem(APP_VIEW_KEY) || "dashboard";
    tab = localStorage.getItem(HELP_TAB_KEY) || "guide";
  } catch (e) {}
  if (!["dashboard", "help", "proxies", "domains"].includes(view)) view = "dashboard";
  setHelpTab(tab);
  filterFaq("");
  setAppView(view, { persist: false, focus: false });
}
document.addEventListener("keydown", event => {
  if (event.key === "Escape" && (document.body.classList.contains("help-view-open") || document.body.classList.contains("proxy-view-open") || document.body.classList.contains("domain-view-open"))) {
    setAppView("dashboard", { focus: true });
  }
});
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
}
function setMsg(id, text, cls) {
  const el = document.getElementById(id);
  el.textContent = text || "";
  el.className = "msg" + (cls ? " " + cls : "");
}
function getToken() {
  const el = document.getElementById("monitor-token");
  const fromInput = el ? (el.value || "").trim() : "";
  const tok = (fromInput || window.MONITOR_TOKEN || localStorage.getItem("MONITOR_TOKEN") || "").trim();
  if (fromInput) try { localStorage.setItem("MONITOR_TOKEN", fromInput); } catch (e) {}
  return tok;
}
function loadTokenField() {
  const el = document.getElementById("monitor-token");
  if (!el) return;
  if (!el.value) {
    try { el.value = localStorage.getItem("MONITOR_TOKEN") || window.MONITOR_TOKEN || ""; } catch (e) {}
  }
}
async function api(path, opts) {
  opts = Object.assign({}, opts || {});
  const authHelp = opts.authHelp !== false;
  delete opts.authHelp;
  const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
  const tok = getToken();
  if (tok) headers["Authorization"] = "Bearer " + tok;
  const r = await fetch(path, Object.assign({}, opts, { headers }));
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    if (r.status === 401) {
      if (authHelp) showHelpFor("token");
    throw new Error("Token akses tidak cocok, silakan masukkan ulang token panel");
    }
    throw new Error(j.error || j.detail || r.statusText || "request failed");
  }
  if (j && j.ok === false) throw new Error(j.error || j.message || "request failed");
  return j;
}
function proxyStatusLabel(status) {
  return ({ healthy: "Sehat", unhealthy: "Bermasalah", cooldown: "Cooldown", testing: "Mengecek", unknown: "Belum dicek" })[status] || "Belum dicek";
}
function proxyTime(value) {
  if (!value) return "--";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false });
}
function cooldownText(item) {
  const seconds = Number(item.cooldown_remaining_seconds || 0);
  if (seconds <= 0) return "";
  const value = seconds >= 3600 ? Math.ceil(seconds / 3600) + " jam" : Math.ceil(seconds / 60) + " menit";
  return (item.cooldown_reason === "risk" ? "Cooldown risk " : "Cooldown jaringan ") + value;
}
function renderProxyPool(data) {
  proxyData = data || {};
  const summary = proxyData.summary || {};
  const values = [
      ["Total", summary.total ?? 0, ""],
      ["Tersedia", summary.usable ?? 0, "ok"],
      ["Bermasalah", summary.unhealthy ?? 0, (summary.unhealthy || 0) > 0 ? "fail" : ""],
      ["Cooldown", summary.cooldown ?? 0, (summary.cooldown || 0) > 0 ? "warn" : ""],
      ["Belum dicek", summary.unknown ?? 0, (summary.unknown || 0) > 0 ? "accent" : ""],
  ];
  document.getElementById("proxy-summary").innerHTML = values.map(([label, value, cls]) =>
    `<div class="proxy-summary-item"><div class="proxy-summary-label">${esc(label)}</div><div class="proxy-summary-value ${cls}">${esc(value)}</div></div>`
  ).join("");
  document.getElementById("proxy-updated").textContent = proxyData.updated_at ? ("Update " + proxyTime(proxyData.updated_at)) : "Belum ditulis";

  const legacy = proxyData.legacy || {};
  const legacyButton = document.getElementById("proxy-legacy-button");
  legacyButton.disabled = !legacy.available;
  legacyButton.textContent = legacy.available ? ("Import proxies.txt (" + (legacy.count || 0) + ")") : "Tidak ada proxies.txt";

  const job = proxyData.test_job || {};
  const testButton = document.getElementById("proxy-test-all");
  testButton.disabled = !!job.running || !(summary.enabled > 0);
  document.getElementById("proxy-test-status").textContent = job.running
      ? ("Mengecek " + (job.completed || 0) + "/" + (job.total || 0) + ", sehat " + (job.healthy || 0) + ", gagal " + (job.failed || 0))
      : (job.finished_at ? ("Cek terakhir: sehat " + (job.healthy || 0) + ", gagal " + (job.failed || 0)) : "Belum dicek");

  const items = proxyData.items || [];
  document.getElementById("proxy-body").innerHTML = items.length ? items.map(item => {
    const status = item.status || "unknown";
    const stateClass = ["healthy", "unhealthy", "cooldown", "testing"].includes(status) ? status : "";
    const exit = item.exit_ip ? esc(item.exit_ip) : "--";
    const asn = item.asn ? ("AS" + esc(item.asn)) : "--";
    const org = item.asn_org ? `<div class="proxy-meta">${esc(item.asn_org)}</div>` : "";
    const latency = item.latency_ms == null ? "--" : (esc(item.latency_ms) + " ms");
    const cooldown = cooldownText(item);
  const detail = cooldown || item.last_error || (item.last_checked_at ? ("Dicek " + proxyTime(item.last_checked_at)) : "Belum dicek");
  const count = (item.failure_count || 0) > 0 ? `<div class="proxy-meta">Gagal ${esc(item.failure_count)} / Risk ${esc(item.risk_count || 0)}</div>` : "";
    return `<tr>
      <td><span class="proxy-state ${stateClass}">${esc(proxyStatusLabel(status))}</span></td>
    <td><div class="mono proxy-endpoint">${esc(item.display_url || "")}</div><div class="proxy-meta">${item.has_auth ? "Kredensial tersembunyi" : "Tanpa auth"}</div></td>
      <td><div class="mono">${exit}</div><div class="proxy-meta mono">${asn}</div>${org}</td>
      <td class="mono">${latency}</td>
      <td title="${esc(item.last_error || "")}">${esc(detail)}${count}</td>
    <td><input class="proxy-toggle" type="checkbox" aria-label="Aktifkan ${esc(item.display_url || "proxy")}" ${item.enabled ? "checked" : ""} onchange="setProxyEnabled('${item.id}', this.checked)"/></td>
    <td><div class="proxy-actions"><button ${status === "testing" ? "disabled" : ""} onclick="testProxies('${item.id}')">Cek</button><button class="danger" onclick="deleteProxy('${item.id}')">Hapus</button></div></td>
    </tr>`;
  }).join("") : '<tr><td colspan="7" class="proxy-empty">Proxy pool kosong, bisa import satu atau banyak proxy di atas</td></tr>';
}
async function refreshProxies(authHelp = false) {
  try {
    const data = await api("/api/proxies?_=" + Date.now(), { authHelp });
    renderProxyPool(data);
    if (!data.ok && data.error) setMsg("proxy-msg", data.error, "err");
  } catch (e) {
    const message = String(e.message || e);
  document.getElementById("proxy-updated").textContent = message.includes("token") ? "Menunggu token" : "Gagal membaca";
    setMsg("proxy-msg", message, "err");
  }
}
function proxyImportMessage(result, prefix) {
  const errors = result.errors || [];
  const errorText = errors.length ? (", lewati " + errors.length + " item: " + errors.slice(0, 2).map(item => "baris " + item.line + " " + item.error).join("; ")) : "";
  return prefix + (result.imported_count || 0) + " item, duplikat " + (result.duplicate_count || 0) + " item" + errorText;
}
async function startImportedProxyTests(result) {
  const ids = result.imported_ids || [];
  if (!ids.length) return false;
  await api("/api/proxies/test", { method: "POST", body: JSON.stringify({ ids }) });
  return true;
}
async function importProxyInput() {
  const input = document.getElementById("proxy-input");
  const button = document.getElementById("proxy-import-button");
  const value = (input.value || "").trim();
  if (!value) { setMsg("proxy-msg", "Masukkan minimal satu proxy", "err"); input.focus(); return; }
  button.disabled = true;
  setMsg("proxy-msg", "Mengimport...", "");
  try {
    const result = await api("/api/proxies/import", { method: "POST", body: JSON.stringify({ proxies: value }) });
    renderProxyPool(result);
    input.value = "";
    const testing = await startImportedProxyTests(result);
  setMsg("proxy-msg", proxyImportMessage(result, "Berhasil import ") + (testing ? ", mulai dicek" : ""), result.errors && result.errors.length ? "warn" : "ok");
    setTimeout(() => refreshProxies(false), 300);
  } catch (e) { setMsg("proxy-msg", String(e.message || e), "err"); }
  button.disabled = false;
}
async function importLegacyProxies() {
  const button = document.getElementById("proxy-legacy-button");
  button.disabled = true;
  try {
    const result = await api("/api/proxies/import", { method: "POST", body: JSON.stringify({ legacy: true }) });
    renderProxyPool(result);
    const testing = await startImportedProxyTests(result);
  setMsg("proxy-msg", proxyImportMessage(result, "Dari proxies.txt diimport ") + (testing ? ", mulai dicek" : ""), "ok");
    setTimeout(() => refreshProxies(false), 300);
  } catch (e) { setMsg("proxy-msg", String(e.message || e), "err"); }
  button.disabled = false;
}
async function testProxies(id) {
  const ids = id ? [id] : [];
  setMsg("proxy-msg", id ? "Mengecek proxy ini..." : "Memulai pengecekan massal...", "");
  try {
    await api("/api/proxies/test", { method: "POST", body: JSON.stringify({ ids }) });
  setMsg("proxy-msg", "Task pengecekan dimulai", "ok");
    await refreshProxies(false);
  } catch (e) { setMsg("proxy-msg", String(e.message || e), "err"); }
}
async function setProxyEnabled(id, enabled) {
  try {
    const result = await api("/api/proxies/" + id, { method: "PATCH", body: JSON.stringify({ enabled }) });
    renderProxyPool(result);
  setMsg("proxy-msg", enabled ? "Proxy diaktifkan" : "Proxy dinonaktifkan", "ok");
  } catch (e) {
    setMsg("proxy-msg", String(e.message || e), "err");
    await refreshProxies(false);
  }
}
async function deleteProxyItem(id) {
  const item = (proxyData && proxyData.items || []).find(value => value.id === id);
  if (!confirm("Hapus proxy " + (item ? item.display_url : "") + "?")) return;
  try {
    const result = await api("/api/proxies/" + id, { method: "DELETE" });
    renderProxyPool(result);
  setMsg("proxy-msg", "Proxy dihapus", "ok");
  } catch (e) { setMsg("proxy-msg", String(e.message || e), "err"); }
}
function currentEmailProviderDefinition(provider = selectedEmailProvider) {
  return (emailProviderData && emailProviderData.providers || []).find(item => item.id === provider) || null;
}
function emailProviderFieldControl(field) {
  const id = "mail-field-" + field.name;
  const raw = emailProviderData && emailProviderData.values ? emailProviderData.values[field.name] : "";
  const value = raw ?? field.default ?? "";
  if (field.type === "select") {
    const options = (field.options || []).map(option => {
      const optionValue = typeof option === "object" ? option.value : option;
      const optionLabel = typeof option === "object" ? option.label : option;
      return `<option value="${esc(optionValue)}" ${String(optionValue) === String(value) ? "selected" : ""}>${esc(optionLabel)}</option>`;
    }).join("");
    return `<select id="${esc(id)}" data-mail-field="${esc(field.name)}">${options}</select>`;
  }
  const isSecret = field.secret === true;
  const configured = isSecret && emailProviderData && emailProviderData.secret_configured && emailProviderData.secret_configured[field.name];
  const placeholder = configured ? "Terkonfigurasi, kosongkan untuk simpan" : (field.placeholder || "");
  const type = isSecret ? "password" : (["url", "email"].includes(field.type) ? field.type : "text");
  const input = `<input id="${esc(id)}" data-mail-field="${esc(field.name)}" type="${type}" value="${isSecret ? "" : esc(value)}" placeholder="${esc(placeholder)}" autocomplete="${isSecret ? "new-password" : "off"}" spellcheck="false" ${isSecret ? `oninput="emailProviderSecretInput('${field.name}')"` : ""}/>`;
  if (!isSecret) return input;
  const clear = configured ? `<button type="button" data-mail-secret-button="${esc(field.name)}" onclick="toggleEmailProviderSecret('${field.name}')">Hapus</button>` : "";
  const note = configured ? "Key tersimpan" : "Belum dikonfigurasi";
  return `<div class="mail-secret-wrap" data-mail-secret-wrap="${esc(field.name)}">${input}${clear}</div><div class="mail-secret-note" data-mail-secret-note="${esc(field.name)}">${note}</div>`;
}
function renderEmailProviderFields(provider) {
  const definition = currentEmailProviderDefinition(provider);
  if (!definition) return;
  selectedEmailProvider = definition.id;
  clearedEmailSecrets.clear();
  const select = document.getElementById("mail-provider-select");
  if (select) select.value = definition.id;
  document.getElementById("mail-provider-heading-label").textContent = definition.label;
  const persisted = emailProviderData && emailProviderData.provider === definition.id;
  document.getElementById("mail-provider-subtitle").textContent = persisted
      ? ("Task registrasi saat ini pakai " + definition.label)
      : ("Menunggu ganti ke " + definition.label);
  const status = document.getElementById("mail-provider-status");
  status.textContent = definition.configured ? "Terkonfigurasi" : "Belum dikonfigurasi";
  status.className = "badge " + (definition.configured ? "ok" : "warn");
  document.getElementById("mail-provider-fields").innerHTML = (definition.fields || []).map(field =>
    `<div class="field"><label for="mail-field-${esc(field.name)}">${esc(field.label)}</label>${emailProviderFieldControl(field)}</div>`
  ).join("") || '<div class="field"><label>Konfigurasi Layanan</label><input disabled value="Penyedia ini tidak punya field yang bisa diedit"/></div>';
  const domainProvider = document.getElementById("domain-provider");
  if (domainProvider && ["cloudflare", "cloudmail", "moemail", "yyds"].includes(definition.id)) {
    domainProvider.value = definition.id;
    if (domainData) renderEmailDomainPool(domainData);
  }
}
function renderEmailProviderConfig(data) {
  emailProviderData = data || {};
  const select = document.getElementById("mail-provider-select");
  const providers = emailProviderData.providers || [];
  select.innerHTML = providers.map(provider =>
    `<option value="${esc(provider.id)}">${esc(provider.label)}</option>`
  ).join("");
  const provider = providers.some(item => item.id === emailProviderData.provider)
    ? emailProviderData.provider
    : (providers[0] && providers[0].id || "");
  const updated = emailProviderData.mtime ? new Date(emailProviderData.mtime * 1000) : null;
  document.getElementById("mail-provider-updated").textContent = updated && !Number.isNaN(updated.getTime())
    ? ("config.json " + updated.toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }))
    : "config.json belum dibuat";
  renderEmailProviderFields(provider);
}
function selectEmailProvider(provider) {
  renderEmailProviderFields(provider);
  setMsg("mail-provider-msg", "", "");
}
function toggleEmailProviderSecret(name) {
  const clearing = !clearedEmailSecrets.has(name);
  if (clearing) clearedEmailSecrets.add(name);
  else clearedEmailSecrets.delete(name);
  const wrap = document.querySelector(`[data-mail-secret-wrap="${name}"]`);
  const button = document.querySelector(`[data-mail-secret-button="${name}"]`);
  const note = document.querySelector(`[data-mail-secret-note="${name}"]`);
  if (wrap) wrap.classList.toggle("pending-clear", clearing);
  if (button) button.textContent = clearing ? "Batal" : "Hapus";
  if (note) {
  note.textContent = clearing ? "Hapus key setelah simpan" : "Key tersimpan";
    note.className = "mail-secret-note" + (clearing ? " warn" : "");
  }
}
function emailProviderSecretInput(name) {
  const input = document.getElementById("mail-field-" + name);
  if (input && input.value && clearedEmailSecrets.has(name)) toggleEmailProviderSecret(name);
}
function collectEmailProviderSettings() {
  const definition = currentEmailProviderDefinition();
  const settings = {};
  (definition && definition.fields || []).forEach(field => {
    const input = document.getElementById("mail-field-" + field.name);
    if (!input) return;
    settings[field.name] = field.name === "moemail_expiry_ms" ? Number(input.value) : input.value;
  });
  return settings;
}
async function refreshEmailProvider(authHelp = false) {
  try {
    const data = await api("/api/email-provider?_=" + Date.now(), { authHelp });
    renderEmailProviderConfig(data);
    if (!data.ok && data.error) setMsg("mail-provider-msg", data.error, "err");
  } catch (e) {
    const message = String(e.message || e);
  document.getElementById("mail-provider-heading-label").textContent = message.includes("token") ? "Menunggu token" : "Gagal membaca";
    setMsg("mail-provider-msg", message, "err");
  }
}
async function saveEmailProviderConfig() {
  const button = document.getElementById("mail-provider-save");
  button.disabled = true;
  setMsg("mail-provider-msg", "Menyimpan...", "");
  try {
    const result = await api("/api/email-provider", { method: "POST", body: JSON.stringify({
      provider: selectedEmailProvider,
      settings: collectEmailProviderSettings(),
      clear_secrets: Array.from(clearedEmailSecrets),
    }) });
    renderEmailProviderConfig(result);
  setMsg("mail-provider-msg", result.provider_label + " konfigurasi tersimpan", "ok");
  } catch (e) { setMsg("mail-provider-msg", String(e.message || e), "err"); }
  button.disabled = false;
}
async function testEmailProviderConnection() {
  const button = document.getElementById("mail-provider-test");
  button.disabled = true;
  setMsg("mail-provider-msg", "Mengecek konektivitas...", "");
  try {
    const result = await api("/api/email-provider/test", { method: "POST", body: JSON.stringify({
      provider: selectedEmailProvider,
      settings: collectEmailProviderSettings(),
      clear_secrets: Array.from(clearedEmailSecrets),
    }) });
  setMsg("mail-provider-msg", result.detail || "Koneksi normal", "ok");
  } catch (e) { setMsg("mail-provider-msg", String(e.message || e), "err"); }
  button.disabled = false;
}
function domainStatusLabel(status) {
  return ({ active: "Rotasi", standby: "Standby", blocked: "Blocked", disabled: "Nonaktif" })[status] || "Standby";
}
function renderEmailDomainPool(data) {
  domainData = data || {};
  const summary = domainData.summary || {};
  const values = [
      ["Total", summary.total ?? 0, ""],
      ["Rotasi", summary.active ?? 0, "ok"],
      ["Standby", summary.standby ?? 0, (summary.standby || 0) > 0 ? "accent" : ""],
      ["Blocked", summary.blocked ?? 0, (summary.blocked || 0) > 0 ? "fail" : ""],
      ["Nonaktif", summary.disabled ?? 0, (summary.disabled || 0) > 0 ? "warn" : ""],
  ];
  document.getElementById("domain-summary").innerHTML = values.map(([label, value, cls]) =>
    `<div class="domain-summary-item"><div class="domain-summary-label">${esc(label)}</div><div class="domain-summary-value ${cls}">${esc(value)}</div></div>`
  ).join("");
  document.getElementById("domain-advanced-count").textContent = (summary.total ?? 0) + " domain";
  document.getElementById("domain-updated").textContent = domainData.updated_at ? ("Update " + proxyTime(domainData.updated_at)) : "Belum ditulis";
  const settings = domainData.settings || {};
  const focused = document.activeElement && ["domain-threshold", "domain-max-active"].includes(document.activeElement.id);
  if (!focused) {
    document.getElementById("domain-threshold").value = settings.failure_threshold ?? 3;
    document.getElementById("domain-max-active").value = settings.max_active_domains ?? 0;
  }
  const provider = document.getElementById("domain-provider").value || "cloudflare";
  const providerLabel = domainData.provider_labels && domainData.provider_labels[provider] || provider;
  const providerCount = domainData.providers && domainData.providers[provider] || 0;
  document.getElementById("domain-status").textContent = providerCount
      ? (providerLabel + " terkonfigurasi " + providerCount + " domain")
      : "Belum ada domain untuk penyedia ini";
  const items = domainData.items || [];
  document.getElementById("domain-body").innerHTML = items.length ? items.map(item => {
    const status = item.status || "standby";
    const stateClass = ["active", "standby", "blocked", "disabled"].includes(status) ? status : "standby";
    const threshold = item.failure_threshold || settings.failure_threshold || 3;
    const rejected = Number(item.consecutive_rejections || 0);
    const total = Number(item.total_rejections || 0);
  const counts = `${rejected}/${threshold}<div class="domain-meta">Total ${total} / Sukses ${Number(item.success_count || 0)}</div>`;
  const latest = item.last_error || (item.last_rejected_at ? ("Ditolak " + proxyTime(item.last_rejected_at)) : (item.last_success_at ? ("Sukses " + proxyTime(item.last_success_at)) : "Belum ada"));
  const resetButton = rejected > 0 || status === "blocked" ? `<button onclick="resetEmailDomain('${item.id}')">Reset</button>` : "";
    return `<tr>
      <td><span class="domain-state ${stateClass}">${esc(domainStatusLabel(status))}</span></td>
      <td><div class="mono domain-name">${esc(item.domain)}</div><div class="domain-meta">${esc(item.source || "panel")}</div></td>
      <td>${esc(item.provider_label || item.provider || "")}</td>
      <td class="mono">${counts}</td>
      <td title="${esc(item.last_error || "")}">${esc(latest)}</td>
    <td><input class="domain-toggle" type="checkbox" aria-label="Aktifkan ${esc(item.domain)}" ${item.enabled ? "checked" : ""} onchange="setEmailDomainEnabled('${item.id}', this.checked)"/></td>
    <td><div class="domain-actions">${resetButton}<button class="danger" onclick="deleteEmailDomain('${item.id}')">Hapus</button></div></td>
    </tr>`;
  }).join("") : '<tr><td colspan="7" class="domain-empty">Domain pool kosong, bisa import domain atau subdomain sendiri di atas</td></tr>';
}
async function refreshEmailDomains(authHelp = false) {
  try {
    const data = await api("/api/email-domains?_=" + Date.now(), { authHelp });
    renderEmailDomainPool(data);
    if (!data.ok && data.error) setMsg("domain-msg", data.error, "err");
  } catch (e) {
    const message = String(e.message || e);
  document.getElementById("domain-updated").textContent = message.includes("token") ? "Menunggu token" : "Gagal membaca";
    setMsg("domain-msg", message, "err");
  }
}
function domainImportMessage(result) {
  const errors = result.errors || [];
  const errorText = errors.length ? (", lewati " + errors.length + " item: " + errors.slice(0, 2).map(item => "baris " + item.line + " " + item.error).join("; ")) : "";
  return "Berhasil import " + (result.imported_count || 0) + " domain, duplikat " + (result.duplicate_count || 0) + " domain" + errorText;
}
async function importDomainInput() {
  const input = document.getElementById("domain-input");
  const button = document.getElementById("domain-import-button");
  const value = (input.value || "").trim();
  if (!value) { setMsg("domain-msg", "Masukkan minimal satu domain", "err"); input.focus(); return; }
  button.disabled = true;
  setMsg("domain-msg", "Mengimport...", "");
  try {
    const result = await api("/api/email-domains/import", { method: "POST", body: JSON.stringify({ domains: value, provider: document.getElementById("domain-provider").value }) });
    renderEmailDomainPool(result);
    input.value = "";
    setMsg("domain-msg", domainImportMessage(result), result.errors && result.errors.length ? "" : "ok");
  } catch (e) { setMsg("domain-msg", String(e.message || e), "err"); }
  button.disabled = false;
}
async function saveDomainSettings() {
  const button = document.getElementById("domain-settings-button");
  button.disabled = true;
  try {
    const result = await api("/api/email-domains/settings", { method: "POST", body: JSON.stringify({
      failure_threshold: Number(document.getElementById("domain-threshold").value || 3),
      max_active_domains: Number(document.getElementById("domain-max-active").value || 0),
    }) });
    renderEmailDomainPool(result);
  setMsg("domain-msg", "Aturan domain pool tersimpan", "ok");
  } catch (e) { setMsg("domain-msg", String(e.message || e), "err"); }
  button.disabled = false;
}
async function setEmailDomainEnabled(id, enabled) {
  try {
    const result = await api("/api/email-domains/" + id, { method: "PATCH", body: JSON.stringify({ enabled }) });
    renderEmailDomainPool(result);
  setMsg("domain-msg", enabled ? "Domain diaktifkan" : "Domain dinonaktifkan", "ok");
  } catch (e) {
    setMsg("domain-msg", String(e.message || e), "err");
    await refreshEmailDomains(false);
  }
}
async function resetEmailDomain(id) {
  try {
    const result = await api("/api/email-domains/reset", { method: "POST", body: JSON.stringify({ id }) });
    renderEmailDomainPool(result);
  setMsg("domain-msg", "Hitungan gagal domain direset", "ok");
  } catch (e) { setMsg("domain-msg", String(e.message || e), "err"); }
}
async function deleteEmailDomain(id) {
  const item = (domainData && domainData.items || []).find(value => value.id === id);
  if (!confirm("Hapus domain " + (item ? item.domain : "") + "?")) return;
  try {
    const result = await api("/api/email-domains/" + id, { method: "DELETE" });
    renderEmailDomainPool(result);
  setMsg("domain-msg", "Domain dihapus", "ok");
  } catch (e) { setMsg("domain-msg", String(e.message || e), "err"); }
}
async function refresh() {
  try {
    const d = await api("/api/status?_=" + Date.now(), { authHelp: false });
    last = d;
    render(d);
  } catch (e) {
    const message = String(e.message || e);
  document.getElementById("clock").textContent = message.includes("token") ? "Butuh token" : "Koneksi bermasalah";
    const sync = document.getElementById("sync-label");
    if (sync) {
  sync.textContent = message.includes("token") ? "Menunggu token" : "Gagal update";
      sync.className = "badge fail";
    }
  if (message.includes("token")) setMsg("ctrl-msg", message, "err");
  }
}
function fillControl(d) {
  const c = d.control || {};
  if (document.activeElement && ["workers-input","batch_count","add_count","risk_pause","mode"].includes(document.activeElement.id)) return;
  if (c.workers != null) document.getElementById("workers-input").value = c.workers;
  if (c.batch_count != null) document.getElementById("batch_count").value = c.batch_count;
  if (c.add_count != null && document.getElementById("add_count")) document.getElementById("add_count").value = c.add_count;
  if (c.risk_pause != null) document.getElementById("risk_pause").value = c.risk_pause;
  if (c.mode) document.getElementById("mode").value = c.mode;
}
function controlBody() {
  return {
    workers: Number(document.getElementById("workers-input").value || 3),
    batch_count: Number(document.getElementById("batch_count").value || 40),
    add_count: Number((document.getElementById("add_count") || {}).value || 40),
    risk_pause: Number(document.getElementById("risk_pause").value || 10),
    mode: document.getElementById("mode").value || "orch",
  };
}
async function saveCtrl() {
  try {
    const j = await api("/api/control", { method: "POST", body: JSON.stringify(controlBody()) });
  setMsg("ctrl-msg", "Pengaturan tersimpan, worker " + j.workers, "ok");
  } catch (e) { setMsg("ctrl-msg", String(e.message || e), "err"); }
}
async function doStart() {
  document.getElementById("btn-start").disabled = true;
  setMsg("ctrl-msg", "Memulai...", "");
  try {
    await api("/api/control", { method: "POST", body: JSON.stringify(controlBody()) });
    const j = await api("/api/start", { method: "POST", body: JSON.stringify(controlBody()) });
    if (j.ok === false) throw new Error(j.error || "start failed");
  const msg = j.message || ("Dimulai, proses " + (j.pid || "?") + ", mode " + (j.mode || ""));
  setMsg("ctrl-msg", msg + (j.need != null ? ", sisa " + j.need : ""), "ok");
    setTimeout(refresh, 1000);
    setTimeout(refresh, 3000);
  } catch (e) { setMsg("ctrl-msg", String(e.message || e), "err"); }
  document.getElementById("btn-start").disabled = false;
}
async function doStop() {
  document.getElementById("btn-stop").disabled = true;
  try {
    const j = await api("/api/stop", { method: "POST", body: "{}" });
  setMsg("ctrl-msg", "Dihentikan killed=" + JSON.stringify(j.killed || []), "ok");
    setTimeout(refresh, 800);
  } catch (e) { setMsg("ctrl-msg", String(e.message || e), "err"); }
  document.getElementById("btn-stop").disabled = false;
}
async function resetBlacklist(mode) {
  mode = mode || "baseline";
  if (!confirm(mode === "empty" ? "Kosongkan semua blacklist?" : "Reset ke baseline circuit-breaker?")) return;
  try {
    const j = await api("/api/blacklist/reset", { method: "POST", body: JSON.stringify({ mode }) });
  setMsg("bl-msg", j.message || "Direset", "ok");
    setTimeout(refresh, 500);
  } catch (e) { setMsg("bl-msg", String(e.message || e), "err"); }
}
async function refreshBlacklist() {
  try {
    const j = await api("/api/blacklist?_=" + Date.now());
    renderBlacklist(j, last && last.blacklist_update);
  setMsg("bl-msg", "Di-refresh / " + (j.mtime_human || "") + " / " + (j.count || 0) + " ASN", "ok");
  } catch (e) { setMsg("bl-msg", String(e.message || e), "err"); }
}
async function refreshStats(authHelp = true) {
  try {
    const j = await api("/api/stats?_=" + Date.now(), { authHelp });
    renderStats(j);
  setMsg("stats-msg", "Statistik di-refresh " + (j.refreshed_at || ""), "ok");
  } catch (e) { setMsg("stats-msg", String(e.message || e), "err"); }
}
function renderRecovery(data) {
  data = data || {};
  const report = data.last_report || {};
  document.getElementById("recovery-kpis").innerHTML = [
      ["Pending", data.pending_count ?? 0, (data.pending_count || 0) > 0 ? "warn" : "ok"],
      ["Catatan Akun", data.account_record_count ?? 0, ""],
      ["Bisa Direcover", data.recoverable_count ?? 0, (data.recoverable_count || 0) > 0 ? "accent" : "ok"],
      ["Sukses Terakhir", report.success_count ?? "--", "ok"],
      ["Gagal Terakhir", report.failure_count ?? "--", (report.failure_count || 0) > 0 ? "fail" : ""],
  ].map(([label, value, cls]) => `<div class="chip"><span>${esc(label)}</span><b class="${cls}">${esc(value)}</b></div>`).join("");
  document.getElementById("recovery-status").textContent = data.running ? ("Recovery #" + (data.pid || "?")) : "Idle";
  document.getElementById("recovery-pending").disabled = !!data.running || !(data.pending_count > 0);
  document.getElementById("recovery-accounts").disabled = !!data.running || !(data.recoverable_count > 0);
  document.getElementById("recovery-stop").disabled = !data.running;
}
async function refreshRecovery() {
  try {
    const data = await api("/api/recovery?_=" + Date.now(), { authHelp: false });
    renderRecovery(data);
  } catch (e) {
    const message = String(e.message || e);
  document.getElementById("recovery-status").textContent = message.includes("token") ? "Menunggu token" : "Gagal cek";
  }
}
async function startRecovery(scope) {
  if (scope === "accounts" && !confirm("Scan semua file akun dan recover CPA yang hilang? Ini bisa memakan waktu lama.")) return;
  setMsg("recovery-msg", "Memulai recovery...", "");
  try {
    const data = await api("/api/recovery/start", { method: "POST", body: JSON.stringify({ scope }) });
  setMsg("recovery-msg", "Recovery dimulai, total " + (data.input_count || 0) + " item", "ok");
    await refreshRecovery();
  } catch (e) { setMsg("recovery-msg", String(e.message || e), "err"); }
}
async function stopRecovery() {
  try {
    const data = await api("/api/recovery/stop", { method: "POST", body: "{}" });
  setMsg("recovery-msg", "Recovery dihentikan, proses diakhiri " + JSON.stringify(data.killed || []), "ok");
    await refreshRecovery();
  } catch (e) { setMsg("recovery-msg", String(e.message || e), "err"); }
}
function renderBlacklist(bl, upd) {
  bl = bl || {};
  upd = upd || {};
  document.getElementById("bl-kpis").innerHTML = [
      ["Jumlah ASN", bl.count ?? 0, "accent"],
      ["Keyword ISP", (bl.isp_keywords || []).length, ""],
      ["Error Parse", (bl.errors || []).length, (bl.errors || []).length ? "fail" : "ok"],
  ].map(([l,v,c]) => `<div class="chip"><span>${esc(l)}</span><b class="${c}">${esc(v)}</b></div>`).join("");
  document.getElementById("bl-body").innerHTML = (bl.items || []).map(i =>
    `<tr><td class="mono">AS${esc(i.asn)}</td><td>${esc(i.note || "")}</td></tr>`
  ).join("") || '<tr><td colspan="2" style="color:var(--muted)">Kosong</td></tr>';
  document.getElementById("bl-err-chips").innerHTML = [
      ["Total Error Update", upd.error_count ?? 0, (upd.error_count ? "fail" : "ok")],
      ["Lookup Gagal", upd.lookup_fail_count ?? 0, "warn"],
      ["Error Analisis", upd.analyze_error_count ?? 0, "warn"],
      ["Jumlah Pause Blacklist", upd.hit_pause_count ?? 0, ""],
      ["Riwayat Penambahan", upd.added_total ?? 0, "accent"],
  ].map(([l,v,c]) => `<div class="chip"><span>${esc(l)}</span><b class="${c}">${esc(v)}</b></div>`).join("");
  document.getElementById("bl-added").innerHTML = (upd.recent_added || []).slice().reverse().map(a =>
    `<tr><td class="mono">AS${esc(a.asn)}</td><td class="mono">${esc(a.log || "")}</td></tr>`
  ).join("") || '<tr><td colspan="2" style="color:var(--muted)">Belum ada penambahan otomatis</td></tr>';
}

function rateCls(r) {
  if (r == null) return "";
  if (r >= 70) return "ok";
  if (r >= 40) return "warn";
  return "fail";
}
function renderBatchLive(bl) {
  bl = bl || {};
  const set = (id, val, cls) => {
    const el = document.getElementById(id);
    if (el) { el.textContent = (val == null || val === "") ? "--" : String(val); if (cls) el.className = "value " + cls; }
  };
  set("bl-target", bl.target ?? "--");
  set("bl-completed", bl.completed ?? "--", "ok");
  set("bl-remaining", bl.remaining ?? "--");
  set("bl-workers", bl.workers ?? "--");
  set("bl-batch-id", (bl.batch_id || "--").toString().slice(0, 20));
  const running = !!bl.running;
  set("bl-running", bl.exists ? (running ? "Jalan" : "Berhenti") : "Tidak ada", running ? "ok" : (bl.exists ? "warn" : ""));
  const meta = document.getElementById("batch-live-meta");
  if (meta) {
    meta.textContent = bl.exists
      ? (running ? "berjalan · update " + (bl.running_age_s ?? 0) + "s lalu" : "terakhir " + (bl.running_age_s ?? 0) + "s lalu")
      : "belum ada batch state";
  }
  const bar = document.getElementById("bl-bar");
  if (bar) { const pct = Math.min(100, Number(bl.pct) || 0); bar.style.width = pct + "%"; }
  const sub = document.getElementById("bl-prog-sub");
  if (sub) sub.textContent = bl.exists
    ? (bl.completed ?? 0) + " / " + (bl.target ?? 0) + " (" + (bl.pct ?? 0) + "%) · sisa " + (bl.remaining ?? 0)
    : "Jalankan batch dulu (gro_register_to_9router.py) untuk melihat progress";
}
function renderRates(rates) {
  rates = rates || {};
  const order = ["1h", "3h", "12h"];
  const labels = { "1h": "1 jam terakhir", "3h": "3 jam terakhir", "12h": "12 jam terakhir" };
  const cards = order.map(k => {
    const b = rates[k] || {};
    const r = b.success_rate;
    const val = r == null ? "--" : (r + "%");
    return `<div class="rate-item">
      <div class="rate-top">
        <span class="rate-label">${esc(labels[k] || k)}</span>
        <span class="rate-total">${b.total ?? 0} kali</span>
      </div>
      <div class="rate-value ${rateCls(r)}">${esc(val)}</div>
      <div class="rate-breakdown">
        <span class="ok">Sukses ${b.ok ?? 0}</span>
        <span class="fail">Gagal ${b.fail ?? 0}</span>
        <span class="warn">Risk ${b.risk ?? 0}</span>
      </div>
    </div>`;
  });
  const el = document.getElementById("rate-kpis");
  if (el) el.innerHTML = cards.join("");
}

function renderStats(s) {
  s = s || {};
  if (s.rates) renderRates(s.rates);
  document.getElementById("stats-chips").innerHTML = [
    ["CPA", s.cpa ?? "--", "accent"],
      ["Perubahan CPA", s.cpa_delta ?? "--", "ok"],
      ["Sukses Batch Ini", s.batch_ok ?? 0, "ok"],
      ["Gagal Batch Ini", s.batch_fail ?? 0, "fail"],
    ["jsonl ok", s.jsonl_ok ?? 0, "ok"],
    ["jsonl risk", s.jsonl_risk ?? 0, "warn"],
  ].map(([l,v,c]) => `<div class="chip"><span>${esc(l)}</span><b class="${c}">${esc(v)}</b></div>`).join("");
  const days = Object.entries(s.by_day || {}).sort((a,b) => b[0].localeCompare(a[0])).slice(0, 10);
  document.getElementById("stats-day").innerHTML = days.length ? days.map(([d, v]) =>
    `<tr><td class="mono">${esc(d)}</td><td class="ok">${v.ok||0}</td><td class="warn">${v.risk||0}</td><td class="fail">${v.fail||0}</td></tr>`
  ).join("") : '<tr><td colspan="4" style="color:var(--muted)">Tidak ada data jsonl</td></tr>';
}
function render(d) {
  document.getElementById("clock").textContent = d.ts_human || "--";
  document.getElementById("logname").textContent =
    (d.log_name || d.log || "--") + (d.process && d.process.etime ? " / durasi " + d.process.etime : "");
  const on = !!(d.process && d.process.running);
  document.getElementById("run-dot").className = "dot " + (on ? "on" : (d.ended ? "done" : "off"));
  let runLabel = "Dihentikan";
  if (d.process && d.process.orch_running) runLabel = "Orkestrasi #" + d.process.orch_pid;
  else if (d.process && d.process.batch_running) runLabel = "Batch #" + d.process.batch_pid;
  else if (d.ended) runLabel = "Selesai";
  document.getElementById("run-label").textContent = runLabel;
  document.getElementById("run-status").setAttribute("aria-label", "Status tugas:" + runLabel);
  const sync = document.getElementById("sync-label");
  if (sync) {
    sync.textContent = "Update Real-time";
    sync.className = "badge";
  }
  document.getElementById("ctrl-status").textContent = on ? "Berjalan" : "Idle";
  document.getElementById("btn-start").disabled = on;
  document.getElementById("btn-stop").disabled = !on;
  fillControl(d);

  const kpis = [
      ["Sukses Batch Ini", d.ok ?? 0, "ok", "Target " + (d.target ?? "--")],
      ["Gagal Batch Ini", d.fail ?? 0, "fail", d.success_rate != null ? "Success rate " + d.success_rate + "%" : "Belum ada data"],
      ["Total CPA", d.cpa ?? "--", "accent", "vs baseline " + (d.cpa_delta != null ? ((Number(d.cpa_delta) >= 0 ? "+" : "") + d.cpa_delta) : "--")],
      ["Normal / Risk", (d.bot0 ?? 0) + " / " + (d.bot1 ?? 0), (d.bot1 ?? 0) > 0 ? "warn" : "ok", "Sampel hasil registrasi"],
      ["Blacklist ASN", (d.blacklist && d.blacklist.count) ?? "--", "accent", "Error update " + ((d.blacklist_update && d.blacklist_update.error_count) ?? 0)],
      ["Perkiraan Selesai", d.ended ? "Selesai" : (d.eta || "--"), "", "Worker " + (d.workers ?? "--") + (d.rate_per_min != null ? " / " + d.rate_per_min + " per menit" : "")],
  ];
  document.getElementById("kpis").innerHTML = kpis.map(([label, val, cls, sub]) =>
    `<div class="metric"><div class="label">${esc(label)}</div><div class="value ${cls}">${esc(val)}</div><div class="sub">${esc(sub)}</div></div>`
  ).join("");
  renderBatchLive(d.batch_live || {});
  renderRates(d.rates || {});
  const ru = document.getElementById("rates-updated");
  if (ru && d.ts_human) ru.textContent = "Data diupdate " + d.ts_human;

  const pct = Math.min(100, Number(d.progress_pct) || 0);
  document.getElementById("bar").style.width = pct + "%";
  document.getElementById("prog-text").textContent = (d.ok ?? 0) + " / " + (d.target ?? 0) + " (" + pct + "%)";
  document.getElementById("prog-sub").textContent =
    "Percobaan " + (d.done_attempts ?? 0) + " / " + (on ? "proses berjalan" : "tidak berjalan")
    + (d.ended ? " / Selesai: sukses " + d.ended.success + ", gagal " + d.ended.fail : "");

  renderBlacklist(d.blacklist, d.blacklist_update);
  // light stats from snapshot
  renderStats({
    cpa: d.cpa, cpa_delta: d.cpa_delta, base_cpa: d.base_cpa,
    batch_ok: d.ok, batch_fail: d.fail,
    jsonl_ok: "--", jsonl_risk: "--",
    by_day: {}, refreshed_at: d.ts_human,
  });

  const wset = new Set([...(Object.keys(d.worker_ok || {})), ...(Object.keys(d.worker_fail || {}))]);
  const ws = [...wset].sort((a, b) => parseInt(a.slice(1)) - parseInt(b.slice(1)));
  document.getElementById("workers-stats").innerHTML = ws.length ? ws.map(w =>
    `<div class="chip"><span>${esc(w)}</span><b><span class="ok">${d.worker_ok && d.worker_ok[w] || 0}</span> <span style="color:var(--muted)">/</span> <span class="fail">${d.worker_fail && d.worker_fail[w] || 0}</span></b></div>`
  ).join("") : '<span style="color:var(--muted)">Belum ada</span>';
  const fk = Object.entries(d.fail_kinds || {}).sort((a, b) => b[1] - a[1]);
  document.getElementById("fails").innerHTML = fk.length ? fk.map(([k, v]) =>
    `<div class="chip"><span>${esc(k)}</span><b class="fail">${v}</b></div>`
  ).join("") : '<span style="color:var(--muted)">Belum ada gagal</span>';
  document.getElementById("ok-body").innerHTML = (d.recent_ok || []).map(r =>
    `<tr><td class="mono">${esc(r.t)}</td><td>${esc(r.w)}</td><td class="mono">${esc(r.email)}</td></tr>`
  ).join("") || '<tr><td colspan="3" style="color:var(--muted)">Belum ada catatan</td></tr>';
  document.getElementById("fail-body").innerHTML = (d.recent_fail || []).map(r =>
    `<tr><td class="mono">${esc(r.t)}</td><td>${esc(r.w)}</td><td>${esc(r.kind)}</td><td class="mono">${esc(r.msg)}</td></tr>`
  ).join("") || '<tr><td colspan="4" style="color:var(--muted)">Belum ada catatan</td></tr>';
  document.getElementById("tail").textContent = (d.tail || []).join("\n");
  document.getElementById("footer").textContent =
    "Server " + location.host + " / Log " + (d.log || "") + " / polling 2 detik / "
    + (d.log_size ? (d.log_size / 1024).toFixed(0) + " KB" : "0 KB")
    + " / Blacklist " + ((d.blacklist && d.blacklist.count) || 0) + " ASN";
}
syncThemeButtons();
initHelp();
loadTokenField();
refresh();
setInterval(refresh, 2000);
// full stats once on load
refreshStats(false);
refreshRecovery();
setInterval(refreshRecovery, 5000);
setInterval(() => {
  if (document.body.classList.contains("proxy-view-open")) refreshProxies(false);
  if (document.body.classList.contains("domain-view-open")) refreshEmailDomains(false);
}, 3000);
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "GrokRegister"
    sys_version = ""

    def version_string(self):
        return self.server_version

    def log_message(self, fmt, *args):
        msg = args[0] if args else ""
        if "/api/status" in str(msg):
            return
        super().log_message(fmt, *args)

    def _send(self, code, body, ctype):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        )
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'none'; object-src 'none'; "
            "frame-ancestors 'none'; form-action 'none'; img-src 'self' data:; "
            "font-src 'self'; connect-src 'self'; "
            "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'",
        )
        # No wildcard CORS — panel is same-origin. Optional explicit origin via env.
        allow = str(os.environ.get("MONITOR_CORS_ORIGIN", "") or "").strip()
        if allow and allow != "*":
            self.send_header("Access-Control-Allow-Origin", allow)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(body)

    def _auth_header(self) -> str:
        return (
            self.headers.get("Authorization")
            or self.headers.get("X-Monitor-Token")
            or ""
        )

    def _require_write(self) -> bool:
        if check_token_optional_read(self._auth_header(), write=True):
            return True
        self._json(401, {"ok": False, "error": "unauthorized: set MONITOR_TOKEN and pass Authorization: Bearer <token>"})
        return False

    def _require_read(self) -> bool:
        if check_token_optional_read(self._auth_header(), write=False):
            return True
        self._json(401, {"ok": False, "error": "unauthorized: enter the current monitor token"})
        return False

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"), "application/json; charset=utf-8")

    def _read_body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if n <= 0:
            return {}
        if n > MAX_REQUEST_BODY:
            raise OverflowError("request body too large")
        raw = self.rfile.read(n)
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except Exception as exc:
            raise ValueError("invalid JSON body") from exc
        if not isinstance(body, dict):
            raise ValueError("JSON body must be an object")
        return body

    def do_OPTIONS(self):
        self._send(204, b"", "text/plain")

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            self._send(200, HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if u.path in FONT_ASSETS:
            path = FONT_ASSETS[u.path]
            if path.is_file():
                self._send(200, path.read_bytes(), "font/woff2")
            else:
                self._send(404, b"not found", "text/plain")
            return
        if u.path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
            return
        if u.path == "/api/health":
            self._json(200, {"ok": True})
            return
        if u.path in ("/api/status", "/api/batch-live", "/api/blacklist", "/api/stats", "/api/control", "/api/recovery", "/api/proxies", "/api/email-provider", "/api/email-domains"):
            if not self._require_read():
                return
        if u.path == "/api/status":
            try:
                self._json(200, snapshot())
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/batch-live":
            try:
                self._json(200, read_batch_state_live())
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/blacklist":
            try:
                bl = read_blacklist()
                bl["update"] = blacklist_update_errors()
                self._json(200, bl)
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/stats":
            try:
                self._json(200, success_stats())
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/control":
            self._json(200, load_control())
            return
        if u.path == "/api/recovery":
            try:
                self._json(200, recovery_status())
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
            return
        if u.path == "/api/proxies":
            try:
                self._json(200, read_proxy_pool())
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-provider":
            try:
                self._json(200, read_email_provider_config())
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-domains":
            try:
                self._json(200, read_email_domain_pool())
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        self._send(404, b"not found", "text/plain")

    def do_POST(self):
        u = urlparse(self.path)
        # All POST endpoints require MONITOR_TOKEN
        if not self._require_write():
            return
        try:
            body = self._read_body()
        except OverflowError as exc:
            self._json(413, {"ok": False, "error": str(exc)})
            return
        except ValueError as exc:
            self._json(400, {"ok": False, "error": str(exc)})
            return
        if u.path == "/api/control":
            try:
                self._json(200, save_control(body))
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/start":
            try:
                if body:
                    save_control(body)
                mode = (body or {}).get("mode") or load_control().get("mode") or "orch"
                if mode == "batch":
                    self._json(200, start_batch_only())
                else:
                    self._json(200, start_orch())
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/stop":
            try:
                self._json(200, kill_all())
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/recovery/start":
            try:
                with START_LOCK:
                    result = start_recovery((body or {}).get("scope") or "pending")
                self._json(200 if result.get("ok") else 409, result)
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
            return
        if u.path == "/api/recovery/stop":
            try:
                self._json(200, stop_recovery())
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
            return
        if u.path == "/api/proxies/import":
            try:
                if body.get("legacy") is True:
                    result = import_legacy_proxies()
                else:
                    result = import_proxies(body.get("proxies"), source="panel")
                self._json(200 if result.get("ok") else 400, result)
            except Exception as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/proxies/test":
            try:
                result = start_proxy_tests(body.get("ids"))
                if result.get("ok"):
                    code = 202
                elif result.get("running"):
                    code = 409
                else:
                    code = 400
                self._json(code, result)
            except Exception as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-provider":
            try:
                result = save_email_provider_config(
                    body.get("provider"),
                    body.get("settings") or {},
                    clear_secrets=body.get("clear_secrets"),
                )
                self._json(200, result)
            except ValueError as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-provider/test":
            try:
                result = test_email_provider_config(
                    body.get("provider"),
                    body.get("settings") or {},
                    clear_secrets=body.get("clear_secrets"),
                )
                self._json(200 if result.get("ok") else 424, result)
            except ValueError as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-domains/import":
            try:
                result = import_domains(
                    body.get("domains"),
                    body.get("provider"),
                    source="panel",
                )
                self._json(200 if result.get("ok") else 400, result)
            except Exception as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-domains/settings":
            try:
                result = update_email_domain_settings(
                    failure_threshold=body.get("failure_threshold"),
                    max_active_domains=body.get("max_active_domains"),
                )
                self._json(200, result)
            except ValueError as e:
                self._json(400, {"ok": False, "error": redact_log_line(str(e))})
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/email-domains/reset":
            try:
                result = reset_domain(body.get("id"))
                self._json(200 if result.get("ok", True) else 404, result)
            except Exception as e:
                self._json(500, {"ok": False, "error": redact_log_line(str(e))})
            return
        if u.path == "/api/blacklist/refresh":
            try:
                bl = read_blacklist()
                bl["update"] = blacklist_update_errors()
                self._json(200, bl)
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        if u.path == "/api/blacklist/reset":
            try:
                from webui.blacklist_ops import reset_blacklist as _reset_bl
            except ImportError:
                try:
                    from blacklist_ops import reset_blacklist as _reset_bl  # type: ignore
                except ImportError:
                    _reset_bl = None
            if _reset_bl is None:
                self._json(501, {"ok": False, "error": "blacklist_ops unavailable"})
                return
            try:
                mode = (body or {}).get("mode") or "baseline"
                self._json(200, _reset_bl(mode))
            except Exception as e:
                self._json(500, {"ok": False, "error": str(e)})
            return
        if u.path == "/api/stats/refresh":
            try:
                self._json(200, success_stats())
            except Exception as e:
                self._json(500, {"error": str(e)})
            return
        self._send(404, b"not found", "text/plain")

    def do_PATCH(self):
        u = urlparse(self.path)
        proxy_match = re.fullmatch(r"/api/proxies/([a-f0-9]{20})", u.path)
        domain_match = re.fullmatch(r"/api/email-domains/([a-f0-9]{20})", u.path)
        if proxy_match is None and domain_match is None:
            self._send(404, b"not found", "text/plain")
            return
        if not self._require_write():
            return
        try:
            body = self._read_body()
        except OverflowError as exc:
            self._json(413, {"ok": False, "error": str(exc)})
            return
        except ValueError as exc:
            self._json(400, {"ok": False, "error": str(exc)})
            return
        try:
            if proxy_match is not None:
                result = update_proxy(proxy_match.group(1), enabled=body.get("enabled"))
            else:
                result = update_domain(domain_match.group(1), enabled=body.get("enabled"))
            self._json(200 if result.get("ok") else 404, result)
        except ValueError as exc:
            self._json(400, {"ok": False, "error": redact_log_line(str(exc))})
        except Exception as exc:
            self._json(500, {"ok": False, "error": redact_log_line(str(exc))})

    def do_DELETE(self):
        u = urlparse(self.path)
        proxy_match = re.fullmatch(r"/api/proxies/([a-f0-9]{20})", u.path)
        domain_match = re.fullmatch(r"/api/email-domains/([a-f0-9]{20})", u.path)
        if proxy_match is None and domain_match is None:
            self._send(404, b"not found", "text/plain")
            return
        if not self._require_write():
            return
        try:
            result = (
                delete_proxy(proxy_match.group(1))
                if proxy_match is not None
                else delete_domain(domain_match.group(1))
            )
            self._json(200 if result.get("ok") else 404, result)
        except Exception as exc:
            self._json(500, {"ok": False, "error": redact_log_line(str(exc))})


def main():
    host = BIND_HOST
    tok = expected_token()
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host.strip().lower() == "localhost"
    if not tok and not loopback:
        raise SystemExit(
            "MONITOR_TOKEN is required when MONITOR_HOST is not loopback"
        )
    ThreadingHTTPServer.allow_reuse_address = True
    try:
        httpd = ThreadingHTTPServer((host, BIND_PORT), Handler)
    except OSError as e1:
        raise SystemExit(
            f"cannot bind {BIND_HOST}:{BIND_PORT} ({e1}); "
            "set MONITOR_HOST/MONITOR_PORT (no 0.0.0.0 fallback)"
        )
    if not tok:
        print(
            "[monitor] WARNING: MONITOR_TOKEN unset — write APIs (start/stop/control) will return 401",
            flush=True,
        )
    print(f"[monitor] http://{host}:{BIND_PORT}/  (bound {host}:{BIND_PORT})", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
