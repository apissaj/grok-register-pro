"""
GroRegto9Router — Register Grok + Auto-Inject to 9Router & grok2api.

Usage:
    python scripts/gro_register_to_9router.py [--count N] [--workers W]
        [--adaptive] [--worker-timeout SEC] [--mid-inject]
        [--preflight-only] [--no-preflight] [--inject-only]

Workflow:
    0. Preflight (CloudMail, 9Router DB, venv python, optional grok2api)
    1. Run grok-register CLI to create account(s) (with optional multi-worker)
    2. Parse accounts file → inject SSO tokens to grok2api (via admin API)
    3. Parse CPA credentials → inject to 9Router DB as grok-cli
    4. Summary report

During multi-worker runs:
    - Live progress board every 15s
    - Per-worker hang timeout (default 300s no output → kill)
    - Mid-batch inject of new CPA/SSO every 60s

Files:
    - grok-register/config.json    — Tempik provider config
    - grok-register/cpa_auths/     — CPA credentials (written by grok-register)
    - grok-register/token.json     — SSO tokens (written by grok-register)
    - grok2api admin API           — Token pool management
    - 9router/db/data.sqlite       — providerConnections table
"""
import glob
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Local helpers (same scripts/ package dir)
_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)
try:
    from batch_progress import (  # type: ignore
            ProgressState,
            choose_workers,
            cpa_email_from_file,
            discover_cpa_files,
            discover_sso_tokens,
            start_progress_monitor,
            start_batch_progress_writer,
            stream_process_output,
        )
    from batch_state import (  # type: ignore
        clear_batch_state,
        load_batch_state,
        remaining,
        save_batch_state,
        update_batch_state,
    )
except ImportError:  # pragma: no cover - flat run fallback
    from scripts.batch_progress import (  # type: ignore
            ProgressState,
            choose_workers,
            cpa_email_from_file,
            discover_cpa_files,
            discover_sso_tokens,
            start_progress_monitor,
            start_batch_progress_writer,
            stream_process_output,
        )
    from scripts.batch_state import (  # type: ignore
        clear_batch_state,
        load_batch_state,
        remaining,
        save_batch_state,
        update_batch_state,
    )

# ─── Paths ───────────────────────────────────────────────────
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GROK_REGISTER_DIR = REPO

# 9Router DB
_NINE_ROUTER_CANDIDATES = [
    os.path.expandvars(r"%APPDATA%\9router\db\data.sqlite"),
    os.path.expandvars(r"%USERPROFILE%\AppData\Roaming\9router\db\data.sqlite"),
    os.path.normpath(os.path.join(REPO, "..", "Backup_Windows_Reinstall", "9router", "db", "data.sqlite")),
]
NINE_ROUTER_DB = ""
for _c in _NINE_ROUTER_CANDIDATES:
    if os.path.isfile(_c):
        NINE_ROUTER_DB = _c
        break
if not NINE_ROUTER_DB:
    NINE_ROUTER_DB = os.path.expandvars(r"%APPDATA%\9router\db\data.sqlite")

# grok2api
GROK2API_URL = "http://127.0.0.1:8000"
GROK2API_KEY = "grok2api"

GROK_REGISTER_SCRIPT = os.path.join(GROK_REGISTER_DIR, "grok_register_ttk.py")
CPA_AUTHS_DIR = os.path.join(GROK_REGISTER_DIR, "cpa_auths")
TOKEN_JSON = os.path.join(GROK_REGISTER_DIR, "token.json")
VENV_PYTHON = os.path.join(GROK_REGISTER_DIR, ".venv", "Scripts", "python.exe")

# WARP proxy (SOCKS5 via Cloudflare WARP client on port 40000)
# Set via --proxy argument or PROXY env var
WARP_PROXY = os.environ.get("PROXY", os.environ.get("HTTP_PROXY", ""))

# Hang timeout: env WORKER_ACCOUNT_TIMEOUT overrides CLI default
DEFAULT_WORKER_TIMEOUT = int(os.environ.get("WORKER_ACCOUNT_TIMEOUT", "300") or "300")
DEFAULT_PROGRESS_INTERVAL = 15.0
DEFAULT_MID_INJECT_INTERVAL = 60.0
MID_INJECT_CPA_THRESHOLD = 5
MAX_WORKERS = 8
ADAPTIVE_SOFT_CAP = 4
MAX_COUNT = 500


# ─── Helpers ─────────────────────────────────────────────────
def log(msg: str):
    print(f"  {msg}", flush=True)


def update_config_count(count: int) -> str:
    config_path = os.path.join(GROK_REGISTER_DIR, "config.json")
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    original = cfg.get("register_count", 1)
    cfg["register_count"] = count
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=4, ensure_ascii=False)
    return str(original)


def restore_config_count(original_count: str):
    config_path = os.path.join(GROK_REGISTER_DIR, "config.json")
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["register_count"] = int(original_count)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=4, ensure_ascii=False)



def _merge_tokens_into_main(sso_tokens: list[str], prefix: str = ""):
    """Atomically merge new SSO tokens into main token.json."""
    lock_path = TOKEN_JSON + ".lock"
    try:
        with open(lock_path, "w") as lf:
            try:
                import msvcrt
                msvcrt.locking(lf.fileno(), msvcrt.LK_NBLCK, 1)
            except (ImportError, OSError):
                pass
        main_data = {"ssoBasic": []}
        if os.path.isfile(TOKEN_JSON):
            try:
                with open(TOKEN_JSON, encoding="utf-8") as f:
                    main_data = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        existing = {e.get("token", "") for e in main_data.get("ssoBasic", [])}
        added = 0
        for tok in sso_tokens:
            if tok and tok not in existing:
                main_data.setdefault("ssoBasic", []).append({"token": tok, "email": ""})
                existing.add(tok)
                added += 1
        if added > 0:
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(TOKEN_JSON), suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(main_data, f, ensure_ascii=False, indent=2)
                os.replace(tmp, TOKEN_JSON)
            except OSError:
                try: os.unlink(tmp)
                except OSError: pass
            log(f"{prefix} Merged {added} tokens into main token.json")
    except Exception as e:
        log(f"{prefix} [WARN] token merge failed: {e}")


def _restart_grok2api():
    """Attempt to start/restart grok2api via granian. Non-blocking."""
    grok2api_dir = os.path.normpath(os.path.join(REPO, "..", "grok2api"))
    granian = os.path.join(grok2api_dir, ".venv", "Scripts", "granian.exe")
    if not os.path.isfile(granian):
        log("[WARN] granian.exe not found, cannot auto-start grok2api")
        return
    log("[INFO] Starting grok2api...")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    subprocess.Popen(
        [granian, "--interface", "asgi", "--host", "0.0.0.0", "--port", "8000",
         "--workers", "1", "app.main:app"],
        cwd=grok2api_dir, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    time.sleep(5)
    log("[INFO] grok2api started (waited 5s for port binding)")


# ─── Preflight ───────────────────────────────────────────────
def _http_json(
    method: str,
    url: str,
    body=None,
    timeout: float = 10.0,
    extra_headers: dict = None,
) -> dict:
    data = None
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        # Browser UA: Cloudflare-protected endpoints (mail.hafizhmuzani.my.id)
        # return 403/error 1010 when called without a browser User-Agent.
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        ),
    }
    if extra_headers:
        headers.update(extra_headers)
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        if not raw:
            return {}
        return json.loads(raw)


def run_preflight() -> list:
    """Check critical deps. Returns list of critical error strings. Prints OK/FAIL."""
    print(f"\n{'='*60}")
    print("[0/4] Preflight checks...")
    print(f"{'='*60}\n")
    errors = []
    warnings = []

    config_path = os.path.join(GROK_REGISTER_DIR, "config.json")
    cfg = {}
    try:
        with open(config_path, encoding="utf-8") as f:
            cfg = json.load(f)
        if not isinstance(cfg, dict):
            raise ValueError("config root is not an object")
        log("[OK] config.json loads")
    except Exception as e:
        msg = f"config.json load failed: {e}"
        log(f"[FAIL] {msg}")
        errors.append(msg)

    if os.path.isfile(VENV_PYTHON):
        log(f"[OK] VENV_PYTHON exists: {VENV_PYTHON}")
    else:
        msg = f"VENV_PYTHON missing: {VENV_PYTHON}"
        log(f"[FAIL] {msg}")
        errors.append(msg)

    if os.path.isfile(NINE_ROUTER_DB):
        writable = os.access(NINE_ROUTER_DB, os.W_OK)
        try:
            conn = sqlite3.connect(NINE_ROUTER_DB, timeout=3)
            conn.execute("SELECT 1")
            conn.close()
            db_ok = True
        except Exception as e:
            db_ok = False
            msg = f"9Router DB not readable: {e}"
            log(f"[FAIL] {msg}")
            errors.append(msg)
        if db_ok:
            if writable:
                log(f"[OK] 9Router DB exists/writable: {NINE_ROUTER_DB}")
            else:
                msg = f"9Router DB not writable: {NINE_ROUTER_DB}"
                log(f"[FAIL] {msg}")
                errors.append(msg)
    else:
        msg = f"9Router DB not found: {NINE_ROUTER_DB}"
        log(f"[FAIL] {msg}")
        errors.append(msg)

    provider = str(cfg.get("email_provider", "") or "").strip().lower()
    if provider == "cloudmail" or (not provider and cfg.get("cloudmail_url")):
        base = (
            str(cfg.get("cloudmail_url") or cfg.get("cloudmail_api_base") or "")
            .strip()
            .rstrip("/")
        )
        email = str(cfg.get("cloudmail_admin_email") or "").strip()
        password = str(cfg.get("cloudmail_password") or "").strip()
        if not base or not email or not password:
            msg = "CloudMail config incomplete (url/admin_email/password)"
            log(f"[FAIL] {msg}")
            errors.append(msg)
        else:
            try:
                # Preflight harus read-only: cek public token (tanpa KV write).
                # Login admin menulis auth-uid:* ke KV → bakar 1 write per batch
                # dan bisa kena "KV put() limit exceeded" saat KV penuh.
                pub_token = str(cfg.get("cloudmail_public_token") or "").strip()
                if not pub_token:
                    msg = "CloudMail public_token kosong (config.json)"
                    log(f"[FAIL] {msg}")
                    errors.append(msg)
                else:
                    result = _http_json(
                        "POST",
                        f"{base}/api/public/emailList",
                        {"size": 1},
                        extra_headers={"Authorization": pub_token},
                        timeout=12.0,
                    )
                    if isinstance(result, dict) and result.get("code") == 200:
                        log(f"[OK] CloudMail public token ({base})")
                    else:
                        msg = f"CloudMail public token invalid ({result!r})"
                        log(f"[FAIL] {msg}")
                        errors.append(msg)
            except Exception as e:
                msg = f"CloudMail login failed: {e}"
                log(f"[FAIL] {msg}")
                errors.append(msg)
    else:
        log(f"[OK] CloudMail check skipped (email_provider={provider or 'unset'})")

    try:
        req = urllib.request.Request(f"{GROK2API_URL}/admin/api/tokens?app_key={GROK2API_KEY}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read(64)
        log(f"[OK] grok2api reachable at {GROK2API_URL}")
    except Exception as e:
        w = f"grok2api unreachable ({e}) — SSO inject may fail (non-critical)"
        log(f"[WARN] {w}")
        warnings.append(w)

    camoufox = os.path.join(GROK_REGISTER_DIR, "camofox-browser")
    if os.path.isdir(camoufox) or os.path.isfile(
        os.path.join(GROK_REGISTER_DIR, "camoufox_adapter.py")
    ):
        log("[OK] camoufox/browser assets present")
    else:
        w = "camoufox assets not found (may still work via system browser)"
        log(f"[WARN] {w}")
        warnings.append(w)

    if errors:
        log(f"\nPreflight FAILED — {len(errors)} critical error(s)")
    else:
        log(f"\nPreflight OK ({len(warnings)} warning(s))")
    return errors


# ─── Mid-batch inject ────────────────────────────────────────
def mid_batch_inject(injected_cpa_emails: set, injected_sso: set, quiet: bool = False):
    """Scan worker temps + main cpa; inject new CPA/SSO. Returns (cpa_new, sso_new)."""
    tmp = tempfile.gettempdir()
    cpa_files = discover_cpa_files(tmp, CPA_AUTHS_DIR)
    new_cpa = []
    for path in cpa_files:
        email = cpa_email_from_file(path)
        if email and email not in injected_cpa_emails:
            new_cpa.append(path)

    cpa_new = 0
    if new_cpa:
        if not quiet:
            log(f"[mid-inject] {len(new_cpa)} new CPA file(s)")
        cpa_new = inject_cpa_to_9router(new_cpa, banner=False)
        for path in new_cpa:
            email = cpa_email_from_file(path)
            if email:
                injected_cpa_emails.add(email)

    sso_tokens = discover_sso_tokens(tmp, TOKEN_JSON)
    new_sso = [t for t in sso_tokens if t and t not in injected_sso]
    sso_new = 0
    if new_sso:
        if not quiet:
            log(f"[mid-inject] {len(new_sso)} new SSO token(s)")
        _merge_tokens_into_main(new_sso, prefix="[mid-inject]")
        sso_new = inject_sso_to_grok2api(new_sso, banner=False)
        for t in new_sso:
            injected_sso.add(t)

    return cpa_new, sso_new


def _start_mid_inject_monitor(stop_event, injected_cpa, injected_sso, interval=DEFAULT_MID_INJECT_INTERVAL):
    last_cpa_count = 0

    def _run():
        nonlocal last_cpa_count
        while not stop_event.wait(timeout=max(5.0, float(interval))):
            try:
                tmp = tempfile.gettempdir()
                all_cpa = discover_cpa_files(tmp, CPA_AUTHS_DIR)
                pending = [p for p in all_cpa if cpa_email_from_file(p) not in injected_cpa]
                if len(pending) >= MID_INJECT_CPA_THRESHOLD or pending or len(all_cpa) != last_cpa_count:
                    cpa_n, sso_n = mid_batch_inject(injected_cpa, injected_sso)
                    last_cpa_count = len(all_cpa)
                    if cpa_n or sso_n:
                        log(f"[mid-inject] done — CPA+{cpa_n} SSO+{sso_n}")
            except Exception as e:
                log(f"[mid-inject] WARN: {e}")

    t = threading.Thread(target=_run, name="mid-inject", daemon=True)
    t.start()
    return t


# ─── Worker Setup ────────────────────────────────────────────
def create_worker_dir(worker_id: int, count: int) -> str:
    """Create a temp working directory for a worker with its own config/token/cpa."""
    workdir = os.path.join(tempfile.gettempdir(), f"grok_worker_{worker_id}")
    os.makedirs(workdir, exist_ok=True)

    # Copy config.json with adjusted count
    with open(os.path.join(GROK_REGISTER_DIR, "config.json"), "r", encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["register_count"] = count
    with open(os.path.join(workdir, "config.json"), "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=4, ensure_ascii=False)

    # Create empty token.json
    with open(os.path.join(workdir, "token.json"), "w", encoding="utf-8") as f:
        json.dump({"ssoBasic": []}, f)

    # Create empty cpa_auths dir
    os.makedirs(os.path.join(workdir, "cpa_auths"), exist_ok=True)

    # Copy ALL local Python modules + compiled/asset files that grok-register
    # may import — tolerate additions in the future (glob instead of list).
    for fname in sorted(set(
        [p.name for p in Path(GROK_REGISTER_DIR).glob("*.py")]
        + ["grok_core.pyd", "human.pyd", "cloudflare_turnstile", "config.json"]
    )):
        src = os.path.join(GROK_REGISTER_DIR, fname)
        dst = os.path.join(workdir, fname)
        if not os.path.exists(src) or os.path.exists(dst):
            continue
        try:
            # Files: try hard link first (fast), fallback to copy
            os.link(src, dst)
        except OSError:
            try:
                shutil.copy2(src, dst)
            except (PermissionError, OSError):
                log(f"[WARN] Could not link {fname}, skipping")

    # email_providers package — required for email OTP (tempik/duckmail/etc.)
    src_ep = os.path.join(GROK_REGISTER_DIR, "email_providers")
    dst_ep = os.path.join(workdir, "email_providers")
    if os.path.isdir(src_ep) and not os.path.exists(dst_ep):
        try:
            shutil.copytree(src_ep, dst_ep, ignore=shutil.ignore_patterns("__pycache__"))
        except (PermissionError, OSError) as exc:
            log(f"[WARN] Could not copy email_providers: {exc}")

    # webui package — imported by browser_session.py (blacklist, etc.)
    src_wui = os.path.join(GROK_REGISTER_DIR, "webui")
    dst_wui = os.path.join(workdir, "webui")
    if os.path.isdir(src_wui) and not os.path.exists(dst_wui):
        try:
            shutil.copytree(src_wui, dst_wui, ignore=shutil.ignore_patterns("__pycache__"))
        except (PermissionError, OSError) as exc:
            log(f"[WARN] Could not copy webui: {exc}")

    # Directory symlinks (cpa_xai) — required Python package for grok-register
    src_cpa = os.path.join(GROK_REGISTER_DIR, "cpa_xai")
    dst_cpa = os.path.join(workdir, "cpa_xai")
    if os.path.isdir(src_cpa) and not os.path.exists(dst_cpa):
        try:
            shutil.copytree(src_cpa, dst_cpa, ignore=shutil.ignore_patterns("__pycache__"))
        except (PermissionError, OSError) as e:
            log(f"[WARN] Could not copy cpa_xai: {e}")

    return workdir


def _collect_worker_artifacts(workdir: str, prefix: str = ""):
    """Parse SSO tokens, CPA files, account files from a worker (or main) dir."""
    sso_tokens = []
    token_file = os.path.join(workdir, "token.json")
    if os.path.isfile(token_file):
        try:
            with open(token_file, encoding="utf-8") as f:
                data = json.load(f)
            sso_tokens = [
                entry.get("token", "")
                for entry in data.get("ssoBasic", [])
                if entry.get("token")
            ]
        except (json.JSONDecodeError, OSError):
            pass

    accounts_dir = os.path.join(workdir, "accounts")
    if os.path.isdir(accounts_dir):
        for accf in sorted(glob.glob(os.path.join(accounts_dir, "*.txt"))):
            name = os.path.basename(accf)
            if name in ("mail_credentials.txt", "sso_pending.txt", "sso_risk_rejected.txt") or name.startswith("accounts_"):
                continue
            try:
                with open(accf, encoding="utf-8") as f:
                    line = f.read().strip()
                if "----" in line:
                    tok = line.split("----")[-1].strip()
                    if tok and tok not in sso_tokens:
                        sso_tokens.append(tok)
            except OSError:
                pass
        for accf in sorted(
            glob.glob(os.path.join(accounts_dir, "accounts_*.txt")),
            key=os.path.getmtime,
            reverse=True,
        ):
            try:
                with open(accf, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if "----" in line:
                            tok = line.split("----")[-1].strip()
                            if tok and tok not in sso_tokens:
                                sso_tokens.append(tok)
            except OSError:
                pass

    if sso_tokens:
        _merge_tokens_into_main(sso_tokens, prefix)

    cpa_dir = os.path.join(workdir, "cpa_auths")
    cpa_files = (
        glob.glob(os.path.join(cpa_dir, "xai-*.json")) if os.path.isdir(cpa_dir) else []
    )
    acc_files = sorted(
        glob.glob(os.path.join(workdir, "accounts_*.txt")),
        key=os.path.getmtime,
        reverse=True,
    )
    return sso_tokens, cpa_files, acc_files


def run_single_worker(
    worker_id: int,
    count: int,
    results: dict,
    lock: threading.Lock,
    proxy: str = "",
    hang_timeout: float = DEFAULT_WORKER_TIMEOUT,
    progress=None,
):
    """Run one worker with streaming stdout + hang timeout."""
    prefix = f"[W{worker_id}]"
    workdir = create_worker_dir(worker_id, count)

    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    if proxy:
        env["HTTP_PROXY"] = proxy
        env["HTTPS_PROXY"] = proxy
        env["ALL_PROXY"] = proxy
    cmd = [VENV_PYTHON, os.path.join(workdir, "grok_register_ttk.py"), "cli"]

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=workdir,
            env=env,
            text=True,
            bufsize=1,
        )

        def _on_line(line: str):
            if progress is not None:
                progress.note_line(line)

        rc, timed_out = stream_process_output(
            proc,
            prefix=prefix,
            hang_timeout=hang_timeout,
            on_line=_on_line,
            log_fn=log,
            stdin_payload="start\n",
        )

        sso_tokens, cpa_files, acc_files = _collect_worker_artifacts(workdir, prefix)

        ok = (rc == 0) and not timed_out
        with lock:
            results["sso_tokens"].extend(sso_tokens)
            results["cpa_files"].extend(cpa_files)
            results["acc_files"].extend(acc_files)
            if ok:
                results["success"] += 1
            else:
                results["failed"] += 1
            if progress is not None:
                progress.set_workers_alive(
                    max(0, progress.snapshot()["workers_alive"] - 1)
                )

        if timed_out:
            log(f"{prefix} TIMEOUT hang — marked failed")
        else:
            log(
                f"{prefix} Done — SSO: {len(sso_tokens)}, CPA: {len(cpa_files)} (rc={rc})"
            )

    except Exception as e:
        with lock:
            results["failed"] += 1
            if progress is not None:
                try:
                    progress.set_workers_alive(
                        max(0, progress.snapshot()["workers_alive"] - 1)
                    )
                except Exception:
                    pass
        log(f"{prefix} ERROR: {e}")


# ─── Step 1: Run grok-register (concurrent) ─────────────────
def run_grok_register(
    count: int = 1,
    workers: int = 1,
    proxy: str = "",
    hang_timeout: float = DEFAULT_WORKER_TIMEOUT,
    mid_inject: bool = True,
) -> dict:
    """Run grok-register with concurrent workers. Returns merged results dict."""
    print(f"\n{'='*60}")
    print(f"[1/4] Running grok-register ({count} account(s), {workers} worker(s))...")
    print(f"{'='*60}\n")

    progress = ProgressState(workers_total=max(1, workers))
    stop_event = threading.Event()
    injected_cpa = set()
    injected_sso = set()
    batch_id = time.strftime("%Y%m%d_%H%M%S")
    start_progress_monitor(
        progress, stop_event, interval=DEFAULT_PROGRESS_INTERVAL, log_fn=log
    )
    start_batch_progress_writer(
        progress, stop_event,
        target=count, workers=workers, batch_id=batch_id,
        interval=4.0,
    )
    if mid_inject:
        _start_mid_inject_monitor(stop_event, injected_cpa, injected_sso)

    try:
        if workers <= 1:
            original_count = update_config_count(count)
            env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
            if proxy:
                env["HTTP_PROXY"] = proxy
                env["HTTPS_PROXY"] = proxy
                env["ALL_PROXY"] = proxy
            cmd = [VENV_PYTHON, GROK_REGISTER_SCRIPT, "cli"]
            progress.set_workers_alive(1)
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=GROK_REGISTER_DIR,
                env=env,
                text=True,
                bufsize=1,
            )
            rc, timed_out = stream_process_output(
                proc,
                prefix="",
                hang_timeout=hang_timeout,
                on_line=progress.note_line,
                log_fn=log,
                stdin_payload="start\n",
            )
            restore_config_count(original_count)
            progress.set_workers_alive(0)

            sso_tokens, cpa_files, acc_files = _collect_worker_artifacts(
                GROK_REGISTER_DIR, ""
            )
            if not cpa_files:
                cpa_files = glob.glob(os.path.join(CPA_AUTHS_DIR, "xai-*.json"))
            ok = (rc == 0) and not timed_out
            if timed_out:
                log("TIMEOUT hang — single worker marked failed")
            return {
                "sso_tokens": sso_tokens,
                "cpa_files": cpa_files,
                "acc_files": acc_files,
                "success": 1 if ok else 0,
                "failed": 0 if ok else 1,
            }

        chunks = []
        base = count // workers
        remainder = count % workers
        for i in range(workers):
            chunk = base + (1 if i < remainder else 0)
            if chunk > 0:
                chunks.append(chunk)

        actual_workers = len(chunks)
        progress.workers_total = actual_workers
        log(f"Splitting {count} accounts across {actual_workers} workers: {chunks}")
        log(f"Hang timeout: {hang_timeout:.0f}s no output → kill worker")

        results = {
            "sso_tokens": [],
            "cpa_files": [],
            "acc_files": [],
            "success": 0,
            "failed": 0,
        }
        lock = threading.Lock()
        threads = []
        progress.set_workers_alive(actual_workers)

        for wid, chunk_size in enumerate(chunks):
            t = threading.Thread(
                target=run_single_worker,
                args=(wid, chunk_size, results, lock, proxy, hang_timeout, progress),
                daemon=True,
            )
            t.start()
            threads.append(t)
            if wid < actual_workers - 1:
                time.sleep(3)

        join_timeout = max(hang_timeout * max(1, count) + 120, 3600)
        for t in threads:
            t.join(timeout=join_timeout)

        print(
            f"\n[OK] Registration completed. Workers: {results['success']} ok, {results['failed']} failed"
        )
        if mid_inject:
            try:
                cpa_n, sso_n = mid_batch_inject(injected_cpa, injected_sso)
                if cpa_n or sso_n:
                    log(f"[mid-inject] final sweep — CPA+{cpa_n} SSO+{sso_n}")
            except Exception as e:
                log(f"[mid-inject] final sweep WARN: {e}")
        return results
    finally:
        stop_event.set()
        log(progress.format_board())


# ─── Step 2: Inject SSO tokens → grok2api ───────────────────
def inject_sso_to_grok2api(sso_tokens: list[str], banner: bool = True) -> int:
    """Inject SSO tokens to grok2api via admin API. Returns count injected."""
    if banner:
        print(f"\n{'='*60}")
        print(f"[2/4] Injecting SSO tokens → grok2api...")
        print(f"{'='*60}\n")

    if not sso_tokens:
        if banner:
            log("[WARN] No SSO tokens to inject")
        return 0

    if banner:
        log(f"SSO tokens to inject: {len(sso_tokens)}")
    else:
        log(f"[mid-inject] SSO tokens to inject: {len(sso_tokens)}")

    try:
        payload = json.dumps({"tokens": sso_tokens, "pool": "basic"}).encode("utf-8")
        req = urllib.request.Request(
            f"{GROK2API_URL}/admin/api/tokens/add?app_key={GROK2API_KEY}",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=10)
        result = json.loads(resp.read().decode())
        added = result.get("count", 0)
        skipped = result.get("skipped", 0)
        log(f"[OK] grok2api: {added} new tokens added, {skipped} already existed")
        return added
    except (urllib.error.URLError, ConnectionRefusedError) as e:
        log(f"[WARN] grok2api unreachable ({e}). Attempting auto-restart...")
        _restart_grok2api()
        try:
            payload2 = json.dumps({"tokens": sso_tokens, "pool": "basic"}).encode("utf-8")
            req2 = urllib.request.Request(
                f"{GROK2API_URL}/admin/api/tokens/add?app_key={GROK2API_KEY}",
                data=payload2, headers={"Content-Type": "application/json"}, method="POST")
            resp2 = urllib.request.urlopen(req2, timeout=15)
            result2 = json.loads(resp2.read().decode())
            added = result2.get("count", 0)
            log(f"[OK] grok2api: {added} new tokens added (retry)")
            return added
        except Exception:
            log("[WARN] grok2api still unreachable. Tokens saved to token.json for later.")
            return 0
    except Exception as e:
        log(f"[ERROR] grok2api injection failed: {e}")
        return 0


# ─── Step 3: Inject CPA credentials → 9Router ──────────────
def inject_cpa_to_9router(cpa_files: list[str], banner: bool = True) -> int:
    """Inject CPA credentials to 9Router. Returns count injected."""
    if banner:
        print(f"\n{'='*60}")
        print(f"[3/4] Injecting CPA credentials → 9Router ({os.path.basename(NINE_ROUTER_DB)})...")
        print(f"{'='*60}\n")

    if not os.path.isfile(NINE_ROUTER_DB):
        log(f"[WARN] 9Router DB not found: {NINE_ROUTER_DB}")
        return 0

    if not cpa_files:
        if banner:
            log("[WARN] No CPA credentials found")
        return 0

    conn = sqlite3.connect(NINE_ROUTER_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM providerConnections WHERE provider='grok-cli'")
    existing = {row[0] for row in cursor.fetchall() if row[0]}

    injected = 0
    for path in cpa_files:
        try:
            with open(path, encoding="utf-8") as f:
                cpa = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        email = cpa.get("email", "")
        access_token = cpa.get("access_token", "")
        if not email or not access_token or email in existing:
            continue

        try:
            exp = datetime.fromisoformat(cpa.get("expired", "").replace("Z", "+00:00")).isoformat()
        except (ValueError, TypeError):
            exp = datetime.now(timezone.utc).isoformat()

        now = datetime.now(timezone.utc).isoformat()
        data = {
            "accessToken": access_token,
            "refreshToken": cpa.get("refresh_token", ""),
            "idToken": cpa.get("id_token", ""),
            "expiresAt": exp,
            "expiresIn": cpa.get("expires_in", 21600),
            "lastRefreshAt": now,
            "backoffLevel": 0,
            "testStatus": "active",
            "providerSpecificData": {"email": email, "userId": cpa.get("sub", "")},
        }

        conn_id = str(uuid.uuid4())
        cursor.execute(
            """INSERT INTO providerConnections
               (id, provider, authType, name, email, priority, isActive, data, createdAt, updatedAt)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (conn_id, "grok-cli", "oauth", email, email, 275, 1, json.dumps(data), now, now),
        )
        existing.add(email)
        injected += 1
        log(f"[OK] 9Router grok-cli: {email}")

    conn.commit()
    conn.close()

    # Also copy CPA files to main cpa_auths dir for retry later
    os.makedirs(CPA_AUTHS_DIR, exist_ok=True)
    for path in cpa_files:
        dst = os.path.join(CPA_AUTHS_DIR, os.path.basename(path))
        if not os.path.isfile(dst):
            shutil.copy2(path, dst)

    conn2 = sqlite3.connect(NINE_ROUTER_DB)
    c2 = conn2.cursor()
    c2.execute("SELECT COUNT(*) FROM providerConnections WHERE provider='grok-cli'")
    total = c2.fetchone()[0]
    conn2.close()
    log(f"\nTotal grok-cli in 9Router: {total} (new: {injected})")
    return injected


# ─── Step 4: Summary ────────────────────────────────────────
def print_summary(sso_injected: int, cpa_injected: int):
    print(f"\n{'='*60}")
    print(f"[4/4] Summary")
    print(f"{'='*60}\n")

    grok2api_count = 0
    try:
        req = urllib.request.Request(f"{GROK2API_URL}/admin/api/tokens?app_key={GROK2API_KEY}")
        resp = urllib.request.urlopen(req, timeout=5)
        data = json.loads(resp.read().decode())
        grok2api_count = len(data.get("tokens", []))
    except Exception:
        grok2api_count = "?"

    grokcli_count = 0
    if os.path.isfile(NINE_ROUTER_DB):
        try:
            conn = sqlite3.connect(NINE_ROUTER_DB)
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM providerConnections WHERE provider='grok-cli'")
            grokcli_count = c.fetchone()[0]
            conn.close()
        except Exception:
            grokcli_count = "?"

    print(f"  ┌────────────────────────────────────────────────┐")
    print(f"  │ Provider      │ Endpoint              │ Akun   │")
    print(f"  ├────────────────────────────────────────────────┤")
    print(f"  │ grok2api      │ localhost:8000/v1     │ {str(grok2api_count):>6} │")
    print(f"  │ 9Router       │ localhost:20128/v1    │        │")
    print(f"  │  ├ grok-cli   │ (CPA/OAuth)          │ {str(grokcli_count):>6} │")
    print(f"  └────────────────────────────────────────────────┘")
    print()
    print(f"  Baru di-inject:")
    print(f"    SSO → grok2api : {sso_injected} akun")
    print(f"    CPA → 9Router  : {cpa_injected} akun")
    print()
    print(f"  Cara pakai:")
    print(f"    grok2api : POST {GROK2API_URL}/v1/chat/completions")
    print(f"               Authorization: Bearer {GROK2API_KEY}")
    print(f"    9Router  : POST http://127.0.0.1:20128/v1/chat/completions")
    print(f"               Authorization: Bearer <your_9router_key>")
    print()


# ─── Cleanup ─────────────────────────────────────────────────
def cleanup_worker_dirs(workers: int):
    """Remove temp worker directories."""
    for i in range(workers):
        workdir = os.path.join(tempfile.gettempdir(), f"grok_worker_{i}")
        if os.path.isdir(workdir):
            try:
                shutil.rmtree(workdir)
            except OSError:
                pass


# ─── Main ───────────────────────────────────────────────────
def _parse_args(argv=None):
    """Parse CLI. Keeps --count N --workers W working; adds orchestration flags."""
    args = list(argv if argv is not None else sys.argv[1:])
    count = 1
    workers = 1
    proxy = ""
    hang_timeout = DEFAULT_WORKER_TIMEOUT
    adaptive = None  # None = auto (True when workers > 4)
    mid_inject = True
    do_preflight = True
    preflight_only = False
    inject_only = False
    resume = False
    clear_state = False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--count" and i + 1 < len(args):
            count = max(1, min(int(args[i + 1]), MAX_COUNT))
            i += 2
        elif a == "--workers" and i + 1 < len(args):
            workers = max(1, min(int(args[i + 1]), MAX_WORKERS))
            i += 2
        elif a == "--proxy" and i + 1 < len(args):
            proxy = args[i + 1]
            i += 2
        elif a == "--worker-timeout" and i + 1 < len(args):
            hang_timeout = max(30, int(args[i + 1]))
            i += 2
        elif a == "--adaptive":
            adaptive = True
            i += 1
        elif a == "--no-adaptive":
            adaptive = False
            i += 1
        elif a == "--mid-inject":
            mid_inject = True
            i += 1
        elif a in ("--no-mid-inject", "--no-midinject"):
            mid_inject = False
            i += 1
        elif a == "--preflight-only":
            preflight_only = True
            i += 1
        elif a == "--no-preflight":
            do_preflight = False
            i += 1
        elif a == "--inject-only":
            inject_only = True
            i += 1
        elif a == "--resume":
            resume = True
            i += 1
        elif a == "--clear-state":
            clear_state = True
            i += 1
        elif a in ("-h", "--help"):
            print(
                "Usage: python scripts/gro_register_to_9router.py [options]\n"
                "  --count N            accounts to register (1-500, default 1)\n"
                "  --workers W          parallel workers (1-8, default 1)\n"
                "  --adaptive           start with min(W, 4) for stability (default if W>4)\n"
                "  --no-adaptive        use full worker count up to 8\n"
                "  --worker-timeout SEC hang kill if no stdout (default 300 / WORKER_ACCOUNT_TIMEOUT)\n"
                "  --mid-inject         mid-batch CPA/SSO inject (default on)\n"
                "  --no-mid-inject      disable mid-batch inject\n"
                "  --preflight-only     run checks and exit\n"
                "  --no-preflight       skip preflight\n"
                "  --inject-only        only inject existing cpa/sso (no register)\n"
                "  --resume             continue from last batch state (log/batch_state.json)\n"
                "  --clear-state        clear saved batch state and exit\n"
                "  --proxy URL          HTTP/SOCKS proxy for workers\n"
            )
            raise SystemExit(0)
        else:
            i += 1

    if not proxy:
        proxy = WARP_PROXY
    if adaptive is None:
        adaptive = workers > ADAPTIVE_SOFT_CAP
    return {
        "count": count,
        "workers": workers,
        "proxy": proxy,
        "hang_timeout": hang_timeout,
        "adaptive": adaptive,
        "mid_inject": mid_inject,
        "do_preflight": do_preflight,
        "preflight_only": preflight_only,
        "inject_only": inject_only,
        "resume": resume,
        "clear_state": clear_state,
    }


def main():
    print("GroRegto9Router — Register + inject to 9Router & grok2api")
    print(f"  grok-register dir : {REPO}")
    print(f"  9Router DB        : {NINE_ROUTER_DB}")
    print(f"  grok2api          : {GROK2API_URL}")

    opts = _parse_args()
    count = opts["count"]
    workers_req = opts["workers"]
    proxy = opts["proxy"]
    hang_timeout = opts["hang_timeout"]
    adaptive = opts["adaptive"]
    mid_inject = opts["mid_inject"]

    # ── Batch resume / clear-state ────────────────────────────
    if opts["clear_state"]:
        cleared = clear_batch_state()
        log("[state] batch state cleared" if cleared else "[state] no batch state to clear")
        raise SystemExit(0)

    if opts["resume"]:
        state = load_batch_state()
        if state is None:
            log("[resume] no saved batch state found — use --count N to start fresh")
            raise SystemExit(2)
        done = int(state.get("completed", 0) or 0)
        target = int(state.get("target", 0) or 0)
        rem = remaining(state)
        log(
            f"[resume] target={target} completed={done} remaining={rem} "
            f"(state file: log/batch_state.json)"
        )
        if rem <= 0:
            log("[resume] batch already complete — nothing to do (use --clear-state to reset)")
            raise SystemExit(0)
        count = rem
        if workers_req == 1 and int(state.get("workers", 1) or 1) > 1:
            workers_req = int(state["workers"])
    else:
        save_batch_state(
            count,
            0,
            workers=workers_req,
            batch_id=time.strftime("%Y%m%d_%H%M%S"),
        )
        log(f"[state] batch started target={count} workers={workers_req}")

    if opts["do_preflight"] or opts["preflight_only"]:
        errors = run_preflight()
        if opts["preflight_only"]:
            raise SystemExit(1 if errors else 0)
        if errors:
            log("Aborting due to preflight failures. Use --no-preflight to skip.")
            raise SystemExit(2)

    workers = choose_workers(
        workers_req, adaptive=adaptive, soft_cap=ADAPTIVE_SOFT_CAP, hard_cap=MAX_WORKERS
    )
    if workers != workers_req:
        log(
            f"[adaptive] requested {workers_req} workers → starting with {workers} "
            f"(soft cap {ADAPTIVE_SOFT_CAP} for stability; --no-adaptive to force)"
        )

    print(f"  Accounts to make  : {count}")
    print(f"  Workers           : {workers}" + (f" (requested {workers_req})" if workers != workers_req else ""))
    print(f"  Hang timeout      : {hang_timeout}s")
    print(f"  Mid-inject        : {'on' if mid_inject else 'off'}")
    if proxy:
        print(f"  Proxy             : {proxy}")

    if opts["inject_only"]:
        log("[inject-only] Skipping registration — scanning existing CPA/SSO")
        tmp = tempfile.gettempdir()
        cpa_files = discover_cpa_files(tmp, CPA_AUTHS_DIR)
        sso_tokens = discover_sso_tokens(tmp, TOKEN_JSON)
        sso_injected = inject_sso_to_grok2api(sso_tokens)
        cpa_injected = inject_cpa_to_9router(cpa_files)
        print_summary(sso_injected, cpa_injected)
        return

    # Step 1: Register
    results = run_grok_register(
        count,
        workers,
        proxy=proxy,
        hang_timeout=hang_timeout,
        mid_inject=mid_inject,
    )

    # Update batch state dengan progress nyata (CPA files sukses)
    try:
        done = len(results.get("cpa_files", []))
        if done > 0:
            state = load_batch_state()
            prev_done = int(state.get("completed", 0) or 0) if state else 0
            update_batch_state(completed=prev_done + done)
            log(f"[state] progress updated completed={prev_done + done}")
    except Exception as e:
        log(f"[state] WARN update: {e}")

    # Step 2: Inject SSO → grok2api
    sso_injected = inject_sso_to_grok2api(results["sso_tokens"])

    # Step 3: Inject CPA → 9Router
    cpa_injected = inject_cpa_to_9router(results["cpa_files"])

    # Step 4: Summary
    print_summary(sso_injected, cpa_injected)

    # Cleanup temp dirs
    if workers > 1:
        cleanup_worker_dirs(max(workers, workers_req))

    # Batch selesai → clear state (kecuali resume yang masih bersisa)
    try:
        state = load_batch_state()
        done = int(state.get("completed", 0) or 0) if state else 0
        target = int(state.get("target", 0) or 0) if state else 0
        if done >= target or (state is not None and cpa_injected >= remaining(state)):
            if clear_batch_state():
                log("[state] batch complete — state cleared")
    except Exception as e:
        log(f"[state] WARN finalize: {e}")


if __name__ == "__main__":
    main()
