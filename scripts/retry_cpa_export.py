"""
Retry failed CPA exports from accounts file.

Reads the latest accounts file, checks which ones already have
CPA credentials in cpa_auths/, and retries the failed ones
with configurable delay between attempts.

Usage:
    python scripts/retry_cpa_export.py [--delay 60] [--limit 5]
"""
import glob
import json
import os
import sqlite3
import sys
import time
import uuid
from datetime import datetime, timezone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CPA_DIR = os.path.join(REPO, "cpa_auths")
NINE_ROUTER_DB = ""
for candidate in [
    os.path.expandvars(r"%APPDATA%\9router\db\data.sqlite"),
    r"D:\Backup_Windows_Reinstall\9router\db\data.sqlite",
]:
    if os.path.isfile(candidate):
        NINE_ROUTER_DB = candidate
        break

VENV_PYTHON = os.path.join(REPO, ".venv", "Scripts", "python.exe")


def find_latest_accounts_file() -> str:
    pattern = os.path.join(REPO, "accounts_*.txt")
    files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    return files[0] if files else ""


def parse_accounts(path: str) -> list[dict]:
    """Parse email----password----sso lines."""
    accounts = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or "----" not in line:
                continue
            parts = line.split("----")
            if len(parts) >= 3:
                accounts.append({"email": parts[0], "password": parts[1], "sso": parts[2]})
    return accounts


def find_exported_emails() -> set[str]:
    emails = set()
    for path in glob.glob(os.path.join(CPA_DIR, "xai-*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if data.get("access_token"):
                emails.add(data["email"])
        except Exception:
            pass
    return emails


def retry_cpa_export(email: str, password: str, sso: str) -> dict:
    """Call grok-register CPA export function."""
    import subprocess
    # Build a Python one-liner that imports and calls the CPA export
    code = f"""
import sys, json, os
sys.path.insert(0, r'{REPO}')
from app_config import load_config
load_config()
from cpa_export import export_cpa_xai_for_account
result = export_cpa_xai_for_account(
    email=r'{email}',
    password=r'{password}',
    sso=r'{sso}',
    log_callback=print,
)
print(json.dumps(result))
"""
    proc = subprocess.run(
        [VENV_PYTHON, "-c", code],
        capture_output=True, text=True, timeout=300,
        cwd=REPO,
        env={**os.environ, "PYTHONPATH": ""},
    )
    output = proc.stdout + proc.stderr
    # Find the JSON result in output (last line that starts with {)
    for line in reversed(output.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                pass
    return {"ok": False, "error": output[-200:]} if output else {"ok": False, "error": "no output"}


def inject_to_9router(email: str, cpa_data: dict) -> bool:
    """Inject a successful CPA credential into 9router."""
    if not NINE_ROUTER_DB or not os.path.isfile(NINE_ROUTER_DB):
        print(f"  [WARN] 9Router DB not found: {NINE_ROUTER_DB}")
        return False

    access = cpa_data.get("access_token", "")
    if not access:
        return False

    try:
        exp = datetime.fromisoformat(cpa_data.get("expired", "").replace("Z", "+00:00")).isoformat()
    except (ValueError, TypeError):
        exp = datetime.now(timezone.utc).isoformat()

    now = datetime.now(timezone.utc).isoformat()
    data = {
        "accessToken": access,
        "refreshToken": cpa_data.get("refresh_token", ""),
        "idToken": cpa_data.get("id_token", ""),
        "expiresAt": exp,
        "expiresIn": cpa_data.get("expires_in", 21600),
        "lastRefreshAt": now,
        "backoffLevel": 0,
        "testStatus": "active",
        "providerSpecificData": {"email": email, "userId": cpa_data.get("sub", "")},
    }

    conn = sqlite3.connect(NINE_ROUTER_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM providerConnections WHERE provider='grok-cli' AND email=?", (email,))
    if cursor.fetchone():
        conn.close()
        print(f"  [SKIP] Already in 9router: {email}")
        return True

    cid = str(uuid.uuid4())
    cursor.execute(
        """INSERT INTO providerConnections
           (id, provider, authType, name, email, priority, isActive, data, createdAt, updatedAt)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (cid, "grok-cli", "oauth", email, email, 275, 1, json.dumps(data), now, now),
    )
    conn.commit()
    conn.close()
    print(f"  [OK] Injected to 9router: {email}")
    return True


def main():
    delay = 60
    limit = 5
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--delay" and i + 1 < len(args):
            delay = int(args[i + 1])
            i += 2
        elif args[i] == "--limit" and i + 1 < len(args):
            limit = int(args[i + 1])
            i += 2
        else:
            i += 1

    accounts_file = find_latest_accounts_file()
    if not accounts_file:
        print("[ERROR] No accounts file found")
        sys.exit(1)

    accounts = parse_accounts(accounts_file)
    exported = find_exported_emails()

    pending = [a for a in accounts if a["email"] not in exported]

    print(f"[CPA Export Retry]")
    print(f"  Accounts file : {os.path.basename(accounts_file)}")
    print(f"  Total accounts: {len(accounts)}")
    print(f"  Already done  : {len(exported)}")
    print(f"  Pending       : {len(pending)}")
    print(f"  Delay         : {delay}s between attempts")
    print(f"  Limit         : {limit}")
    print()

    if not pending:
        print("[OK] All accounts already have CPA credentials.")
        return

    success = 0
    failed = 0
    for idx, acct in enumerate(pending[:limit]):
        email = acct["email"]
        print(f"[{idx+1}/{min(len(pending), limit)}] {email}")

        result = retry_cpa_export(email, acct["password"], acct["sso"])

        if result.get("ok") and result.get("path"):
            print(f"  [OK] CPA exported: {result['path']}")
            # Read the exported file and inject
            with open(result["path"], encoding="utf-8") as f:
                cpa_data = json.load(f)
            inject_to_9router(email, cpa_data)
            success += 1
        else:
            error = result.get("error", "unknown")[:100]
            print(f"  [FAIL] {error}")
            failed += 1

        # Delay between attempts (except last)
        if idx < min(len(pending), limit) - 1:
            print(f"  Waiting {delay}s...")
            time.sleep(delay)

    print()
    print(f"[Done] Success: {success} | Failed: {failed} | Skipped: {len(pending) - min(len(pending), limit)}")

    if success > 0:
        # Report total in 9router
        conn = sqlite3.connect(NINE_ROUTER_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM providerConnections WHERE provider='grok-cli'")
        print(f"[9Router] Total grok-cli connections: {cursor.fetchone()[0]}")
        conn.close()


if __name__ == "__main__":
    main()
