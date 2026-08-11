"""
Monitor 9Router grok-cli account health.

Tests each active grok-cli connection by sending a lightweight
request to cli-chat-proxy.grok.com via the 9Router proxy.

Reports:
  - ALIVE accounts (responded successfully)
  - DEAD accounts (auth errors, rate limited, revoked)
  - Token expiry warnings

Usage:
    python scripts/monitor_9router_accounts.py [--json] [--alert-cmd "echo ALERT"]

Requires: stdlib only (urllib, sqlite3, json)
"""
import json
import os
import sqlite3
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# ---- Config ----
GROK_CLI_BASE = "https://cli-chat-proxy.grok.com/v1"
TEST_MODEL = "grok-4.5"
TEST_TIMEOUT = 30

# 9Router DB + API — auto-detect
def find_9router_db():
    candidates = [
        os.path.expandvars(r"%APPDATA%\9router\db\data.sqlite"),
        os.path.expandvars(r"%USERPROFILE%\AppData\Roaming\9router\db\data.sqlite"),
        r"D:\Backup_Windows_Reinstall\9router\db\data.sqlite",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return candidates[0]


def get_9router_api_key(db_path: str) -> str:
    """Read the first API key from 9Router DB."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT key FROM apiKeys LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else ""
    except Exception:
        return ""


def test_account_direct(access_token: str) -> dict:
    """Test a grok-cli token directly against cli-chat-proxy.grok.com."""
    body = json.dumps({
        "model": TEST_MODEL,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 5,
        "stream": False,
    }).encode()

    req = urllib.request.Request(
        f"{GROK_CLI_BASE}/chat/completions",
        data=body,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "grok-shell/0.2.99 (linux; x86_64)",
            "x-grok-client-identifier": "grok-shell",
            "x-grok-client-version": "0.2.99",
            "x-xai-token-auth": "xai-grok-cli",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=TEST_TIMEOUT) as resp:
            data = json.loads(resp.read())
            return {
                "status": "alive",
                "http_code": resp.status,
                "response": data.get("choices", [{}])[0].get("message", {}).get("content", ""),
                "model": data.get("model", ""),
                "usage": data.get("usage", {}),
            }
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            err_data = json.loads(body)
            err_field = err_data.get("error", "")
            if isinstance(err_field, dict):
                error_msg = err_field.get("message", body[:200])
            else:
                error_msg = str(err_field) or body[:200]
        except json.JSONDecodeError:
            error_msg = body[:200]

        status = "dead"
        if e.code == 429:
            status = "rate_limited"
        elif e.code == 402:
            status = "no_credits"
        elif e.code == 401:
            status = "token_expired"
        elif e.code == 429:
            status = "rate_limited"
        else:
            status = "error"

        return {
            "status": status,
            "http_code": e.code,
            "error": error_msg[:200],
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)[:200],
        }


def format_time_left(expires_at_str: str) -> str:
    if not expires_at_str:
        return "unknown"
    try:
        expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        diff = (expires_at - now).total_seconds()
        if diff < 0:
            return f"expired {-diff/60:.0f}min ago"
        if diff < 3600:
            return f"{diff/60:.0f}min left"
        return f"{diff/3600:.1f}h left"
    except (ValueError, TypeError):
        return "parse error"


def main():
    output_json = False
    alert_cmd = ""

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--json":
            output_json = True
            i += 1
        elif args[i] == "--alert-cmd" and i + 1 < len(args):
            alert_cmd = args[i + 1]
            i += 2
        else:
            i += 1

    db_path = find_9router_db()
    if not os.path.isfile(db_path):
        print(f"[ERROR] 9Router DB not found: {db_path}")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM providerConnections WHERE provider = 'grok-cli' AND isActive = 1"
    )
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print("[INFO] No active grok-cli connections.")
        return

    print(f"[Monitor] Testing {len(rows)} grok-cli accounts...")
    print(f"  Model: {TEST_MODEL} | Timeout: {TEST_TIMEOUT}s")
    print()

    results = []
    alive = []
    dead = []
    warns = []

    for row in rows:
        d = dict(row)
        data = json.loads(d["data"])
        email = d.get("email") or data.get("providerSpecificData", {}).get("email", "unknown")
        access_token = data.get("accessToken", "")
        expires_at = data.get("expiresAt", "")
        test_status = data.get("testStatus", "unknown")
        expiry_str = format_time_left(expires_at)

        if not access_token:
            result = {"status": "no_token", "error": "No access token"}
        else:
            result = test_account_direct(access_token)

        entry = {
            "email": email,
            "id": d["id"],
            "expiry": expiry_str,
            "test_status": test_status,
            **result,
        }
        results.append(entry)

        # Categorize
        status = result["status"]
        if status == "alive":
            alive.append(entry)
            icon = "✅"
            extra = f"model={result.get('model','')} resp={result.get('response','')[:30]}"
        elif status == "rate_limited":
            warns.append(entry)
            icon = "⚠️"
            extra = f"HTTP {result.get('http_code')}: {result.get('error','')[:50]}"
        else:
            dead.append(entry)
            icon = "❌"
            extra = f"HTTP {result.get('http_code','')}: {result.get('error','')[:50]}"

        # Token expiry warning
        expiry_icon = ""
        if "expired" in expiry_str or "0min" in expiry_str:
            expiry_icon = " 🕐TOKEN"
            if entry not in warns:
                warns.append(entry)

        print(f"  {icon} {email:45} {expiry_str:16}{expiry_icon}  {extra}")

    # Summary
    print()
    print(f"[Summary] Total: {len(results)} | ✅ Alive: {len(alive)} | ⚠️  Warn: {len(warns)} | ❌ Dead: {len(dead)}")

    if dead:
        print()
        print("[Dead accounts]:")
        for d in dead:
            print(f"  ❌ {d['email']} — {d.get('error', 'unknown')}")

    # Alert if dead accounts found
    if dead and alert_cmd:
        dead_emails = ", ".join(d["email"] for d in dead)
        cmd = alert_cmd.replace("{DEAD_COUNT}", str(len(dead))).replace("{DEAD_EMAILS}", dead_emails)
        print(f"\n[Alert] Running: {cmd}")
        subprocess.run(cmd, shell=True)

    # JSON output
    if output_json:
        print()
        print(json.dumps(results, indent=2, ensure_ascii=False))

    if dead:
        sys.exit(1)


if __name__ == "__main__":
    main()
