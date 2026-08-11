"""
Auto-refresh expired/expiring 9Router grok-cli tokens.

Reads all grok-cli connections from 9Router's SQLite DB.
For each connection:
  - Checks if accessToken is expired or expiring within a buffer (default 10min)
  - If so, calls xAI OAuth2 token endpoint to refresh
  - Updates the DB with new tokens

Usage:
    python scripts/refresh_9router_tokens.py [--buffer-minutes 10] [--force] [--dry-run]

Requires: requests (stdlib only: urllib)
"""
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# ---- Config ----
XAI_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
XAI_TOKEN_URL = "https://auth.x.ai/oauth2/token"
DEFAULT_BUFFER_MINUTES = 10

# 9Router DB — auto-detect
def find_9router_db():
    candidates = [
        os.path.expandvars(r"%APPDATA%\9router\db\data.sqlite"),
        os.path.expandvars(r"%USERPROFILE%\AppData\Roaming\9router\db\data.sqlite"),
        r"D:\Backup_Windows_Reinstall\9router\db\data.sqlite",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return candidates[0]  # fallback


def refresh_token(refresh_tok: str) -> dict | None:
    """Call xAI OAuth2 token endpoint to refresh access token."""
    data = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "client_id": XAI_CLIENT_ID,
        "refresh_token": refresh_tok,
    }).encode()

    req = urllib.request.Request(
        XAI_TOKEN_URL,
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"    [ERROR] HTTP {e.code}: {body[:200]}")
        if "invalid_grant" in body or "invalid_request" in body:
            return {"error": "invalid_grant", "detail": body}
        return None
    except Exception as e:
        print(f"    [ERROR] {e}")
        return None


def is_expired_or_expiring(expires_at_str: str, buffer_minutes: int) -> bool:
    """Check if token is expired or expiring within buffer."""
    if not expires_at_str:
        return True  # no expiry info = assume needs refresh
    try:
        expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        buffer = buffer_minutes * 60
        return (expires_at - now).total_seconds() < buffer
    except (ValueError, TypeError):
        return True


def format_time_left(expires_at_str: str) -> str:
    """Human-readable time until expiry."""
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
    # Parse args
    buffer_minutes = DEFAULT_BUFFER_MINUTES
    force = False
    dry_run = False

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--buffer-minutes" and i + 1 < len(args):
            buffer_minutes = int(args[i + 1])
            i += 2
        elif args[i] == "--force":
            force = True
            i += 1
        elif args[i] == "--dry-run":
            dry_run = True
            i += 1
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

    if not rows:
        print("[INFO] No active grok-cli connections found.")
        conn.close()
        return

    print(f"[9Router Token Refresh] DB: {db_path}")
    print(f"  Active grok-cli connections: {len(rows)}")
    print(f"  Buffer: {buffer_minutes}min | Force: {force} | Dry-run: {dry_run}")
    print()

    refreshed = 0
    skipped = 0
    failed = 0

    for row in rows:
        d = dict(row)
        data = json.loads(d["data"])
        email = d.get("email") or data.get("providerSpecificData", {}).get("email", "unknown")
        expires_at = data.get("expiresAt", "")
        refresh_tok = data.get("refreshToken", "")

        status = format_time_left(expires_at)
        needs_refresh = force or is_expired_or_expiring(expires_at, buffer_minutes)

        if not needs_refresh:
            print(f"  [OK] {email:45} {status:20} — skipping")
            skipped += 1
            continue

        if not refresh_tok:
            print(f"  [!!] {email:45} {status:20} — NO refresh token, cannot refresh")
            failed += 1
            continue

        print(f"  [>>] {email:45} {status:20} — refreshing...")

        if dry_run:
            print(f"       (dry-run, would refresh)")
            skipped += 1
            continue

        result = refresh_token(refresh_tok)

        if not result or "error" in result:
            error = result.get("error", "unknown") if result else "no response"
            print(f"       [FAIL] Refresh failed: {error}")
            if result and result.get("error") == "invalid_grant":
                # Mark connection as inactive — refresh token is dead
                print(f"       [DEAD] Refresh token revoked, deactivating...")
                data["testStatus"] = "token_revoked"
                data["lastError"] = f"refresh_token revoked: {result.get('detail', '')[:100]}"
                data["lastErrorAt"] = datetime.now(timezone.utc).isoformat()
                cursor.execute(
                    "UPDATE providerConnections SET data = ?, updatedAt = ? WHERE id = ?",
                    (json.dumps(data), datetime.now(timezone.utc).isoformat(), d["id"]),
                )
                conn.commit()
            failed += 1
            continue

        # Update tokens in DB
        now = datetime.now(timezone.utc).isoformat()
        new_expires_in = result.get("expires_in", 21600)
        try:
            new_expires_at = datetime.fromtimestamp(
                time.time() + new_expires_in, tz=timezone.utc
            ).isoformat()
        except (ValueError, TypeError):
            new_expires_at = now

        data["accessToken"] = result["access_token"]
        if result.get("refresh_token"):
            data["refreshToken"] = result["refresh_token"]
        data["expiresAt"] = new_expires_at
        data["expiresIn"] = new_expires_in
        data["lastRefreshAt"] = now
        data["backoffLevel"] = 0
        data["testStatus"] = "active"
        data.pop("lastError", None)
        data.pop("lastErrorAt", None)
        if result.get("id_token"):
            data["idToken"] = result["id_token"]

        cursor.execute(
            "UPDATE providerConnections SET data = ?, updatedAt = ? WHERE id = ?",
            (json.dumps(data), now, d["id"]),
        )
        conn.commit()

        new_status = format_time_left(new_expires_at)
        print(f"       [OK] Refreshed! New expiry: {new_status} (token len={len(result['access_token'])})")
        refreshed += 1

    conn.close()

    print()
    print(f"[Done] Refreshed: {refreshed} | Skipped: {skipped} | Failed: {failed}")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
