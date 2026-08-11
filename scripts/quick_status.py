#!/usr/bin/env python3
"""Quick status check for grok2api and 9Router."""
import sqlite3, urllib.request, json, os, sys

def check_grok2api():
    try:
        r = urllib.request.urlopen("http://127.0.0.1:8000/admin/api/tokens?app_key=grok2api", timeout=10)
        d = json.loads(r.read())
        return len(d.get("tokens", []))
    except:
        return -1

def check_9router():
    try:
        db = os.path.expandvars(r"%APPDATA%\9router\db\data.sqlite")
        conn = sqlite3.connect(db)
        n = conn.execute("SELECT COUNT(*) FROM providerConnections WHERE provider='grok-cli' AND isActive=1").fetchone()[0]
        conn.close()
        return n
    except:
        return -1

g = check_grok2api()
r = check_9router()
print(f"grok2api: {g} tokens | 9Router: {r} accounts")
