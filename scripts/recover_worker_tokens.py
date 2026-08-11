"""Recover SSO tokens from worker temp dirs into main token.json + accounts/."""
import json
import os
import glob
import tempfile

tmp = tempfile.gettempdir()
all_pairs = []
for wd in glob.glob(os.path.join(tmp, "grok_worker_*")):
    accd = os.path.join(wd, "accounts")
    if not os.path.isdir(accd):
        continue
    for f in glob.glob(os.path.join(accd, "*.txt")):
        name = os.path.basename(f)
        if name in ("mail_credentials.txt", "sso_pending.txt", "sso_risk_rejected.txt") or name.startswith("accounts_"):
            continue
        try:
            with open(f, encoding="utf-8") as fh:
                line = fh.read().strip()
            if "----" in line:
                email = line.split("----")[0].strip()
                tok = line.split("----")[-1].strip()
                if tok:
                    all_pairs.append((email, tok))
        except OSError:
            pass

# Merge into token.json
main = json.load(open("token.json", encoding="utf-8"))
existing = {e.get("token", "") for e in main.get("ssoBasic", [])}
added = 0
for email, tok in all_pairs:
    if tok not in existing:
        main.setdefault("ssoBasic", []).append({"token": tok, "email": email})
        existing.add(tok)
        added += 1
with open("token.json", "w", encoding="utf-8") as fh:
    json.dump(main, fh, ensure_ascii=False, indent=2)
print(f"Added {added} tokens -> token.json")
print(f"Total: {len(main.get('ssoBasic', []))} SSO tokens")

# Save per-account files to main accounts/ dir (permanent)
os.makedirs("accounts", exist_ok=True)
saved = 0
for email, tok in all_pairs:
    safe = email.replace("/", "_").replace("\\", "_")
    p = os.path.join("accounts", safe + ".txt")
    if not os.path.exists(p):
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(f"{email}----{tok}\n")
        saved += 1
print(f"Saved {saved} account files to accounts/")