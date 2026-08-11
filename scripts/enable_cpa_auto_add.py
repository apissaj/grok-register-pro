import json

CONFIG = "config.json"

cfg = json.load(open(CONFIG, encoding="utf-8"))

# 1. Turn on SSO->CPA conversion so future registrations write CPA auths
cfg["cpa_auto_add"] = True
cfg["grok2api_auth_dir"] = "./grok2api_auth"

# 2. Persist
with open(CONFIG, "w", encoding="utf-8") as fh:
    json.dump(cfg, fh, ensure_ascii=False, indent=2)
print("cpa_auto_add =", cfg["cpa_auto_add"])
print("grok2api_auth_dir =", cfg["grok2api_auth_dir"])