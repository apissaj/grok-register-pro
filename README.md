<div align="center">

# 🚀 grok-register-pro

**Massive Grok (xAI) account registration pipeline — automated, parallel, anti-detection ready.**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)]()
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)]()
[![Camoufox](https://img.shields.io/badge/antidetect-Camoufox-orange)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)]()

*Register hundreds of Grok accounts at scale — headless, parallel, and invisible to bot detection.*

</div>

---

## ✨ Features

| | Feature | Detail |
|---|---|---|
| 🕵️ | **Anti-detection browser** | Camoufox (Firefox-based) with BrowserForge fingerprinting, geo-IP matched timezone/language, WebRTC leak protection |
| ⚡ | **Headless mode** | Fully headless registration — no windows, no clicks, no focus stealing. Multi-worker parallel by design |
| 🔀 | **Parallel workers** | Register N accounts concurrently across CPU cores |
| 📬 | **Email OTP automation** | Built-in providers: **CloudMail** (own domain), Tempik, DuckMail, YYDS, MailNest, Cloudflare |
| 🍪 | **SSO cookie capture** | Automatically captures `sso` cookie after signup |
| 🔑 | **SSO → CPA conversion** | Device Flow (RFC 8628) + Authorization Code fallback to mint OAuth credentials |
| 📡 | **9Router integration** | Auto-inject CPA credentials into 9Router's SQLite pool (`grok-cli` provider) |
| 🔋 | **grok2api integration** | Auto-inject SSO tokens into grok2api token pool |
| 🖥️ | **Web control panel** | Real-time monitor, proxy pool, email provider & domain management, batch control |
| 🛡️ | **Risk detection** | Reads xAI risk fields (`botFlagSource`/`policy`) and rejects risky registrations before minting |
| 🧹 | **Fast mode** | Keep browser alive between accounts, clear cookies, OTP poll @1s — **10 accounts in ~2 min** |

---

## 🧱 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    grok-register-pro                            │
│                                                                 │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────────────┐  │
│  │  Camoufox   │   │  Email OTP   │   │  Risk Engine         │  │
│  │  Browser    │──▶│  Providers   │──▶│  botFlag / policy    │  │
│  │  (headless) │   │  CloudMail…  │   │  check               │  │
│  └─────────────┘   └──────────────┘   └──────────────────────┘  │
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  SSO Cookie → token.json → grok2api (SSO pool)           │   │
│  │  SSO → CPA (Device Flow) → cpa_auths/ → 9Router (sqlite) │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────────────────────────────┐                        │
│  │  Web Panel (monitor + control)     │                        │
│  └─────────────────────────────────────┘                        │
└─────────────────────────────────────────────────────────────────┘
```

### Flow: one account

```
sign-up page → click "Sign up with email" → create mailbox (CloudMail)
→ fill email → poll OTP (1s) → fill code → fill profile (Turnstile handling)
→ wait for sso cookie → save account → convert to CPA → inject 9Router
```

---

## 📦 Installation

### Prerequisites
- Python 3.11+
- [Camoufox](https://github.com/daijro/camoufox) browser fetched (`python -m camoufox fetch`)
- An email provider (CloudMail recommended: own domain + SMTP web UI)

### Install
```bash
git clone https://github.com/hafizhmuzani/grok-register-pro.git
cd grok-register-pro
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt   # Windows
# source .venv/bin/activate && pip install -r requirements.txt  # Linux
python -m camoufox fetch   # download browser engine (~1GB)
```

### Configure
```bash
cp config.json config.json   # edit with your email provider + API keys
```

Key config:
```jsonc
{
  "email_provider": "cloudmail",
  "defaultDomains": "yourdomain.com",
  "cloudmail_url": "https://mail.yourdomain.com",
  "cloudmail_admin_email": "admin@yourdomain.com",
  "cloudmail_password": "***",
  "browser_headless": true,
  "register_count": 10,
  "register_workers": 5,
  "account_interval": "0-2",
  "cpa_auto_add": true,
  "cpa_auth_dir": "./cpa_auths"
}
```

---

## ▶️ Usage

### Register + inject (recommended)
```bash
python scripts/gro_register_to_9router.py --count 10 --workers 5
```
Runs registration across `workers` parallel headless browsers, then injects:
- SSO tokens → grok2api (port 8000)
- CPA credentials → 9Router (port 20128)

### CLI only
```bash
python grok_register_ttk.py cli
```

### Web monitor panel
```bash
python webui/monitor.py  # http://127.0.0.1:8787
```

### Recover SSO tokens from crashed worker dirs
```bash
python scripts/recover_worker_tokens.py
```

### Convert existing SSO pool → CPA
```bash
python sso_to_auth_json.py --accounts-dir ./accounts --cpa-auth-dir ./cpa_auths --from-config config.json
```

---

## 🧪 Tests
```bash
bash scripts/run_tests.sh
```
13 test suites: security utils, runtime platform (Windows 8.3 paths), SSO recovery,
monitor HTTP, batch supervisor, proxy store, email domains, panel structure, release.

---

## 🛡️ Anti-detection details

| Layer | Implementation |
|---|---|
| Engine | Camoufox patches Gecko at C++ level — JS cannot detect |
| Fingerprint | BrowserForge generates consistent per-profile fingerprints |
| IP geo-match | `geoip: true` matches timezone/language/coordinates to egress IP |
| WebRTC | `block_webrtc: true` prevents real-IP STUN leaks |
| Humanization | Bezier-curve mouse movements, humanized typing |
| Risk early-exit | Reads xAI risk API before minting — skips flagged accounts (saves OAuth quota) |

---

## 🔒 Security

- `config.json`, `token.json`, `cpa_auths/`, `grok2api_auth/`, `accounts/*.txt` are gitignored
- Sensitive output paths use atomic writes with restrictive permissions
- Monitor panel protected by bearer token auth
- `harden_runtime_permissions.py` locks down runtime dirs

---

## 📋 Requirements

See [requirements.txt](requirements.txt) — pin-locked deps + `camoufox[geoip]==0.5.4`

---

## 📄 License

MIT — free to use, modify, and distribute.

> ⚠️ **Disclaimer**: This tool automates account creation. Use responsibly — respect xAI / Grok
> Terms of Service. The author is not responsible for misuse, account termination, or violations
> of any platform policy.