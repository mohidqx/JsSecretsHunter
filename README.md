# JsSecretHunter

<div align="center">

<img src="https://github.com/mohidqx.png" width="80" style="border-radius:50%"/>

**by [mohidqx](https://github.com/mohidqx) / TeamCyberOps**

![Version](https://img.shields.io/badge/version-4.0.0-black?style=for-the-badge)
![Python](https://img.shields.io/badge/python-3.10+-black?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20WSL2%20%7C%20Kali-black?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-black?style=for-the-badge)
![Patterns](https://img.shields.io/badge/patterns-619+-black?style=for-the-badge)

**Production-grade JavaScript secret scanner with dark glass-morphism GUI.**

</div>
<img width="1374" height="933" alt="image" src="https://github.com/user-attachments/assets/395b5661-d69f-44b1-b225-da0b4b8e13bd" />
---

## ⚠️ Legal Disclaimer

> **Authorized use only.** For penetration testing, bug bounty, and security research on systems you own or have explicit written permission to test. Unauthorized use is illegal. Authors assume no liability.

---

## 📂 Required Files

```
jsSecretsHunter/
├── jssecrethunter_gui.py        ← Main GUI app
├── jssecrethunter.py            ← CLI version
├── secretfinder_regexes.txt     ← 600+ patterns  ⚠ MUST be in same dir
├── requirements.txt
├── install.sh / install.bat
├── CHANGELOG.md
├── LICENSE
└── README.md
```

---

## ✨ v4.0.0 Features

| Feature | Detail |
|---------|--------|
| 🖥️ **Glass Morphism GUI** | Canvas-based gradient panels, glow borders |
| 🔎 **600+ Patterns** | Live-loaded from `secretfinder_regexes.txt` |
| ⚡ **Rate-Limit Bypass** | Exponential backoff · UA rotation · jitter delays |
| 🌐 **Proxy Rotation** | HTTP / HTTPS / SOCKS5 proxy pool |
| 🔗 **Auto JS Discovery** | Extracts JS from src, href, import, require, loadScript |
| 📁 **Local Scanning** | Local `.js` files or entire directories |
| 🎯 **Severity Levels** | CRITICAL / HIGH / MEDIUM |
| ⟳ **Auto-Update** | One-click GitHub release update |
| 🧩 **Pattern Viewer** | Browse / search all patterns in-app |
| 📤 **Export** | JSON · CSV · TXT |
| 🚫 **Zero pip deps** | Pure stdlib (Pillow optional for logo) |

---

## 🚀 Quick Start

```bash
git clone https://github.com/mohidqx/jsSecretsHunter.git
cd jsSecretsHunter
python3 jssecrethunter_gui.py
```

---

## 💻 Platform Setup

### Windows
```cmd
python jssecrethunter_gui.py
```

---

### WSL2 — Windows 11 (WSLg — zero config)
```bash
python3 jssecrethunter_gui.py
```

### WSL2 — Windows 10 (requires VcXsrv)

**Step 1:** Install **[VcXsrv](https://sourceforge.net/projects/vcxsrv/)** on Windows  
Launch: *Multiple windows* · Display=`0` · ✅ Disable access control

**Step 2:** Set DISPLAY in WSL (tool auto-detects, but you can set manually):
```bash
# Auto-detect Windows host IP (recommended)
export DISPLAY=$(ip route show default | awk '{print $3}'):0.0

# Then run
python3 jssecrethunter_gui.py
```

**Make permanent** — add to `~/.bashrc`:
```bash
echo 'export DISPLAY=$(ip route show default | awk '"'"'{print $3}'"'"'):0.0' >> ~/.bashrc
source ~/.bashrc
```

> **Why not `grep nameserver /etc/resolv.conf`?**  
> Some WSL2 configs include public DNS (8.8.8.8, 1.1.1.1) in resolv.conf.  
> `ip route` gives the actual Windows gateway IP, which is correct.

---

### Kali Linux / Ubuntu / Debian

```bash
# Install tkinter if missing
sudo apt install python3-tk -y

# Native desktop
python3 jssecrethunter_gui.py

# Headless (no desktop)
sudo apt install xvfb -y
Xvfb :99 -screen 0 1280x800x24 &
export DISPLAY=:99
python3 jssecrethunter_gui.py
```

---

## 🔧 Rate-Limit & Proxy Setup

### Rate-Limit Bypass Options (in GUI → Options)

| Setting | Description |
|---------|-------------|
| **Delay(s)** | Pause between requests (e.g. 0.3–1.0s). Reduces rate-limiting. |
| **Retries** | How many times to retry on 429/503. Uses exponential backoff. |
| **Threads** | Lower threads = less aggressive, less likely to be blocked. |

**Recommended for aggressive sites:** Threads=4, Delay=0.5s, Retries=4

### Proxy Setup (in GUI → Proxies section)

Paste proxies one per line:
```
http://1.2.3.4:8080
https://5.6.7.8:3128
socks5://user:pass@9.10.11.12:1080
http://user:pass@proxy.example.com:8888
```
Click **Apply Proxies** → tool rotates through them automatically.  
Failed proxies are marked and skipped for the session.

**Free proxy sources:** `proxy-list.download`, `proxyscrape.com`, `openproxy.space`

> For SOCKS5 support install: `pip install PySocks`

---
<img width="1377" height="967" alt="JsSecretHunter" src="https://github.com/user-attachments/assets/edf1a058-d832-4bec-9bf4-cf39a320b97e" />

## 📖 GUI Reference

| Control | Action |
|---------|--------|
| **URL** | Target website — auto-extracts all JS file links |
| **Bulk URL List** | `.txt` file, one URL per line |
| **Local Path** | Local `.js` file or directory |
| **Threads** | Concurrent workers (recommended: 4–10) |
| **Timeout(s)** | Per-request timeout |
| **Delay(s)** | Sleep between requests (rate-limit bypass) |
| **Retries** | Max retries per URL (exponential backoff) |
| **Severity** | CRITICAL / HIGH / MEDIUM / ALL |
| **Format** | JSON · CSV · TXT |
| **Scan HTML page** | Include page HTML in scan |
| **Dedup results** | Remove duplicate findings |
| **Proxies** | Paste proxy list, click Apply |
| **Reload Patterns** | Hot-reload regex file without restart |
| **▶ Start Scan** | Begin |
| **■ Stop** | Abort |
| **⟳ Auto-Update** | Update from GitHub |

---

## 🖥️ CLI Usage

```bash
python jssecrethunter.py -u https://target.com
python jssecrethunter.py -j https://cdn.target.com/app.js
python jssecrethunter.py -f targets.txt -o json -t 10
python jssecrethunter.py -l ./js_files/
python jssecrethunter.py -u https://target.com --severity HIGH
```

---

## 🎯 Pattern Coverage (600+)

| Category | Providers |
|----------|-----------|
| ☁️ Cloud | AWS, GCP, Azure, Heroku, DigitalOcean, Cloudflare, Vercel |
| 💳 Payment | Stripe, PayPal, Square, Razorpay, Adyen, Braintree |
| 📡 Comms | Twilio, SendGrid, Mailgun, Mailchimp, Firebase FCM |
| 🔑 Auth | JWT, OAuth2, Bearer, Basic, CSRF, Session tokens |
| 🔐 Keys | RSA, DSA, EC, PGP, OpenSSH, PKCS8 private keys |
| 🗄️ DBs | MySQL, PostgreSQL, MongoDB, Redis, Supabase, PlanetScale |
| 👥 Social | GitHub, GitLab, Slack, Discord, Twitter, Telegram |
| 🤖 AI/ML | OpenAI, Anthropic, HuggingFace, Groq, Replicate |
| 📊 Analytics | GA4, Mixpanel, Segment, HubSpot, Salesforce |
| 🔒 Secrets | HashiCorp Vault, Doppler, AWS Secrets Manager |

---

## 🤝 Contributing

Add patterns to `secretfinder_regexes.txt`:
```python
'pattern_name' : r'your_regex_here',
```
Click **Reload Patterns** — no restart needed.

---

## 📜 License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
Made with ❤️ by <a href="https://github.com/mohidqx"><b>mohidqx</b></a> / TeamCyberOps
</div>
