#!/usr/bin/env python3
"""
JSSecretHunter GUI v4.0.0
Author  : mohidqx / TeamCyberOps
GitHub  : https://github.com/mohidqx/jsSecretsHunter
License : MIT

HOW IT WORKS:
  - Provide a direct JS file URL  → fetches & scans that file
  - Provide a page URL            → extracts JS links, scans each JS file
  - Provide a bulk .txt list      → processes each URL/JS file
  - Provide a local directory     → scans all .js files recursively
  The tool runs ALL 600+ regex patterns on the JS file CONTENT.
"""

# ───────────────────────────────────────────────────────────────────────────────
# WSL / KALI DISPLAY FIX  —  MUST be FIRST, before any import
# ───────────────────────────────────────────────────────────────────────────────
import os, platform, subprocess, sys

def _fix_display():
    if platform.system() != 'Linux':
        return
    cur = os.environ.get('DISPLAY', '')
    if cur and ':' in cur:
        ip = cur.split(':')[0]
        bad = ('8.8.', '1.1.1', '9.9.', '208.', '4.2.', '0.0.0')
        if not any(ip.startswith(b) for b in bad):
            return   # already valid
    host = None
    # Method 1 — ip route (most reliable in WSL2)
    try:
        out  = subprocess.check_output(
            ['ip', 'route', 'show', 'default'],
            stderr=subprocess.DEVNULL, timeout=3).decode()
        host = out.strip().split()[2]
    except Exception:
        pass
    # Method 2 — resolv.conf skipping public DNS
    if not host:
        public = ('8.8.', '1.1.', '9.9.', '208.', '4.2.', '4.4.', '0.0.')
        try:
            with open('/etc/resolv.conf') as f:
                for ln in f:
                    if ln.startswith('nameserver'):
                        ip = ln.split()[1].strip()
                        if not any(ip.startswith(p) for p in public):
                            host = ip
                            break
        except Exception:
            pass
    os.environ['DISPLAY'] = f'{host}:0.0' if host else ':0'
    os.environ.setdefault('LIBGL_ALWAYS_INDIRECT', '1')
    os.environ.setdefault('GDK_BACKEND', 'x11')
    try:
        os.environ.setdefault('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}')
    except Exception:
        pass

_fix_display()

# ───────────────────────────────────────────────────────────────────────────────
# IMPORTS
# ───────────────────────────────────────────────────────────────────────────────
import re, json, time, threading, hashlib, random, shutil, socket, traceback
import urllib.request, urllib.error, urllib.parse
import csv, io, gzip
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

try:
    from PIL import Image, ImageTk, ImageDraw
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# ───────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ───────────────────────────────────────────────────────────────────────────────
VERSION  = '4.0.0'
REPO     = 'mohidqx/jsSecretsHunter'
LOGO_URL = 'https://github.com/mohidqx.png'
API_URL  = f'https://api.github.com/repos/{REPO}/releases/latest'
RAW_URL  = f'https://raw.githubusercontent.com/{REPO}/main/jssecrethunter_gui.py'
REGEX_F  = Path(__file__).parent / 'secretfinder_regexes.txt'

_IS_WIN = platform.system() == 'Windows'

# ───────────────────────────────────────────────────────────────────────────────
# PALETTE  (matched exactly to reference image)
# ───────────────────────────────────────────────────────────────────────────────
BG      = '#0b0f16'
BG2     = '#0e1520'
BG3     = '#111c28'
PANEL   = '#0d1822'
GLASS   = '#10202e'
GLASS2  = '#152535'
BORDER  = '#1c3044'
ACC     = '#e0102e'
ACC2    = '#ff2244'
ACC_DIM = '#180008'
RED     = '#ff5566'
AMBER   = '#f59e0b'
CYAN    = '#22d3ee'
GREEN   = '#00e5a0'
PURPLE  = '#8b5cf6'
TEXT    = '#c8d8e8'
TEXT2   = '#6a8090'
MUTED   = '#2e4050'
HDR     = '#070c12'
CODE_BG = '#070b10'
ROW_C   = '#1e0006'   # critical row
ROW_H   = '#120e00'   # high row
ROW_M   = '#001520'   # medium row

_FN  = 'Segoe UI'    if _IS_WIN else 'Ubuntu'
_FC  = 'Consolas'    if _IS_WIN else 'Monospace'
UI   = (_FN, 9)
UIB  = (_FN, 9,  'bold')
UI8  = (_FN, 8)
UI8B = (_FN, 8,  'bold')
UI7  = (_FN, 7)
H11  = (_FN, 11, 'bold')
H14  = (_FN, 14, 'bold')
H17  = (_FN, 17, 'bold')
MN9  = (_FC, 9)
MN8  = (_FC, 8)

# ───────────────────────────────────────────────────────────────────────────────
# USER-AGENT POOL
# ───────────────────────────────────────────────────────────────────────────────
_UAS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36',
    'Googlebot/2.1 (+http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; bingbot/2.0)',
]

# ───────────────────────────────────────────────────────────────────────────────
# PROXY MANAGER
# ───────────────────────────────────────────────────────────────────────────────
class ProxyMgr:
    def __init__(self):
        self._list   : list[str] = []
        self._failed : set[str]  = set()
        self._idx    = 0
        self._lock   = threading.Lock()

    def load(self, lines: list[str]):
        with self._lock:
            self._list   = [l.strip() for l in lines if l.strip()]
            self._failed.clear()
            self._idx    = 0

    def next(self) -> str | None:
        with self._lock:
            active = [p for p in self._list if p not in self._failed]
            if not active:
                return None
            p = active[self._idx % len(active)]
            self._idx += 1
            return p

    def fail(self, p: str):
        with self._lock:
            self._failed.add(p)

    @property
    def count(self): return len(self._list)
    @property
    def active_count(self): return len([p for p in self._list if p not in self._failed])


_PM = ProxyMgr()

# ───────────────────────────────────────────────────────────────────────────────
# HTTP FETCH  (rate-limit bypass: UA rotation + exponential backoff + proxy)
# ───────────────────────────────────────────────────────────────────────────────
_RL = {429, 503, 403, 509}

def fetch(url: str, timeout: int = 15, retries: int = 3, delay: float = 0.2) -> str | None:
    if delay > 0:
        time.sleep(delay + random.uniform(0, delay * 0.5))

    for attempt in range(retries):
        proxy = _PM.next()
        hdrs  = {
            'User-Agent'      : random.choice(_UAS),
            'Accept'          : 'text/html,application/javascript,*/*;q=0.8',
            'Accept-Language' : 'en-US,en;q=0.9',
            'Accept-Encoding' : 'gzip, deflate',
            'Connection'      : 'keep-alive',
            'Referer'         : 'https://www.google.com/',
        }
        try:
            opener = None
            if proxy:
                try:
                    opener = urllib.request.build_opener(
                        urllib.request.ProxyHandler({'http': proxy, 'https': proxy}))
                except Exception:
                    pass

            req    = urllib.request.Request(url, headers=hdrs)
            open_f = opener.open if opener else urllib.request.urlopen

            with open_f(req, timeout=timeout) as r:
                if r.getcode() in _RL:
                    raise urllib.error.HTTPError(url, r.getcode(), 'Rate-limited', {}, None)
                raw  = r.read()
                enc  = r.headers.get_content_charset() or 'utf-8'
                cenc = r.headers.get('Content-Encoding', '')
                if cenc == 'gzip':
                    raw = gzip.decompress(raw)
                return raw.decode(enc, errors='replace')

        except urllib.error.HTTPError as e:
            if e.code in _RL:
                if proxy: _PM.fail(proxy)
                time.sleep(min(2 ** attempt + random.uniform(0, 1.5), 30))
                continue
            return None
        except Exception:
            if proxy: _PM.fail(proxy)
            if attempt < retries - 1:
                time.sleep(1.5 ** attempt)
    return None


def is_js_url(url: str) -> bool:
    """True if URL directly points to a .js file."""
    path = urllib.parse.urlparse(url).path.lower()
    return path.endswith('.js') or '.js?' in path or '.js#' in path

# ───────────────────────────────────────────────────────────────────────────────
# JS LINK EXTRACTOR  (used when user provides a PAGE url, not a direct JS url)
# ───────────────────────────────────────────────────────────────────────────────
_SKIP = ('google-analytics', 'gtag', 'hotjar', 'clarity', 'facebook.net',
         'doubleclick', 'fbevents', 'amplitude', 'segment.io', 'mixpanel')

def extract_js_links(html: str, base: str) -> list[str]:
    parsed = urllib.parse.urlparse(base)
    root   = f"{parsed.scheme}://{parsed.netloc}"
    seen   = set()
    for pat in [
        r'(?:src|href)\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
        r'import\s+.*?from\s+["\']([^"\']+\.js[^"\']*)["\']',
        r'require\s*\(\s*["\']([^"\']+\.js)["\']',
        r'["\']([^"\']*?/[^"\']+\.js(?:\?[^"\']*)?)["\']',
    ]:
        for m in re.finditer(pat, html, re.I):
            h = m.group(1)
            if   h.startswith('http'): u = h
            elif h.startswith('//')  : u = f"{parsed.scheme}:{h}"
            elif h.startswith('/')   : u = f"{root}{h}"
            else:
                bp = '/'.join(parsed.path.split('/')[:-1])
                u  = f"{root}{bp}/{h}"
            if any(s in u.lower() for s in _SKIP): continue
            seen.add(u.split('?')[0])
    return list(seen)

# ───────────────────────────────────────────────────────────────────────────────
# REGEX LOADER
# ───────────────────────────────────────────────────────────────────────────────
def load_regexes(path: Path) -> dict:
    if not path.exists(): return {}
    out = {}
    for m in re.finditer(r"'([^']+)'\s*:\s*r'([^']*)'",
                          path.read_text(encoding='utf-8', errors='replace')):
        n, p = m.group(1), m.group(2)
        try:
            re.compile(p)
            out[n] = p
        except re.error:
            pass
    return out

_rex_raw = load_regexes(REGEX_F)
if not _rex_raw:
    _rex_raw = {
        'google_api_key'   : r'AIza[0-9A-Za-z\-_]{35}',
        'aws_access_key'   : r'(?:AKIA|AGPA|AIDA|AROA)[A-Z0-9]{16}',
        'stripe_live'      : r'sk_live_[0-9a-zA-Z]{24}',
        'github_pat'       : r'ghp_[0-9a-zA-Z]{36}',
        'slack_bot'        : r'xoxb-[0-9]{11}-[0-9]{11,13}-[0-9a-zA-Z]{24}',
        'openai_key'       : r'sk-[0-9A-Za-z]{48}',
        'jwt'              : r'ey[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_\.\+/=]*',
        'rsa_private'      : r'-----BEGIN RSA PRIVATE KEY-----',
        'hardcoded_api_key': r'(?i)(?:api_key|apikey|api-key)\s*[=:]\s*["\'][^"\']{10,}["\']',
        'hardcoded_secret' : r'(?i)(?:secret|password|passwd)\s*[=:]\s*["\'][^"\']{8,}["\']',
        'db_connection'    : r'(?i)(?:mysql|postgres|mongodb|redis)://[^\s"\']+',
    }

_compiled : dict[str, re.Pattern] = {n: re.compile(p) for n, p in _rex_raw.items()}

_CRIT = {
    'rsa_private_key','dsa_private_key','ec_private_key','pgp_private_key',
    'openssh_private_key','pkcs8_private_key','google_cloud_private_key',
    'ethereum_private_key','stripe_live_secret_key','amazon_aws_secret_access_key',
    'amazon_aws_access_key_id','twilio_auth_token','sendgrid_api_key',
    'hashicorp_vault_token','openai_api_key','anthropic_api_key',
    'mysql_connection_string','postgres_connection_string','mongo_atlas_connection',
}
_HIGH = {
    'github_pat_classic','github_fine_grained_pat','gitlab_pat','slack_bot_token',
    'discord_bot_token','telegram_bot_token','facebook_access_token',
    'twitter_bearer_token','stripe_test_secret_key','mailgun_api_key',
    'sentry_dsn','azure_storage_connection_string','heroku_api_key',
    'cloudflare_api_token','shopify_private_app_token',
}

def _sev(n: str) -> str:
    if n in _CRIT: return 'CRITICAL'
    if n in _HIGH: return 'HIGH'
    return 'MEDIUM'

# ───────────────────────────────────────────────────────────────────────────────
# SCANNER  — runs ALL regexes on JS file CONTENT
# ───────────────────────────────────────────────────────────────────────────────
def scan_js_content(content: str, source: str) -> list[dict]:
    """
    Run every regex pattern against the raw JS file content.
    Returns list of findings with redacted values.
    """
    results, seen = [], set()
    lines = content.splitlines()
    for name, pat in _compiled.items():
        for m in pat.finditer(content):
            val = m.group(0)
            uid = hashlib.md5(f"{name}:{val}".encode()).hexdigest()
            if uid in seen: continue
            seen.add(uid)
            ln  = content[:m.start()].count('\n') + 1
            ctx = (lines[ln - 1].strip() if ln <= len(lines) else '')[:300]
            # Redact the middle of sensitive values for display
            redacted = _redact(val)
            results.append({
                'source'   : source,
                'type'     : _friendly_name(name),
                'type_raw' : name,
                'severity' : _sev(name),
                'value'    : redacted,
                'value_raw': val,
                'line'     : ln,
                'context'  : ctx,
            })
    return results

def _redact(val: str) -> str:
    """Show first 8 chars, redact middle, keep last 4."""
    if len(val) <= 16:
        return val
    show = min(8, len(val) // 4)
    stars = '*' * min(len(val) - show - 4, 20)
    return f'"{val[:show]}{stars}{val[-4:]}"'

def _friendly_name(raw: str) -> str:
    """Convert snake_case pattern name to friendly display name."""
    mapping = {
        'hardcoded_api_key'           : 'Hardcoded API Key',
        'hardcoded_secret'            : 'Hardcoded Secret',
        'google_api_key'              : 'Google API Key',
        'amazon_aws_access_key_id'    : 'AWS Access Key',
        'amazon_aws_secret_access_key': 'AWS Secret Key',
        'stripe_live_secret_key'      : 'Stripe Live Key',
        'stripe_test_secret_key'      : 'Stripe Test Key',
        'github_pat_classic'          : 'GitHub PAT',
        'github_fine_grained_pat'     : 'GitHub Fine-Grained PAT',
        'slack_bot_token'             : 'Slack Bot Token',
        'openai_api_key'              : 'OpenAI API Key',
        'anthropic_api_key'           : 'Anthropic API Key',
        'jwt'                         : 'JSON Web Token',
        'rsa_private_key'             : 'RSA Private Key',
        'mysql_connection_string'     : 'MySQL Connection String',
        'postgres_connection_string'  : 'PostgreSQL Connection',
        'mongo_atlas_connection'      : 'MongoDB Atlas Connection',
        'db_connection'               : 'Database Connection String',
        'sendgrid_api_key'            : 'SendGrid API Key',
        'mailgun_api_key'             : 'Mailgun API Key',
        'twilio_auth_token'           : 'Twilio Auth Token',
        'facebook_access_token'       : 'Facebook Access Token',
        'twitter_bearer_token'        : 'Twitter Bearer Token',
        'discord_bot_token'           : 'Discord Bot Token',
        'telegram_bot_token'          : 'Telegram Bot Token',
        'cloudflare_api_token'        : 'Cloudflare API Token',
        'heroku_api_key'              : 'Heroku API Key',
        'shopify_private_app_token'   : 'Shopify Private Token',
        'hashicorp_vault_token'       : 'HashiCorp Vault Token',
        'hardcoded_password_assignment': 'Exposed Database Credentials',
        'db_password'                 : 'Exposed Database',
        'env_password'                : 'Exposed Credentials',
        'env_secret'                  : 'Exposed Secret',
        'env_api_key'                 : 'Exposed API Key',
        'json_password_field'         : 'Exposed Database Credentials',
        'generic_secret_32'           : 'Generic Secret',
        'generic_secret_40'           : 'Generic Secret',
    }
    if raw in mapping: return mapping[raw]
    return raw.replace('_', ' ').title()

# ───────────────────────────────────────────────────────────────────────────────
# REPORT WRITER
# ───────────────────────────────────────────────────────────────────────────────
def write_report(data: list[dict], path: Path, fmt: str):
    clean = [{k: v for k, v in f.items() if k != 'value_raw'} for f in data]
    if fmt == 'json':
        path.write_text(json.dumps(clean, indent=2), encoding='utf-8')
    elif fmt == 'csv':
        buf = io.StringIO()
        w   = csv.DictWriter(buf, fieldnames=['source','type','severity','value','line','context'])
        w.writeheader()
        w.writerows(clean)
        path.write_text(buf.getvalue(), encoding='utf-8')
    else:
        lns = []
        for f in clean:
            lns += [f"[{f['severity']}] {f['type']}",
                    f"  Source : {f['source']}",
                    f"  Line   : {f['line']}",
                    f"  Value  : {f['value']}",
                    f"  Context: {f['context']}", '']
        path.write_text('\n'.join(lns), encoding='utf-8')

# ───────────────────────────────────────────────────────────────────────────────
# AUTO-UPDATE
# ───────────────────────────────────────────────────────────────────────────────
def do_update(log_fn):
    log_fn('Checking GitHub for updates…', 'info')
    try:
        raw  = fetch(API_URL, timeout=8)
        data = json.loads(raw or '{}')
        tag  = data.get('tag_name', '').lstrip('v')
        if not tag:
            log_fn('Could not read version from API.', 'warn')
            messagebox.showwarning('Auto-Update', 'Cannot reach GitHub.'); return
        if tag == VERSION:
            log_fn(f'Already on latest v{VERSION}.', 'ok')
            messagebox.showinfo('Auto-Update', f'Already latest v{VERSION}.'); return
        url     = next((a['browser_download_url'] for a in data.get('assets', [])
                        if a['name'].endswith('.py')), RAW_URL)
        content = fetch(url, timeout=30)
        if not content:
            log_fn('Download failed.', 'error'); return
        sp = Path(__file__).resolve()
        shutil.copy2(sp, sp.with_suffix('.bak'))
        sp.write_text(content, encoding='utf-8')
        log_fn(f'Updated to v{tag} — restarting…', 'ok')
        messagebox.showinfo('Auto-Update', f'Updated to v{tag}!')
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        log_fn(f'Update error: {e}', 'error')

# ───────────────────────────────────────────────────────────────────────────────
# MINI WIDGETS
# ───────────────────────────────────────────────────────────────────────────────
class BarChart(tk.Canvas):
    """Animated mini bar chart for thread usage."""
    def __init__(self, parent, bars=8, **kw):
        kw.setdefault('bg', PANEL)
        kw.setdefault('highlightthickness', 0)
        kw.setdefault('width', 64)
        kw.setdefault('height', 18)
        super().__init__(parent, **kw)
        self._vals = [random.uniform(0.1, 1.0) for _ in range(bars)]
        self._bars = bars
        self._after_id = None
        self.bind('<Destroy>', lambda _: self._cancel())
        self._anim()

    def _cancel(self):
        if self._after_id:
            try: self.after_cancel(self._after_id)
            except Exception: pass

    def _anim(self):
        self.delete('all')
        w, h = max(self.winfo_width(), 64), max(self.winfo_height(), 18)
        bw   = max(1, (w - 2) // self._bars - 1)
        for i, v in enumerate(self._vals):
            x0  = 1 + i * (bw + 1)
            bh  = max(1, int((h - 2) * v))
            clr = ACC if v > 0.8 else AMBER if v > 0.5 else GREEN
            self.create_rectangle(x0, h - 1 - bh, x0 + bw, h - 1,
                                  fill=clr, outline='')
        self._vals = self._vals[1:] + [random.uniform(0.1, 1.0)]
        self._after_id = self.after(450, self._anim)


class DonutChart(tk.Canvas):
    """Severity breakdown donut."""
    def __init__(self, parent, **kw):
        kw.setdefault('bg', GLASS)
        kw.setdefault('highlightthickness', 0)
        kw.setdefault('width', 180)
        kw.setdefault('height', 130)
        super().__init__(parent, **kw)
        self._d = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0}
        self.bind('<Configure>', lambda _: self.draw())
        self.draw()

    def update(self, findings: list[dict]):
        self._d = {
            'CRITICAL': sum(1 for f in findings if f['severity'] == 'CRITICAL'),
            'HIGH'    : sum(1 for f in findings if f['severity'] == 'HIGH'),
            'MEDIUM'  : sum(1 for f in findings if f['severity'] == 'MEDIUM'),
        }
        self.draw()

    def draw(self):
        self.delete('all')
        w, h  = max(self.winfo_width(), 180), max(self.winfo_height(), 130)
        cx, cy = w // 2, h // 2
        r, ri  = min(cx, cy) - 8, min(cx, cy) - 26
        total  = sum(self._d.values()) or 1
        clrs   = [('CRITICAL', RED), ('HIGH', AMBER), ('MEDIUM', CYAN)]
        start  = -90.0
        for key, clr in clrs:
            ext = (self._d[key] / total) * 360
            if ext > 1:
                self.create_arc(cx - r, cy - r, cx + r, cy + r,
                                start=start, extent=ext,
                                fill=clr, outline=GLASS, width=2)
            start += ext
        # Inner hole
        self.create_oval(cx - ri, cy - ri, cx + ri, cy + ri,
                         fill=GLASS, outline='')
        # Center text
        tot = sum(self._d.values())
        self.create_text(cx, cy - 4, text=str(tot),
                         font=(_FN, 12, 'bold'), fill=TEXT)
        self.create_text(cx, cy + 10, text='findings',
                         font=(_FN, 7), fill=TEXT2)


class SparkLine(tk.Canvas):
    """Findings-over-time sparkline."""
    def __init__(self, parent, **kw):
        kw.setdefault('bg', GLASS)
        kw.setdefault('highlightthickness', 0)
        kw.setdefault('width', 180)
        kw.setdefault('height', 90)
        super().__init__(parent, **kw)
        self._pts: list[int] = []
        self.bind('<Configure>', lambda _: self._draw())
        self._draw()

    def push(self, n: int):
        self._pts.append(n)
        if len(self._pts) > 40:
            self._pts = self._pts[-40:]
        self._draw()

    def _draw(self):
        self.delete('all')
        w, h  = max(self.winfo_width(), 180), max(self.winfo_height(), 90)
        pad   = 18
        iw, ih = w - pad - 8, h - pad - 8
        pts   = self._pts or [0]
        mx    = max(max(pts), 1)

        # Y grid + labels
        for i in range(5):
            yv  = int(mx * i / 4)
            yp  = pad + ih - int(yv / mx * ih)
            self.create_line(pad, yp, w - 8, yp,
                             fill=MUTED, dash=(2, 4))
            self.create_text(pad - 2, yp, text=str(yv),
                             font=(_FN, 6), fill=TEXT2, anchor='e')

        if len(pts) < 2:
            return

        step   = iw / (len(pts) - 1)
        coords = []
        for i, v in enumerate(pts):
            xp = pad + i * step
            yp = pad + ih - int(v / mx * ih)
            coords += [xp, yp]

        # Fill area
        fp = [pad, pad + ih] + coords + [pad + iw, pad + ih]
        self.create_polygon(fp, fill='#00182a', outline='')
        # Line
        self.create_line(coords, fill=ACC, width=2, smooth=True)
        # Last dot
        self.create_oval(coords[-2] - 3, coords[-1] - 3,
                         coords[-2] + 3, coords[-1] + 3,
                         fill=ACC, outline='')


# ───────────────────────────────────────────────────────────────────────────────
# TTK STYLE
# ───────────────────────────────────────────────────────────────────────────────
def _apply_style():
    s = ttk.Style()
    s.theme_use('default')
    s.configure('.', background=BG, foreground=TEXT,
                fieldbackground=BG3, borderwidth=0, font=UI)

    for name, bg in [('TFrame', BG), ('Panel.TFrame', PANEL),
                     ('Glass.TFrame', GLASS), ('G2.TFrame', GLASS2),
                     ('HDR.TFrame', HDR), ('Code.TFrame', CODE_BG)]:
        s.configure(name, background=bg)

    for name, bg, fg in [
        ('TLabel', BG, TEXT), ('P.TLabel', PANEL, TEXT),
        ('G.TLabel', GLASS, TEXT), ('M.TLabel', PANEL, MUTED),
        ('T2.TLabel', PANEL, TEXT2), ('Acc.TLabel', PANEL, ACC),
        ('Gr.TLabel', PANEL, GREEN), ('HDR.TLabel', HDR, TEXT)
    ]:
        s.configure(name, background=bg, foreground=fg)

    s.configure('TEntry',
        fieldbackground=BG3, foreground=TEXT,
        insertbackground=ACC, relief='flat', padding=5)
    s.configure('TCombobox',
        fieldbackground=BG3, foreground=TEXT,
        selectbackground=ACC, relief='flat', padding=5)
    s.map('TCombobox', fieldbackground=[('readonly', BG3)])

    s.configure('TSpinbox',
        fieldbackground=BG3, foreground=TEXT,
        insertbackground=ACC, relief='flat', padding=5)

    s.configure('TNotebook', background=BG2, borderwidth=0, tabmargins=[0, 0, 0, 0])
    s.configure('TNotebook.Tab',
        background=BG2, foreground=TEXT2, padding=[14, 9], font=UIB)
    s.map('TNotebook.Tab',
        background=[('selected', GLASS)],
        foreground=[('selected', ACC)])

    s.configure('Treeview',
        background=BG2, foreground=TEXT,
        fieldbackground=BG2, rowheight=27,
        borderwidth=0, font=MN9)
    s.configure('Treeview.Heading',
        background=BG3, foreground=TEXT2, font=UIB, relief='flat')
    s.map('Treeview',
        background=[('selected', ACC_DIM)],
        foreground=[('selected', ACC2)])

    s.configure('TScrollbar',
        background=BG2, troughcolor=BG,
        arrowcolor=MUTED, borderwidth=0, relief='flat')
    s.configure('TProgressbar',
        background=ACC, troughcolor=BG3,
        borderwidth=0, thickness=4)

    s.configure('Red.TButton',
        background=ACC, foreground='#ffffff',
        font=UIB, padding=[20, 9], relief='flat')
    s.map('Red.TButton',
        background=[('active', ACC2), ('disabled', MUTED)],
        foreground=[('disabled', BG3)])

    s.configure('Ghost.TButton',
        background=GLASS2, foreground=TEXT2,
        font=UI, padding=[10, 6], relief='flat')
    s.map('Ghost.TButton',
        background=[('active', BORDER)],
        foreground=[('active', TEXT)])

    s.configure('Sm.TButton',
        background=GLASS, foreground=TEXT2,
        font=UI8, padding=[7, 4], relief='flat')
    s.map('Sm.TButton',
        background=[('active', GLASS2)],
        foreground=[('active', TEXT)])

    s.configure('SmRed.TButton',
        background=GLASS, foreground=ACC,
        font=UI8, padding=[7, 4], relief='flat')
    s.map('SmRed.TButton',
        background=[('active', ACC_DIM)])

    s.configure('Stop.TButton',
        background='#12000a', foreground=RED,
        font=UIB, padding=[14, 9], relief='flat')
    s.map('Stop.TButton',
        background=[('active', '#1e0010'), ('disabled', BG3)],
        foreground=[('disabled', MUTED)])

    s.configure('TCheckbutton', background=PANEL, foreground=TEXT2, font=UI)
    s.map('TCheckbutton', background=[('active', PANEL)])

    s.configure('TScale',
        background=PANEL, troughcolor=BG3,
        sliderlength=12, sliderrelief='flat')


# ───────────────────────────────────────────────────────────────────────────────
# LOGO LOADER
# ───────────────────────────────────────────────────────────────────────────────
def _load_logo(size: int = 38):
    try:
        raw = urllib.request.urlopen(LOGO_URL, timeout=5).read()
        if HAS_PIL:
            import io as _io
            img  = Image.open(_io.BytesIO(raw)).resize((size, size), Image.LANCZOS).convert('RGBA')
            mask = Image.new('L', (size, size), 0)
            ImageDraw.Draw(mask).ellipse((0, 0, size, size), fill=255)
            res  = Image.new('RGBA', (size, size), (0, 0, 0, 0))
            res.paste(img, mask=mask)
            return ImageTk.PhotoImage(res)
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            f.write(raw); tmp = f.name
        p = tk.PhotoImage(file=tmp)
        try: os.unlink(tmp)
        except: pass
        return p
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════
class App:
    def __init__(self, root: tk.Tk):
        self.root         = root
        self.findings     : list[dict] = []
        self._code_cache  : dict[str, str] = {}
        self.scan_active  = False
        self._logo_img    = None
        self._sort_rev    : dict[str, bool] = {}
        self._start_ts    = 0.0
        self._elapsed_id  = None
        self._spark_pts   : list[int] = []

        _apply_style()
        self._build_ui()
        threading.Thread(target=self._fetch_logo, daemon=True).start()

        self._log(f'JSSecretHunter v{VERSION} ready', 'ok')
        self._log(f'Platform : {platform.system()} {platform.release()}', 'dim')
        self._log(f'DISPLAY  : {os.environ.get("DISPLAY","N/A")}', 'dim')
        src = REGEX_F.name if REGEX_F.exists() else 'built-in fallback'
        self._log(f'Patterns : {len(_compiled)} from {src}', 'info')
        if not REGEX_F.exists():
            self._log('⚠  secretfinder_regexes.txt not found!', 'warn')

    def _fetch_logo(self):
        p = _load_logo(38)
        if p:
            self._logo_img = p
            self.root.after(0, lambda: self._logo_lbl.configure(image=p, text=''))

    # ── WINDOW ─────────────────────────────────────────────────────────────────
    def _build_ui(self):
        self.root.title('JSSecretHunter')
        self.root.geometry('1380x900')
        self.root.minsize(1100, 720)
        self.root.configure(bg=BG)
        if _IS_WIN:
            try:
                from ctypes import windll
                windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                pass
        self._build_header()
        self._build_body()
        self._build_statusbar()

    # ── HEADER ─────────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self.root, bg=HDR, height=60)
        hdr.pack(fill='x')
        hdr.pack_propagate(False)

        # Left stripe
        tk.Frame(hdr, bg=ACC, width=4).pack(side='left', fill='y')

        # Logo
        self._logo_lbl = tk.Label(hdr, text='⬡', font=('', 20),
                                   bg=HDR, fg=ACC)
        self._logo_lbl.pack(side='left', padx=(12, 6))

        # Title
        tk.Label(hdr, text='JSSecretHunter', font=H17,
                 bg=HDR, fg=TEXT).pack(side='left')
        tk.Label(hdr, text=f'  v{VERSION}', font=UI,
                 bg=HDR, fg=TEXT2).pack(side='left')

        # Badge
        bd = tk.Frame(hdr, bg=ACC_DIM)
        bd.pack(side='left', padx=12)
        tk.Label(bd, text='  AUTHORIZED USE ONLY  ',
                 font=UI8B, bg=ACC_DIM, fg=ACC).pack(padx=0, pady=3)

        # Center — Scan Status + progress + elapsed
        ctr = tk.Frame(hdr, bg=HDR)
        ctr.pack(side='left', fill='both', expand=True, padx=30)

        row1 = tk.Frame(ctr, bg=HDR)
        row1.pack(fill='x', pady=(6, 0))

        tk.Label(row1, text='Scan Status:', font=UIB,
                 bg=HDR, fg=TEXT2).pack(side='left')
        tk.Label(row1, text=' ⓘ', font=UI, bg=HDR, fg=TEXT2).pack(side='left')
        self._scan_st = tk.Label(row1, text='  Ready',
                                  font=UI, bg=HDR, fg=MUTED)
        self._scan_st.pack(side='left')
        self._elapsed_lbl = tk.Label(row1, text='Elapsed: 00:00',
                                      font=UI, bg=HDR, fg=CYAN)
        self._elapsed_lbl.pack(side='right', padx=6)

        self.hdr_prog_var = tk.DoubleVar()
        ttk.Progressbar(ctr, variable=self.hdr_prog_var,
                        maximum=100, style='TProgressbar').pack(
            fill='x', pady=(4, 6))

        # Right
        rr = tk.Frame(hdr, bg=HDR)
        rr.pack(side='right', padx=12)
        ttk.Button(rr, text='⟳ Auto-Update', style='Ghost.TButton',
                   command=lambda: threading.Thread(
                       target=do_update, args=(self._log,), daemon=True).start()
                   ).pack(side='right', padx=4)
        tk.Label(rr, text='github.com/mohidqx',
                 font=UI8, bg=HDR, fg=TEXT2).pack(side='right', padx=8)

        # Thin accent rule
        tk.Frame(self.root, bg=ACC, height=1).pack(fill='x')

    # ── BODY ───────────────────────────────────────────────────────────────────
    def _build_body(self):
        pw = tk.PanedWindow(self.root, orient='horizontal',
                             bg=BORDER, sashwidth=3, sashrelief='flat', bd=0)
        pw.pack(fill='both', expand=True)
        pw.add(self._build_left(),  minsize=285, width=292)
        pw.add(self._build_right(), minsize=680)

    # ══════════════════════════════════════════════════════════════════════════
    # LEFT PANEL
    # ══════════════════════════════════════════════════════════════════════════
    def _build_left(self):
        outer  = tk.Frame(self.root, bg=BG2)
        canvas = tk.Canvas(outer, bg=BG2, highlightthickness=0, bd=0)
        vsb    = ttk.Scrollbar(outer, orient='vertical', command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side='left', fill='both', expand=True)
        vsb.pack(side='right', fill='y')

        inner = tk.Frame(canvas, bg=BG2)
        win   = canvas.create_window((0, 0), window=inner, anchor='nw')
        canvas.bind('<Configure>',
                    lambda e: canvas.itemconfigure(win, width=e.width))
        inner.bind('<Configure>',
                   lambda e: canvas.configure(scrollregion=canvas.bbox('all')))

        def _mw(e):
            delta = int(-1 * (e.delta / 120)) if hasattr(e, 'delta') and e.delta else 1
            canvas.yview_scroll(delta, 'units')
        canvas.bind_all('<MouseWheel>', _mw)
        canvas.bind_all('<Button-4>',   lambda _: canvas.yview_scroll(-1, 'units'))
        canvas.bind_all('<Button-5>',   lambda _: canvas.yview_scroll(1, 'units'))

        # ── helpers ─────────────────────────────────────────────────────────
        def sec_hdr(title, extra_fn=None):
            hf = tk.Frame(inner, bg=ACC_DIM)
            hf.pack(fill='x', pady=(8, 0))
            tk.Label(hf, text=f' {title}',
                     font=UI8B, bg=ACC_DIM, fg=ACC).pack(side='left', pady=3, padx=4)
            if extra_fn:
                extra_fn(hf)
            body = tk.Frame(inner, bg=PANEL,
                            highlightbackground=BORDER,
                            highlightthickness=1)
            body.pack(fill='x')
            return body

        def row(parent, label, var, btn=None, cmd=None, validate=False):
            if label:
                tk.Label(parent, text=label, font=UI8,
                         bg=PANEL, fg=TEXT2).pack(anchor='w', padx=8, pady=(4, 1))
            r = tk.Frame(parent, bg=PANEL)
            r.pack(fill='x', padx=8, pady=(0, 5))
            e = ttk.Entry(r, textvariable=var, font=MN8)
            e.pack(side='left', fill='x', expand=True)
            if btn:
                ttk.Button(r, text=btn, style='Sm.TButton',
                           command=cmd).pack(side='right', padx=(4, 0))
            return e

        # ── TARGET ──────────────────────────────────────────────────────────
        t = sec_hdr('TARGET')
        tk.Label(t, text='URL  (crawls all JS from page)', font=UI8,
                 bg=PANEL, fg=TEXT2).pack(anchor='w', padx=8, pady=(4, 1))
        ur = tk.Frame(t, bg=PANEL)
        ur.pack(fill='x', padx=8, pady=(0, 5))
        self.url_var = tk.StringVar()
        ttk.Entry(ur, textvariable=self.url_var, font=MN8).pack(
            side='left', fill='x', expand=True)
        self._url_ok = tk.Label(ur, text='', font=('', 10), bg=PANEL, fg=GREEN)
        self._url_ok.pack(side='right', padx=(4, 0))
        self.url_var.trace_add('write', self._chk_url)

        self.bulk_var  = tk.StringVar()
        self.local_var = tk.StringVar()
        row(t, 'Bulk URL list  (.txt)', self.bulk_var,  '…',  self._br_bulk)
        row(t, 'Local JS file / directory', self.local_var, '📁', self._br_local)

        # ── OPTIONS ─────────────────────────────────────────────────────────
        def opt_extra(hf):
            tk.Label(hf, text='Thread usage', font=UI7,
                     bg=ACC_DIM, fg=TEXT2).pack(side='right', padx=4)
            BarChart(hf, bars=8, bg=ACC_DIM,
                     width=60, height=14).pack(side='right', padx=(0, 4), pady=2)

        o = sec_hdr('OPTIONS', opt_extra)
        og = tk.Frame(o, bg=PANEL)
        og.pack(fill='x', padx=8, pady=4)
        for i in range(4): og.columnconfigure(i, weight=1)

        def spin(lbl, var, r, c, lo=1, hi=100, w=5):
            tk.Label(og, text=lbl, font=UI8, bg=PANEL,
                     fg=TEXT2).grid(row=r, column=c, sticky='w', pady=2)
            ttk.Spinbox(og, from_=lo, to=hi, textvariable=var,
                        width=w).grid(row=r, column=c+1, sticky='w', padx=(3,10))

        self.thr_var  = tk.IntVar(value=8)
        self.to_var   = tk.IntVar(value=15)
        self.del_var  = tk.DoubleVar(value=0.3)
        self.ret_var  = tk.IntVar(value=3)
        spin('Threads',    self.thr_var,  0, 0)
        spin('Timeout(s)', self.to_var,   0, 2, 5, 120)
        spin('Delay(s)',   self.del_var,  1, 0, w=6)

        # Retries with mini bar
        tk.Label(og, text='Retries', font=UI8, bg=PANEL,
                 fg=TEXT2).grid(row=1, column=2, sticky='w', pady=2)
        rf = tk.Frame(og, bg=PANEL)
        rf.grid(row=1, column=3, sticky='w')
        ttk.Spinbox(rf, from_=1, to=10, textvariable=self.ret_var,
                    width=3).pack(side='left')
        BarChart(rf, bars=6, bg=PANEL, width=48, height=14).pack(side='left', padx=3)

        ck = tk.Frame(o, bg=PANEL)
        ck.pack(fill='x', padx=8, pady=(0, 4))
        self.scan_pg_var = tk.BooleanVar(value=True)
        self.dedup_var   = tk.BooleanVar(value=True)
        ttk.Checkbutton(ck, text='Scan HTML page',
                        variable=self.scan_pg_var).pack(side='left')
        ttk.Checkbutton(ck, text='Dedup results',
                        variable=self.dedup_var).pack(side='left', padx=10)

        # Scan Depth
        sd_row = tk.Frame(o, bg=PANEL)
        sd_row.pack(fill='x', padx=8, pady=(0, 2))
        tk.Label(sd_row, text='Scan Depth', font=UI8, bg=PANEL,
                 fg=TEXT2).pack(side='left')
        self.depth_var = tk.IntVar(value=2)
        ttk.Scale(sd_row, from_=1, to=5, variable=self.depth_var,
                  orient='horizontal').pack(side='left', fill='x', expand=True, padx=6)
        dl = tk.Frame(o, bg=PANEL)
        dl.pack(fill='x', padx=8, pady=(0, 6))
        for i, n in enumerate('12345', 1):
            tk.Label(dl, text=n, font=UI7, bg=PANEL,
                     fg=TEXT2).pack(side='left', expand=True)

        # ── OUTPUT DIR ──────────────────────────────────────────────────────
        def od_extra(hf):
            ttk.Button(hf, text='JSON', style='Sm.TButton',
                       command=self._quick_json).pack(side='right', padx=2, pady=2)
            ttk.Button(hf, text='PDF',  style='Sm.TButton',
                       command=self._quick_pdf).pack(side='right', padx=2, pady=2)
            tk.Label(hf, text='Quick view:', font=UI7,
                     bg=ACC_DIM, fg=TEXT2).pack(side='right', padx=4)

        od = sec_hdr('OUTPUT DIRECTORY', od_extra)
        self.out_var = tk.StringVar(value=str(Path.cwd() / 'output'))
        row(od, '', self.out_var, '📂', self._br_out)

        # ── REGEX FILE ──────────────────────────────────────────────────────
        def rf_extra(hf):
            BarChart(hf, bars=6, bg=ACC_DIM, width=44, height=14).pack(
                side='right', padx=(0, 4), pady=2)
            tk.Label(hf, text='Custom profile applied.',
                     font=UI7, bg=ACC_DIM, fg=GREEN).pack(side='right', padx=4)

        rxf = sec_hdr('REGEX FILE', rf_extra)
        self._rex_lbl = tk.Label(rxf,
            text=f'Loaded {len(_compiled)} patterns. Custom profile applied.',
            font=UI8B, bg=PANEL, fg=GREEN if REGEX_F.exists() else AMBER)
        self._rex_lbl.pack(anchor='w', padx=8, pady=(4, 2))

        self.rex_var = tk.StringVar(value=str(REGEX_F))
        row(rxf, '', self.rex_var, '…', self._br_regex)

        rb = tk.Frame(rxf, bg=PANEL)
        rb.pack(fill='x', padx=8, pady=(0, 8))
        ttk.Button(rb, text='⟳ Reload Patterns', style='SmRed.TButton',
                   command=self._reload_pats).pack(side='left')
        tk.Label(rb, text='  Custom profile applied', font=UI8,
                 bg=PANEL, fg=GREEN).pack(side='left')

        # ── PROXIES ─────────────────────────────────────────────────────────
        px = sec_hdr('PROXIES  (one per line: http/https/socks5://host:port)')
        self._proxy_txt = tk.Text(px, bg=BG3, fg=TEXT2,
                                   insertbackground=ACC,
                                   font=MN8, height=4, relief='flat', wrap='none')
        self._proxy_txt.pack(fill='x', padx=8, pady=(4, 4))

        # Quick presets
        qp = tk.Frame(px, bg=PANEL)
        qp.pack(fill='x', padx=8, pady=(0, 4))
        tk.Label(qp, text='Quick presets:', font=UI8, bg=PANEL,
                 fg=TEXT2).pack(side='left')
        for lbl in ['Proxy presets', 'Different proxy', 'UMSP proxy']:
            ttk.Button(qp, text=lbl, style='Sm.TButton',
                       command=lambda l=lbl: self._proxy_preset(l)
                       ).pack(side='left', padx=(4, 0))

        self._px_val = tk.Label(px,
            text='Validation list: 0 patterns mattore loaded',
            font=UI8, bg=PANEL, fg=MUTED)
        self._px_val.pack(anchor='w', padx=8, pady=(0, 4))

        pb = tk.Frame(px, bg=PANEL)
        pb.pack(fill='x', padx=8, pady=(0, 8))
        ttk.Button(pb, text='Apply Proxies', style='Sm.TButton',
                   command=self._apply_proxies).pack(side='left')
        ttk.Button(pb, text='Clear', style='Sm.TButton',
                   command=lambda: self._proxy_txt.delete('1.0', 'end')
                   ).pack(side='left', padx=4)
        self._px_lbl = tk.Label(pb, text='No proxies', font=UI8,
                                 bg=PANEL, fg=MUTED)
        self._px_lbl.pack(side='left', padx=8)

        # ── ACTIONS ─────────────────────────────────────────────────────────
        tk.Frame(inner, bg=BG2, height=8).pack(fill='x')
        ab = tk.Frame(inner, bg=BG2)
        ab.pack(fill='x', padx=8, pady=4)
        self.scan_btn = ttk.Button(ab, text='▶  START SCAN',
                                    style='Red.TButton',
                                    command=self._start_scan)
        self.scan_btn.pack(side='left', fill='x', expand=True)
        self.stop_btn = ttk.Button(ab, text='■  STOP',
                                    style='Stop.TButton',
                                    command=self._stop_scan,
                                    state='disabled')
        self.stop_btn.pack(side='right', padx=(6, 0))

        # ── STATS ───────────────────────────────────────────────────────────
        sg = tk.Frame(inner, bg=BG2)
        sg.pack(fill='x', padx=8, pady=(4, 6))
        for i in range(4):
            sg.columnconfigure(i, weight=1)
        self._st_total = self._stat(sg, '0', 'TOTAL',    0, TEXT)
        self._st_crit  = self._stat(sg, '0', 'CRITICAL', 1, RED)
        self._st_high  = self._stat(sg, '0', 'HIGH',     2, AMBER)
        self._st_med   = self._stat(sg, '0', 'MEDIUM',   3, CYAN)

        return outer

    def _stat(self, parent, val, label, col, fg):
        box = tk.Frame(parent, bg=GLASS,
                       highlightbackground=BORDER,
                       highlightthickness=1)
        box.grid(row=0, column=col, sticky='nsew', padx=2)
        n = tk.Label(box, text=val, font=(_FN, 18, 'bold'),
                     bg=GLASS, fg=fg)
        n.pack(pady=(6, 0))
        tk.Label(box, text=label, font=UI7 + ('bold',),
                 bg=GLASS, fg=MUTED).pack(pady=(0, 6))
        return n

    # ══════════════════════════════════════════════════════════════════════════
    # RIGHT PANEL
    # ══════════════════════════════════════════════════════════════════════════
    def _build_right(self):
        outer = tk.Frame(self.root, bg=BG)
        self._nb = ttk.Notebook(outer)
        self._nb.pack(fill='both', expand=True)
        self._nb.add(self._tab_results(self._nb),  text='  🔎  Results   ')
        self._nb.add(self._tab_detail(self._nb),   text='  📄  Detail    ')
        self._nb.add(self._tab_patterns(self._nb), text='  ⚙  Patterns  ')
        self._nb.add(self._tab_log(self._nb),      text='  📋  Log       ')
        return outer

    # ── RESULTS TAB ────────────────────────────────────────────────────────────
    def _tab_results(self, nb):
        f  = ttk.Frame(nb)
        pw = tk.PanedWindow(f, orient='horizontal',
                             bg=BORDER, sashwidth=3, sashrelief='flat', bd=0)
        pw.pack(fill='both', expand=True)

        left  = tk.Frame(pw, bg=BG)
        right = tk.Frame(pw, bg=GLASS,
                         highlightbackground=BORDER, highlightthickness=1)
        pw.add(left,  minsize=480)
        pw.add(right, minsize=175, width=200)

        # ── Filter toolbar ──────────────────────────────────────────────────
        tb = tk.Frame(left, bg=GLASS2, pady=6)
        tb.pack(fill='x')
        tk.Label(tb, text='Filter:', font=UI,
                 bg=GLASS2, fg=TEXT2).pack(side='left', padx=(12, 4))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add('write', lambda *_: self._apply_filter())
        ttk.Entry(tb, textvariable=self.filter_var,
                  width=18, font=MN9).pack(side='left')

        self.sev_flt = tk.StringVar(value='ALL')
        cb = ttk.Combobox(tb, textvariable=self.sev_flt, width=9,
                           values=['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'],
                           state='readonly')
        cb.pack(side='left', padx=5)
        cb.bind('<<ComboboxSelected>>', lambda *_: self._apply_filter())

        ttk.Button(tb, text='✕ Clear',   style='Sm.TButton',
                   command=self._clear_all).pack(side='left', padx=3)
        ttk.Button(tb, text='💾 Export', style='Ghost.TButton',
                   command=self._export).pack(side='right', padx=4)
        ttk.Button(tb, text='📋 Copy',   style='Ghost.TButton',
                   command=self._copy_sel).pack(side='right', padx=4)

        # ── Vertical split: table + code ────────────────────────────────────
        vpw = tk.PanedWindow(left, orient='vertical',
                              bg=BORDER, sashwidth=3, sashrelief='flat', bd=0)
        vpw.pack(fill='both', expand=True)

        tf = tk.Frame(left, bg=BG)
        cf = tk.Frame(left, bg=CODE_BG)
        vpw.add(tf, minsize=100)
        vpw.add(cf, minsize=80, height=170)

        self._build_tree(tf)
        self._build_code(cf)

        # ── Right side charts ────────────────────────────────────────────────
        def chart_hdr(title):
            hr = tk.Frame(right, bg=GLASS2)
            hr.pack(fill='x')
            tk.Label(hr, text=f' {title}', font=UI8B,
                     bg=GLASS2, fg=TEXT2).pack(side='left', pady=4, padx=6)
            tk.Label(hr, text='∨', font=UI8, bg=GLASS2,
                     fg=TEXT2).pack(side='right', padx=6)

        chart_hdr('SEVERITY BREAKDOWN')
        self._donut = DonutChart(right, width=190, height=130, bg=GLASS)
        self._donut.pack(padx=6, pady=4)

        # Legend
        leg = tk.Frame(right, bg=GLASS)
        leg.pack(fill='x', padx=12, pady=(0, 6))
        for label, clr in [('High', AMBER), ('Medium', CYAN),
                            ('Medium', CYAN), ('High', AMBER)]:
            rw = tk.Frame(leg, bg=GLASS)
            rw.pack(fill='x', pady=1)
            tk.Frame(rw, bg=clr, width=8, height=8).pack(side='left')
            tk.Label(rw, text=f'  {label}', font=UI7,
                     bg=GLASS, fg=TEXT2).pack(side='left')

        chart_hdr('FINDINGS OVER TIME')
        self._spark = SparkLine(right, width=190, height=100, bg=GLASS)
        self._spark.pack(padx=6, pady=4)

        # X-axis labels for sparkline
        xl = tk.Frame(right, bg=GLASS)
        xl.pack(fill='x', padx=10, pady=(0, 4))
        for i in range(6):
            tk.Label(xl, text=str(i), font=UI7, bg=GLASS,
                     fg=TEXT2).pack(side='left', expand=True)

        return f

    def _build_tree(self, parent):
        cols = ('severity', 'type', 'source', 'line', 'value', '_cp')
        self.tree = ttk.Treeview(parent, columns=cols,
                                  show='headings', selectmode='browse')
        self.tree.tag_configure('CRITICAL', background=ROW_C, foreground=RED)
        self.tree.tag_configure('HIGH',     background=ROW_H, foreground=AMBER)
        self.tree.tag_configure('MEDIUM',   background=ROW_M, foreground=CYAN)

        for col, w, head in [
            ('severity', 82,  'SEVERITY ▲'),
            ('type',    185,  'TYPE'),
            ('source',  210,  'SOURCE'),
            ('line',     46,  'LINE'),
            ('value',   290,  'VALUE'),
            ('_cp',      55,  ''),
        ]:
            self.tree.heading(col, text=head,
                              command=lambda c=col: self._sort(c) if c != '_cp' else None)
            self.tree.column(col, width=w, minwidth=30,
                             stretch=(col == 'value'))

        vsb = ttk.Scrollbar(parent, orient='vertical',   command=self.tree.yview)
        hsb = ttk.Scrollbar(parent, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        self.tree.bind('<<TreeviewSelect>>', self._on_select)
        self.tree.bind('<Button-1>', self._tree_click)

    def _build_code(self, parent):
        tk.Frame(parent, bg=BORDER, height=1).pack(fill='x')
        self.code_txt = tk.Text(
            parent, bg=CODE_BG, fg=TEXT,
            insertbackground=ACC,
            font=MN9, relief='flat', bd=0,
            wrap='none', state='disabled')
        code_vsb = ttk.Scrollbar(parent, orient='vertical',   command=self.code_txt.yview)
        code_hsb = ttk.Scrollbar(parent, orient='horizontal', command=self.code_txt.xview)
        self.code_txt.configure(yscrollcommand=code_vsb.set,
                                 xscrollcommand=code_hsb.set)
        self.code_txt.pack(side='left', fill='both', expand=True)
        code_vsb.pack(side='right', fill='y')
        code_hsb.pack(side='bottom', fill='x')
        # Syntax tags
        self.code_txt.tag_config('ln',   foreground=MUTED)
        self.code_txt.tag_config('kw',   foreground=ACC2)
        self.code_txt.tag_config('str',  foreground=GREEN)
        self.code_txt.tag_config('cmt',  foreground=TEXT2)
        self.code_txt.tag_config('hl',   background='#1e0e00', foreground=AMBER)
        self.code_txt.tag_config('num',  foreground=CYAN)

    # ── DETAIL TAB ─────────────────────────────────────────────────────────────
    def _tab_detail(self, nb):
        f = ttk.Frame(nb)
        self.detail = scrolledtext.ScrolledText(
            f, bg=BG2, fg=TEXT, insertbackground=ACC,
            font=MN9, relief='flat', bd=0, wrap='word', state='disabled')
        self.detail.pack(fill='both', expand=True, padx=2, pady=2)
        for tag, fg in [('key', ACC), ('val', GREEN), ('crit', RED),
                        ('high', AMBER), ('med', CYAN), ('dim', TEXT2)]:
            self.detail.tag_config(tag, foreground=fg)
        return f

    # ── PATTERNS TAB ───────────────────────────────────────────────────────────
    def _tab_patterns(self, nb):
        f = ttk.Frame(nb)
        # Header
        hdr = tk.Frame(f, bg=BG)
        hdr.pack(fill='x', padx=14, pady=(10, 6))
        tk.Label(hdr, text='Loaded Regex Patterns',
                 font=H11, bg=BG, fg=ACC).pack(side='left')
        self.pat_q = tk.StringVar()
        self.pat_q.trace_add('write', lambda *_: self._fill_pats())
        ttk.Entry(hdr, textvariable=self.pat_q, width=28, font=MN9).pack(side='right')
        tk.Label(hdr, text='Search:', font=UI, bg=BG,
                 fg=TEXT2).pack(side='right', padx=(0, 4))

        pf = tk.Frame(f, bg=BG)
        pf.pack(fill='both', expand=True, padx=14, pady=(0, 8))
        self.ptree = ttk.Treeview(pf, columns=('n', 'p'), show='headings')
        self.ptree.heading('n', text='PATTERN NAME')
        self.ptree.heading('p', text='REGEX')
        self.ptree.column('n', width=220, minwidth=100)
        self.ptree.column('p', width=520, minwidth=200, stretch=True)
        pv = ttk.Scrollbar(pf, orient='vertical',   command=self.ptree.yview)
        ph = ttk.Scrollbar(pf, orient='horizontal', command=self.ptree.xview)
        self.ptree.configure(yscrollcommand=pv.set, xscrollcommand=ph.set)
        self.ptree.grid(row=0, column=0, sticky='nsew')
        pv.grid(row=0, column=1, sticky='ns')
        ph.grid(row=1, column=0, sticky='ew')
        pf.rowconfigure(0, weight=1)
        pf.columnconfigure(0, weight=1)
        self._pcnt = tk.Label(f, text='', font=UI, bg=BG, fg=TEXT2)
        self._pcnt.pack(anchor='e', padx=14, pady=(0, 4))
        self._fill_pats()
        return f

    def _fill_pats(self):
        self.ptree.delete(*self.ptree.get_children())
        q = getattr(self, 'pat_q', None)
        q = q.get().lower() if q else ''
        n = 0
        for name, pat in _rex_raw.items():
            if q and q not in name.lower() and q not in pat.lower():
                continue
            self.ptree.insert('', 'end', values=(name, pat))
            n += 1
        self._pcnt.configure(text=f'{n} patterns shown')

    # ── LOG TAB ────────────────────────────────────────────────────────────────
    def _tab_log(self, nb):
        f  = ttk.Frame(nb)
        tb = tk.Frame(f, bg=GLASS2, pady=6)
        tb.pack(fill='x')
        tk.Label(tb, text='Scan Log', font=UIB,
                 bg=GLASS2, fg=TEXT2).pack(side='left', padx=12)
        ttk.Button(tb, text='💾 Save', style='Sm.TButton',
                   command=self._save_log).pack(side='right', padx=8)
        ttk.Button(tb, text='✕ Clear', style='Sm.TButton',
                   command=self._clear_log).pack(side='right', padx=4)
        self.log_w = scrolledtext.ScrolledText(
            f, bg=BG, fg=TEXT2, insertbackground=ACC,
            font=MN9, relief='flat', bd=0, wrap='word', state='disabled')
        self.log_w.pack(fill='both', expand=True, padx=2, pady=2)
        for tag, fg in [('ok', GREEN), ('warn', AMBER),
                        ('error', RED), ('info', CYAN), ('dim', TEXT2)]:
            self.log_w.tag_config(tag, foreground=fg)
        return f

    # ── STATUS BAR ─────────────────────────────────────────────────────────────
    def _build_statusbar(self):
        sb = tk.Frame(self.root, bg=HDR, height=26,
                      highlightbackground=BORDER, highlightthickness=1)
        sb.pack(fill='x', side='bottom')
        sb.pack_propagate(False)

        self.status_var   = tk.StringVar(value='Ready')
        self.js_count_var = tk.StringVar(value='')
        self._sb_scan_var = tk.StringVar(value='')

        tk.Label(sb, textvariable=self.status_var,
                 font=UI8, bg=HDR, fg=TEXT2).pack(side='left', padx=10)
        tk.Label(sb, textvariable=self.js_count_var,
                 font=UI8, bg=HDR, fg=CYAN).pack(side='left', padx=4)
        tk.Label(sb, textvariable=self._sb_scan_var,
                 font=UI8B, bg=HDR, fg=GREEN).pack(side='left', padx=8)

        tk.Label(sb, text=f'Python {sys.version.split()[0]}  ·  {platform.system()}  ·  {len(_rex_raw)} patterns',
                 font=UI8, bg=HDR, fg=TEXT2).pack(side='right', padx=10)

        self._thr_lbl = tk.Label(sb, text='', font=UI8, bg=HDR, fg=TEXT2)
        self._thr_lbl.pack(side='right', padx=6)
        self._mem_lbl = tk.Label(sb, text='Memory 1',
                                  font=UI8, bg=HDR, fg=TEXT2)
        self._mem_lbl.pack(side='right', padx=6)

    # ══════════════════════════════════════════════════════════════════════════
    # BROWSE
    # ══════════════════════════════════════════════════════════════════════════
    def _br_bulk(self):
        p = filedialog.askopenfilename(
            filetypes=[('Text', '*.txt'), ('All', '*.*')])
        if p: self.bulk_var.set(p)

    def _br_local(self):
        p = filedialog.askdirectory()
        if not p:
            p = filedialog.askopenfilename(
                filetypes=[('JavaScript', '*.js'), ('All', '*.*')])
        if p: self.local_var.set(p)

    def _br_out(self):
        p = filedialog.askdirectory()
        if p: self.out_var.set(p)

    def _br_regex(self):
        p = filedialog.askopenfilename(
            filetypes=[('Text', '*.txt'), ('Python', '*.py'), ('All', '*.*')])
        if p: self.rex_var.set(p)

    def _chk_url(self, *_):
        url = self.url_var.get().strip()
        if re.match(r'https?://\S+', url):
            self._url_ok.configure(text='✓ ✓', fg=GREEN)
        elif url:
            self._url_ok.configure(text='✗', fg=RED)
        else:
            self._url_ok.configure(text='')

    # ══════════════════════════════════════════════════════════════════════════
    # PROXY
    # ══════════════════════════════════════════════════════════════════════════
    def _apply_proxies(self):
        lines = [l.strip() for l in
                 self._proxy_txt.get('1.0', 'end').splitlines() if l.strip()]
        _PM.load(lines)
        n = _PM.count
        self._px_lbl.configure(
            text=f'{n} proxies active' if n else 'No proxies',
            fg=GREEN if n else MUTED)
        self._px_val.configure(
            text=f'Validation list: {n} patterns mattore loaded',
            fg=GREEN if n else MUTED)
        self._log(f'Proxies: {n} loaded', 'info' if n else 'warn')

    def _proxy_preset(self, label):
        p = {
            'Proxy presets' : 'http://proxy1.example.com:8080\nhttp://proxy2.example.com:3128',
            'Different proxy': 'socks5://127.0.0.1:9050',
            'UMSP proxy'    : 'http://user:pass@proxy.umsp.net:8080',
        }
        self._proxy_txt.delete('1.0', 'end')
        self._proxy_txt.insert('end', p.get(label, ''))

    # ══════════════════════════════════════════════════════════════════════════
    # RELOAD PATTERNS
    # ══════════════════════════════════════════════════════════════════════════
    def _reload_pats(self):
        global _rex_raw, _compiled
        path = Path(self.rex_var.get().strip())
        new  = load_regexes(path)
        if not new:
            messagebox.showerror('Reload', f'No valid patterns:\n{path}')
            return
        _rex_raw  = new
        _compiled = {n: re.compile(p) for n, p in _rex_raw.items()}
        self._rex_lbl.configure(
            text=f'Loaded {len(_compiled)} patterns. Custom profile applied.',
            fg=GREEN)
        self._fill_pats()
        self._log(f'Reloaded {len(_compiled)} patterns from {path.name}', 'ok')

    # ══════════════════════════════════════════════════════════════════════════
    # LOG
    # ══════════════════════════════════════════════════════════════════════════
    def _log(self, msg: str, tag: str = 'dim'):
        def _do():
            self.log_w.configure(state='normal')
            ts = datetime.now().strftime('%H:%M:%S')
            self.log_w.insert('end', f'[{ts}] {msg}\n', tag)
            self.log_w.see('end')
            self.log_w.configure(state='disabled')
        self.root.after(0, _do)

    def _clear_log(self):
        self.log_w.configure(state='normal')
        self.log_w.delete('1.0', 'end')
        self.log_w.configure(state='disabled')

    def _save_log(self):
        p = filedialog.asksaveasfilename(
            defaultextension='.txt',
            filetypes=[('Text', '*.txt')],
            initialfile=f'jssh_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt')
        if p:
            self.log_w.configure(state='normal')
            Path(p).write_text(self.log_w.get('1.0', 'end'), encoding='utf-8')
            self.log_w.configure(state='disabled')
            self._log(f'Log saved → {p}', 'ok')

    def _set_status(self, msg: str):
        self.root.after(0, lambda: self.status_var.set(msg))

    def _set_hdr(self, msg: str, color: str = MUTED):
        self.root.after(0, lambda:
            self._scan_st.configure(text=f'  {msg}', fg=color))

    # ══════════════════════════════════════════════════════════════════════════
    # ELAPSED
    # ══════════════════════════════════════════════════════════════════════════
    def _start_elapsed(self):
        self._start_ts = time.time()
        self._tick()

    def _tick(self):
        if not self.scan_active:
            return
        el = int(time.time() - self._start_ts)
        mm, ss = el // 60, el % 60
        self.root.after(0, lambda:
            self._elapsed_lbl.configure(text=f'Elapsed: {mm:02d}:{ss:02d}'))
        self._elapsed_id = self.root.after(1000, self._tick)

    def _stop_elapsed(self):
        if self._elapsed_id:
            try: self.root.after_cancel(self._elapsed_id)
            except Exception: pass
            self._elapsed_id = None

    # ══════════════════════════════════════════════════════════════════════════
    # SCAN
    # ══════════════════════════════════════════════════════════════════════════
    def _start_scan(self):
        targets = self._build_target_list()
        if not targets:
            messagebox.showwarning('No Target',
                'Provide a JS file URL, page URL, bulk list, or local path.')
            return
        self.scan_active = True
        self.findings    = []
        self._code_cache = {}
        self.scan_btn.configure(state='disabled')
        self.stop_btn.configure(state='normal')
        self._clear_tree()
        self._upd_stats()
        self.hdr_prog_var.set(0)
        self._set_status('Scanning…')
        self._set_hdr('Scanning…', AMBER)
        self._start_elapsed()
        self._thr_lbl.configure(
            text=f'▶ 0/{self.thr_var.get()} threads')
        threading.Thread(target=self._worker, args=(targets,), daemon=True).start()

    def _stop_scan(self):
        self.scan_active = False
        self.stop_btn.configure(state='disabled')
        self._log('Stop requested.', 'warn')
        self._set_hdr('Stopped', AMBER)

    def _build_target_list(self) -> list[tuple[str, str]]:
        """
        Returns list of (source, kind) where kind is 'js_url' | 'page_url' | 'local'.
        The tool:
          - js_url  → fetch & scan that single JS file
          - page_url → if scan_page checked, extract JS links then scan each
          - local   → read from disk
        """
        out = []
        url = self.url_var.get().strip()
        if url:
            if is_js_url(url):
                out.append((url, 'js_url'))     # direct JS file
            else:
                out.append((url, 'page_url'))   # page to crawl

        if self.bulk_var.get().strip():
            try:
                for ln in Path(self.bulk_var.get().strip()).read_text().splitlines():
                    ln = ln.strip()
                    if not ln or ln.startswith('#'): continue
                    if is_js_url(ln):
                        out.append((ln, 'js_url'))
                    else:
                        out.append((ln, 'page_url'))
            except Exception as e:
                self._log(f'Bulk file error: {e}', 'error')

        if self.local_var.get().strip():
            out.append((self.local_var.get().strip(), 'local'))

        return out

    def _worker(self, targets: list[tuple[str, str]]):
        delay   = float(self.del_var.get())
        retries = int(self.ret_var.get())
        js_jobs : list[tuple[str, str]] = []  # (url_or_path, 'url'|'local')

        try:
            for src, kind in targets:
                if not self.scan_active: break

                if kind == 'js_url':
                    # User gave us a direct JS file URL — scan it
                    js_jobs.append((src, 'url'))
                    self._log(f'Queued JS: {src}', 'info')

                elif kind == 'page_url':
                    # User gave a page URL — extract JS links, scan each
                    self._log(f'Fetching page: {src}', 'info')
                    self._set_status(f'Fetching page…')
                    html = fetch(src, self.to_var.get(), retries, delay)
                    if not html:
                        self._log(f'Failed to fetch page: {src}', 'error')
                        continue
                    links = extract_js_links(html, src)
                    if self.scan_pg_var.get():
                        links.insert(0, src)
                    self._log(f'Found {len(links)} JS files on {src}', 'ok')
                    js_jobs.extend([(l, 'url') for l in links])

                elif kind == 'local':
                    path = Path(src)
                    if path.is_dir():
                        files = list(path.rglob('*.js'))
                        js_jobs.extend([(str(f), 'local') for f in files])
                        self._log(f'{len(files)} files in {src}', 'ok')
                    elif path.is_file():
                        js_jobs.append((str(path), 'local'))
                        self._log(f'Local: {src}', 'ok')

            if not js_jobs:
                self._log('No JS files to scan.', 'warn')
                return

            total = len(js_jobs)
            self.root.after(0, lambda:
                self.js_count_var.set(f'{total} JS files queued'))
            self.root.after(0, lambda:
                self._thr_lbl.configure(
                    text=f'▶ {self.thr_var.get()}/{self.thr_var.get()} threads'))

            done    = 0
            found_n = 0

            with ThreadPoolExecutor(max_workers=self.thr_var.get()) as ex:
                fmap = {ex.submit(self._scan_file, src, kind, delay, retries): src
                        for src, kind in js_jobs if self.scan_active}

                for fut in as_completed(fmap):
                    if not self.scan_active:
                        ex.shutdown(wait=False, cancel_futures=True)
                        break
                    done  += 1
                    pct    = (done / total) * 100
                    self.root.after(0,
                        lambda p=pct: self.hdr_prog_var.set(p))

                    try:
                        results = fut.result()
                    except Exception as e:
                        self._log(f'Scan error: {e}', 'error')
                        results = []

                    if results:
                        self.findings.extend(results)
                        found_n += len(results)
                        self.root.after(0, lambda r=results: self._add_rows(r))
                        self.root.after(0, self._upd_stats)
                        self.root.after(0, lambda:
                            self._donut.update(self.findings))
                        self.root.after(0, lambda n=found_n:
                            self._spark.push(n))

                    self._set_status(
                        f'[{done}/{total}]  {len(self.findings)} secrets')

        except Exception:
            self._log(traceback.format_exc(), 'error')
        finally:
            self._finish()

    def _scan_file(self, src: str, kind: str,
                   delay: float, retries: int) -> list[dict]:
        """
        Fetch or read the JS file, then run ALL regex patterns on its content.
        This is the core scanning function.
        """
        if kind == 'url':
            content = fetch(src, self.to_var.get(), retries, delay)
            if not content:
                self._log(f'Skip (fetch failed): {src.split("/")[-1][:55]}', 'warn')
                return []
        else:
            try:
                content = Path(src).read_text(errors='replace')
            except Exception as e:
                self._log(f'Read error: {e}', 'warn')
                return []

        # Cache for code viewer
        self._code_cache[src] = content

        # Run all 600+ regex patterns on the actual JS content
        results = scan_js_content(content, src)

        if results:
            self._log(
                f'✓ {len(results)} secrets — {src.split("/")[-1][:55]}', 'ok')
        return results

    def _finish(self):
        def _do():
            self.scan_active = False
            self._stop_elapsed()
            self.scan_btn.configure(state='normal')
            self.stop_btn.configure(state='disabled')
            self.hdr_prog_var.set(100)
            n    = len(self.findings)
            crit = sum(1 for f in self.findings if f['severity'] == 'CRITICAL')
            high = sum(1 for f in self.findings if f['severity'] == 'HIGH')
            med  = sum(1 for f in self.findings if f['severity'] == 'MEDIUM')
            self._set_status(f'Done — {n} secrets found')
            self._set_hdr('Complete', GREEN)
            self._thr_lbl.configure(
                text=f'✓ {self.thr_var.get()}/{self.thr_var.get()} threads')
            self._sb_scan_var.configure(
                text=f'SCAN STATUS: Complete. Total {n} findings. '
                     f'{high}998 findings, {crit}55 H findings')
            self._log(
                f'── Complete: {n} total [{crit} CRIT  {high} HIGH  {med} MED] ──', 'ok')
            self._donut.update(self.findings)
            if self.findings:
                self._autosave()
        self.root.after(0, _do)

    def _autosave(self):
        try:
            out = Path(self.out_var.get())
            out.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            p  = out / f'jssh_{ts}.json'
            write_report(self.findings, p, 'json')
            self._log(f'Auto-saved → {p}', 'ok')
        except Exception as e:
            self._log(f'Auto-save error: {e}', 'error')

    # ══════════════════════════════════════════════════════════════════════════
    # TREE / RESULTS
    # ══════════════════════════════════════════════════════════════════════════
    def _add_rows(self, results: list[dict]):
        for f in results:
            src = f['source'].split('/')[-1][:42]
            sev = f['severity']
            dot = '🔴' if sev == 'CRITICAL' else '🟠' if sev == 'HIGH' else '🟡'
            self.tree.insert('', 'end', values=(
                f'{dot} {sev}',
                f['type'],
                src,
                f['line'],
                f['value'][:80],
                '⎘ Copy',
            ), tags=(sev,))

    def _clear_tree(self):
        self.tree.delete(*self.tree.get_children())

    def _clear_all(self):
        self.findings = []
        self._code_cache = {}
        self._clear_tree()
        self._upd_stats()
        for w in [self.detail, self.code_txt]:
            w.configure(state='normal')
            w.delete('1.0', 'end')
            w.configure(state='disabled')
        self._donut.update([])

    def _apply_filter(self):
        q   = self.filter_var.get().lower()
        sev = self.sev_flt.get()
        self._clear_tree()
        for f in self.findings:
            if sev != 'ALL' and f['severity'] != sev:
                continue
            if q and q not in json.dumps(f).lower():
                continue
            src = f['source'].split('/')[-1][:42]
            s   = f['severity']
            dot = '🔴' if s == 'CRITICAL' else '🟠' if s == 'HIGH' else '🟡'
            self.tree.insert('', 'end', values=(
                f'{dot} {s}', f['type'], src,
                f['line'], f['value'][:80], '⎘ Copy'), tags=(s,))

    def _sort(self, col: str):
        rev  = self._sort_rev.get(col, False)
        data = [(self.tree.set(c, col), c) for c in self.tree.get_children('')]
        data.sort(reverse=rev)
        for i, (_, c) in enumerate(data):
            self.tree.move(c, '', i)
        self._sort_rev[col] = not rev

    def _tree_click(self, event):
        region = self.tree.identify('region', event.x, event.y)
        if region != 'cell': return
        if self.tree.identify_column(event.x) == '#6':
            item = self.tree.identify_row(event.y)
            if item:
                vals = self.tree.item(item)['values']
                v    = str(vals[4]) if len(vals) > 4 else ''
                self.root.clipboard_clear()
                self.root.clipboard_append(v)
                self._set_status('Value copied.')

    def _on_select(self, _=None):
        sel = self.tree.selection()
        if not sel: return
        vals = self.tree.item(sel[0])['values']
        if not vals: return
        # Match finding by type + line
        for f in self.findings:
            if (f['type'] == str(vals[1]) and str(f['line']) == str(vals[3])):
                self._show_detail(f)
                self._show_code(f)
                break

    def _show_detail(self, f: dict):
        st = {'CRITICAL': 'crit', 'HIGH': 'high', 'MEDIUM': 'med'}.get(
            f['severity'], 'dim')
        self.detail.configure(state='normal')
        self.detail.delete('1.0', 'end')
        self.detail.insert('end', '─' * 66 + '\n', 'dim')
        self.detail.insert('end', f"  {f['severity']}  —  {f['type']}\n", st)
        self.detail.insert('end', '─' * 66 + '\n\n', 'dim')
        for k, v, t in [
            ('Type',    f['type'],     'key'),
            ('Source',  f['source'],   None),
            ('Line',    str(f['line']), 'dim'),
            ('Severity', f['severity'], st),
        ]:
            self.detail.insert('end', f'  {k:<12}: ', 'dim')
            self.detail.insert('end', v + '\n', t)
        self.detail.insert('end', '\n  Matched Value:\n', 'dim')
        self.detail.insert('end', f"  {f['value']}\n", 'val')
        self.detail.insert('end', '\n  Full Value (raw):\n', 'dim')
        self.detail.insert('end', f"  {f['value_raw']}\n", 'val')
        self.detail.insert('end', '\n  Context:\n', 'dim')
        self.detail.insert('end', f"  {f['context']}\n")
        self.detail.insert('end', '\n' + '─' * 66 + '\n', 'dim')
        self.detail.configure(state='disabled')

    def _show_code(self, f: dict):
        content = self._code_cache.get(f['source'], '')
        self.code_txt.configure(state='normal')
        self.code_txt.delete('1.0', 'end')
        if not content:
            self.code_txt.insert('end',
                f'  // {f["source"]}\n  // {f["context"]}\n', 'cmt')
            self.code_txt.configure(state='disabled')
            return

        lines  = content.splitlines()
        target = f['line']
        start  = max(0, target - 10)
        end    = min(len(lines), target + 12)

        kws_re = re.compile(
            r'\b(var|let|const|function|return|class|import|export|'
            r'from|if|else|try|catch|new|this|async|await|typeof|'
            r'null|undefined|true|false)\b')
        str_re = re.compile(r'(["\'])(?:(?!\1).)*\1')
        cmt_re = re.compile(r'//.*$|/\*[\s\S]*?\*/')
        num_re = re.compile(r'\b\d+\b')

        for i, ln in enumerate(lines[start:end], start + 1):
            prefix = f'{i:4d}  '
            hl     = (i == target)
            self.code_txt.insert('end', prefix, 'hl' if hl else 'ln')
            # Basic syntax highlighting
            pos  = self.code_txt.index('end-1c')
            self.code_txt.insert('end', ln + '\n', 'hl' if hl else '')

        self.code_txt.see(f'{target - start}.0')
        self.code_txt.configure(state='disabled')

    # ══════════════════════════════════════════════════════════════════════════
    # EXPORT
    # ══════════════════════════════════════════════════════════════════════════
    def _export(self):
        if not self.findings:
            messagebox.showinfo('Export', 'No findings to export.')
            return
        p = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=[('JSON', '*.json'), ('CSV', '*.csv'), ('Text', '*.txt')],
            initialfile=f'jssh_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
        if p:
            fmt = Path(p).suffix.lstrip('.')
            write_report(self.findings, Path(p),
                         fmt if fmt in ('json', 'csv', 'txt') else 'json')
            self._log(f'Exported {len(self.findings)} findings → {p}', 'ok')
            messagebox.showinfo('Export', f'{len(self.findings)} findings saved.')

    def _quick_json(self):
        if not self.findings:
            messagebox.showinfo('Export', 'No findings yet.')
            return
        out = Path(self.out_var.get())
        out.mkdir(parents=True, exist_ok=True)
        p   = out / f'jssh_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        write_report(self.findings, p, 'json')
        self._log(f'JSON → {p}', 'ok')
        messagebox.showinfo('Quick JSON', f'Saved → {p}')

    def _quick_pdf(self):
        messagebox.showinfo('PDF Export',
            'PDF export requires: pip install reportlab\n'
            'Use JSON export in the meantime.')

    def _copy_sel(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo('Copy', 'Select a row first.')
            return
        vals = self.tree.item(sel[0])['values']
        self.root.clipboard_clear()
        self.root.clipboard_append('\t'.join(str(v) for v in vals[:-1]))
        self._set_status('Row copied.')

    # ══════════════════════════════════════════════════════════════════════════
    # STATS
    # ══════════════════════════════════════════════════════════════════════════
    def _upd_stats(self):
        n    = len(self.findings)
        crit = sum(1 for f in self.findings if f['severity'] == 'CRITICAL')
        high = sum(1 for f in self.findings if f['severity'] == 'HIGH')
        med  = sum(1 for f in self.findings if f['severity'] == 'MEDIUM')
        self._st_total.configure(text=str(n))
        self._st_crit.configure( text=str(crit))
        self._st_high.configure( text=str(high))
        self._st_med.configure(  text=str(med))


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    if platform.system() == 'Linux':
        disp = os.environ.get('DISPLAY', '')
        if not disp:
            print('[ERROR] DISPLAY not set.')
            print('  WSL2: export DISPLAY=$(ip route show default | awk \'{print $3}\'):0.0')
            print('  Then start VcXsrv on Windows (Display=0, disable access control).')
            sys.exit(1)
        print(f'[INFO] DISPLAY = {disp}')

    root = tk.Tk()
    root.withdraw()
    App(root)
    root.deiconify()
    root.mainloop()


if __name__ == '__main__':
    main()
