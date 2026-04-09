#!/usr/bin/env python3
"""
JSSecretHunter GUI v3.1.0
Author  : mohidqx / TeamCyberOps
GitHub  : https://github.com/mohidqx/jsSecretsHunter
License : MIT
"""

# ─── WSL DISPLAY FIX ── MUST be before any other import ───────────────────────
import os, platform, subprocess, sys

def _fix_display():
    if platform.system() != 'Linux':
        return
    cur = os.environ.get('DISPLAY', '')
    if cur and ':' in cur:
        ip = cur.split(':')[0]
        bad = ('8.8.', '1.1.1', '9.9.', '208.', '4.2.', '0.0.0')
        if not any(ip.startswith(b) for b in bad):
            return
    host = None
    try:
        out = subprocess.check_output(['ip','route','show','default'],
                                      stderr=subprocess.DEVNULL, timeout=3).decode()
        host = out.strip().split()[2]
    except Exception:
        pass
    if not host:
        try:
            pub = ('8.8.','1.1.','9.9.','208.','4.2.','4.4.','0.0.')
            with open('/etc/resolv.conf') as f:
                for ln in f:
                    if ln.startswith('nameserver'):
                        ip = ln.split()[1].strip()
                        if not any(ip.startswith(p) for p in pub):
                            host = ip; break
        except Exception:
            pass
    os.environ['DISPLAY'] = f'{host}:0.0' if host else ':0'
    os.environ.setdefault('LIBGL_ALWAYS_INDIRECT','1')
    os.environ.setdefault('GDK_BACKEND','x11')
    try: os.environ.setdefault('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}')
    except: pass

_fix_display()

# ─── IMPORTS ───────────────────────────────────────────────────────────────────
import re, json, time, threading, hashlib, random, shutil, socket, math, traceback
import urllib.request, urllib.error, urllib.parse
import csv, io
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

try:
    from PIL import Image, ImageTk, ImageDraw
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# ─── CONSTANTS ─────────────────────────────────────────────────────────────────
VERSION  = '3.1.0'
REPO     = 'mohidqx/jsSecretsHunter'
LOGO_URL = 'https://github.com/mohidqx.png'
API_URL  = f'https://api.github.com/repos/{REPO}/releases/latest'
RAW_URL  = f'https://raw.githubusercontent.com/{REPO}/main/jssecrethunter_gui.py'
REGEX_F  = Path(__file__).parent / 'secretfinder_regexes.txt'

# ─── PALETTE ───────────────────────────────────────────────────────────────────
C = {
    'bg'      :'#0a0e14', 'bg2':'#0d1117', 'bg3':'#111820',
    'panel'   :'#0f1923', 'glass':'#121f2e', 'glass2':'#162536',
    'border'  :'#1e3048', 'border2':'#243850',
    'acc'     :'#e01030', 'acc2':'#ff2244', 'acc_dim':'#1a0008',
    'green'   :'#00e5a0', 'amber':'#f59e0b', 'red':'#ff5566',
    'cyan'    :'#22d3ee', 'purple':'#8b5cf6', 'blue':'#3b82f6',
    'text'    :'#cdd6e0', 'text2':'#7a8fa0', 'muted':'#3d5060',
    'row_h'   :'#1a0008', 'row_m':'#0f1a00', 'row_n':'#001820',
    'crit_fg' :'#ff5566', 'high_fg':'#f59e0b', 'med_fg':'#22d3ee',
    'code_bg' :'#090d12',
    'hdr_bg'  :'#080c12',
}
_W  = platform.system()=='Windows'
_MN = ('Consolas',9)   if _W else ('Monospace',9)
_MNB= ('Consolas',9,'bold') if _W else ('Monospace',9,'bold')
_UI = ('Segoe UI',9)   if _W else ('Ubuntu',9)
_B  = ('Segoe UI',9,'bold') if _W else ('Ubuntu',9,'bold')
_H  = ('Segoe UI',11,'bold') if _W else ('Ubuntu',11,'bold')
_BIG= ('Segoe UI',14,'bold') if _W else ('Ubuntu',14,'bold')

# ─── UA POOL ───────────────────────────────────────────────────────────────────
_UAS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
    'Googlebot/2.1 (+http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
]

# ─── PROXY MANAGER ─────────────────────────────────────────────────────────────
class ProxyMgr:
    def __init__(self):
        self._list: list[str] = []
        self._failed: set[str] = set()
        self._idx = 0
        self._lock = threading.Lock()
    def load(self, lines):
        with self._lock:
            self._list   = [l.strip() for l in lines if l.strip()]
            self._failed.clear(); self._idx = 0
    def next(self):
        with self._lock:
            active = [p for p in self._list if p not in self._failed]
            if not active: return None
            p = active[self._idx % len(active)]; self._idx += 1; return p
    def fail(self, p):
        with self._lock: self._failed.add(p)
    @property
    def count(self): return len(self._list)
    @property
    def active(self): return len([p for p in self._list if p not in self._failed])

_PM = ProxyMgr()

# ─── FETCH ─────────────────────────────────────────────────────────────────────
_RL_CODES = {429,503,403,509}

def fetch(url, timeout=15, retries=3, delay=0.2):
    if delay > 0:
        time.sleep(delay + random.uniform(0, delay*0.4))
    for attempt in range(retries):
        proxy = _PM.next()
        ua    = random.choice(_UAS)
        hdrs  = {
            'User-Agent'     : ua,
            'Accept'         : 'text/html,application/javascript,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection'     : 'keep-alive',
            'Referer'        : 'https://www.google.com/',
        }
        try:
            opener = None
            if proxy:
                try:
                    opener = urllib.request.build_opener(
                        urllib.request.ProxyHandler({'http':proxy,'https':proxy}))
                except Exception: pass
            req    = urllib.request.Request(url, headers=hdrs)
            opener_fn = opener.open if opener else urllib.request.urlopen
            with opener_fn(req, timeout=timeout) as r:
                code = r.getcode()
                if code in _RL_CODES:
                    raise urllib.error.HTTPError(url,code,'Rate-limited',{},None)
                raw  = r.read()
                enc  = r.headers.get_content_charset() or 'utf-8'
                cenc = r.headers.get('Content-Encoding','')
                if cenc == 'gzip':
                    import gzip; raw = gzip.decompress(raw)
                return raw.decode(enc, errors='replace')
        except urllib.error.HTTPError as e:
            if e.code in _RL_CODES:
                if proxy: _PM.fail(proxy)
                time.sleep(min(2**attempt + random.uniform(0,1.5), 30))
                continue
            return None
        except Exception:
            if proxy: _PM.fail(proxy)
            if attempt < retries-1: time.sleep(1.2**attempt)
    return None

# ─── JS LINK EXTRACTOR ─────────────────────────────────────────────────────────
_SKIP_JS = ('google-analytics','gtag','hotjar','clarity','facebook.net',
            'doubleclick','fbevents','amplitude','segment.io','mixpanel')

def extract_js(html, base):
    parsed = urllib.parse.urlparse(base)
    root   = f"{parsed.scheme}://{parsed.netloc}"
    seen   = set()
    pats   = [
        r'(?:src|href)\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
        r'["\']([^"\']+\.js)["\']',
        r'import\s+.*?from\s+["\']([^"\']+\.js[^"\']*)["\']',
        r'require\s*\(\s*["\']([^"\']+\.js)["\']',
    ]
    for pat in pats:
        for m in re.finditer(pat, html, re.I):
            h = m.group(1)
            if   h.startswith('http'): u=h
            elif h.startswith('//'): u=f"{parsed.scheme}:{h}"
            elif h.startswith('/'): u=f"{root}{h}"
            else:
                bp='/'.join(parsed.path.split('/')[:-1])
                u=f"{root}{bp}/{h}"
            if any(s in u.lower() for s in _SKIP_JS): continue
            seen.add(u.split('?')[0])
    return list(seen)

# ─── LOAD REGEXES ──────────────────────────────────────────────────────────────
def load_regexes(path):
    if not path.exists(): return {}
    text = path.read_text(encoding='utf-8', errors='replace')
    out  = {}
    for m in re.finditer(r"'([^']+)'\s*:\s*r'([^']*)'", text):
        n, p = m.group(1), m.group(2)
        try: re.compile(p); out[n]=p
        except: pass
    return out

_rex_raw = load_regexes(REGEX_F)
if not _rex_raw:
    _rex_raw = {
        'google_api_key': r'AIza[0-9A-Za-z\-_]{35}',
        'aws_access_key': r'(?:AKIA|AGPA|AIDA|AROA)[A-Z0-9]{16}',
        'stripe_live'   : r'sk_live_[0-9a-zA-Z]{24}',
        'github_pat'    : r'ghp_[0-9a-zA-Z]{36}',
        'slack_bot'     : r'xoxb-[0-9]{11}-[0-9]{11,13}-[0-9a-zA-Z]{24}',
        'openai_key'    : r'sk-[0-9A-Za-z]{48}',
        'jwt'           : r'ey[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_\.\+/=]*',
        'rsa_private'   : r'-----BEGIN RSA PRIVATE KEY-----',
    }
_compiled = {n: re.compile(p) for n,p in _rex_raw.items()}

_CRIT={'rsa_private_key','dsa_private_key','ec_private_key','pgp_private_key',
       'openssh_private_key','pkcs8_private_key','google_cloud_private_key',
       'ethereum_private_key','stripe_live_secret_key','amazon_aws_secret_access_key',
       'amazon_aws_access_key_id','twilio_auth_token','sendgrid_api_key',
       'hashicorp_vault_token','openai_api_key','anthropic_api_key',
       'mysql_connection_string','postgres_connection_string','mongo_atlas_connection'}
_HIGH={'github_pat_classic','github_fine_grained_pat','gitlab_pat','slack_bot_token',
       'discord_bot_token','telegram_bot_token','facebook_access_token',
       'twitter_bearer_token','stripe_test_secret_key','mailgun_api_key',
       'sentry_dsn','azure_storage_connection_string','heroku_api_key',
       'cloudflare_api_token','shopify_private_app_token','linear_api_key','okta_api_token'}

def _sev(n):
    if n in _CRIT: return 'CRITICAL'
    if n in _HIGH: return 'HIGH'
    return 'MEDIUM'

def scan_content(content, source):
    results, seen = [], set()
    lines = content.splitlines()
    for name, pat in _compiled.items():
        for m in pat.finditer(content):
            val = m.group(0)
            uid = hashlib.md5(f"{name}:{val}".encode()).hexdigest()
            if uid in seen: continue
            seen.add(uid)
            ln  = content[:m.start()].count('\n')+1
            ctx = (lines[ln-1].strip() if ln<=len(lines) else '')[:300]
            results.append({
                'source':source, 'type':name, 'severity':_sev(name),
                'value':val[:120]+('…' if len(val)>120 else ''),
                'line':ln, 'context':ctx,
            })
    return results

def write_report(data, path, fmt):
    if fmt=='json':
        path.write_text(json.dumps(data, indent=2), encoding='utf-8')
    elif fmt=='csv':
        buf=io.StringIO()
        w=csv.DictWriter(buf, fieldnames=['source','type','severity','value','line','context'])
        w.writeheader(); w.writerows(data)
        path.write_text(buf.getvalue(), encoding='utf-8')
    else:
        lines=[]
        for f in data:
            lines+=[f"[{f['severity']}] {f['type']}",
                    f"  Source : {f['source']}", f"  Line   : {f['line']}",
                    f"  Value  : {f['value']}", f"  Context: {f['context']}",""]
        path.write_text('\n'.join(lines), encoding='utf-8')

# ─── AUTO-UPDATE ───────────────────────────────────────────────────────────────
def do_update(log_fn):
    log_fn('Checking GitHub for updates…','info')
    try:
        raw  = fetch(API_URL, timeout=8)
        data = json.loads(raw or '{}')
        tag  = data.get('tag_name','').lstrip('v')
        if not tag: log_fn('Cannot read version from API.','warn'); return
        if tag==VERSION:
            log_fn(f'Already latest v{VERSION}.','ok')
            messagebox.showinfo('Auto-Update',f'Already on v{VERSION}.'); return
        url     = next((a['browser_download_url'] for a in data.get('assets',[])
                        if a['name'].endswith('.py')), RAW_URL)
        content = fetch(url, timeout=30)
        if not content: log_fn('Download failed.','error'); return
        sp = Path(__file__).resolve()
        shutil.copy2(sp, sp.with_suffix('.bak'))
        sp.write_text(content, encoding='utf-8')
        log_fn(f'Updated to v{tag} — restarting…','ok')
        messagebox.showinfo('Auto-Update',f'Updated to v{tag}!')
        os.execv(sys.executable, [sys.executable]+sys.argv)
    except Exception as e:
        log_fn(f'Update error: {e}','error')

# ─── MINI CHART CANVAS ─────────────────────────────────────────────────────────
class MiniBar(tk.Canvas):
    """Mini thread-usage bar chart (header options area)."""
    def __init__(self, parent, bars=8, **kw):
        kw.setdefault('bg', C['panel']); kw.setdefault('highlightthickness',0)
        kw.setdefault('width',60); kw.setdefault('height',18)
        super().__init__(parent, **kw)
        self._bars = bars; self._vals = [random.uniform(0.2,1.0) for _ in range(bars)]
        self._anim()
    def _anim(self):
        self.delete('all')
        w,h = self.winfo_width() or 60, self.winfo_height() or 18
        bw  = max(1, (w-2)//self._bars - 1)
        for i,v in enumerate(self._vals):
            x0 = 1+i*(bw+1); bh=int((h-2)*v)
            clr = C['acc'] if v>0.8 else C['amber'] if v>0.5 else C['green']
            self.create_rectangle(x0, h-1-bh, x0+bw, h-1, fill=clr, outline='')
        self._vals = self._vals[1:]+[random.uniform(0.1,1.0)]
        self.after(400, self._anim)

class DonutChart(tk.Canvas):
    """Severity breakdown donut."""
    def __init__(self, parent, **kw):
        kw.setdefault('bg',C['glass']); kw.setdefault('highlightthickness',0)
        kw.setdefault('width',140); kw.setdefault('height',120)
        super().__init__(parent, **kw)
        self._data = {'CRITICAL':0,'HIGH':0,'MEDIUM':0}
        self.draw()
    def update_data(self, findings):
        self._data = {
            'CRITICAL': sum(1 for f in findings if f['severity']=='CRITICAL'),
            'HIGH'    : sum(1 for f in findings if f['severity']=='HIGH'),
            'MEDIUM'  : sum(1 for f in findings if f['severity']=='MEDIUM'),
        }
        self.draw()
    def draw(self):
        self.delete('all')
        w,h   = self.winfo_width() or 140, self.winfo_height() or 120
        cx,cy = w//2, h//2-5
        r,ri  = min(cx,cy)-8, min(cx,cy)-22
        total = sum(self._data.values()) or 1
        colors= {'CRITICAL':C['red'],'HIGH':C['amber'],'MEDIUM':C['cyan']}
        start = -90.0
        for key,clr in colors.items():
            ext = (self._data[key]/total)*360
            if ext>0:
                self.create_arc(cx-r,cy-r,cx+r,cy+r, start=start,
                                extent=ext, fill=clr, outline=C['glass'], width=2)
                start += ext
        # Hole
        self.create_oval(cx-ri,cy-ri,cx+ri,cy+ri, fill=C['glass'], outline='')
        # Center text
        self.create_text(cx, cy, text=str(sum(self._data.values())),
                         font=(_B[0],11,'bold'), fill=C['text'])
        self.create_text(cx, cy+14, text='total', font=(_UI[0],7), fill=C['muted'])

class LineChart(tk.Canvas):
    """Findings over time sparkline."""
    def __init__(self, parent, **kw):
        kw.setdefault('bg',C['glass']); kw.setdefault('highlightthickness',0)
        kw.setdefault('width',160); kw.setdefault('height',80)
        super().__init__(parent, **kw)
        self._pts : list[int] = []
        self.draw()
    def add(self, n):
        self._pts.append(n)
        if len(self._pts)>30: self._pts=self._pts[-30:]
        self.draw()
    def draw(self):
        self.delete('all')
        w,h = self.winfo_width() or 160, self.winfo_height() or 80
        pad = 8
        iw,ih = w-pad*2, h-pad*2
        pts   = self._pts if self._pts else [0]
        mx    = max(max(pts),1)
        # Y axis labels
        for yv in [0, mx//2, mx]:
            yp = pad + ih - int(yv/mx*ih)
            self.create_text(pad-2, yp, text=str(yv), font=(_UI[0],6),
                             fill=C['muted'], anchor='e')
        # Grid
        for i in range(4):
            yp = pad + int(ih*i/3)
            self.create_line(pad, yp, w-pad, yp, fill=C['border'], dash=(2,4))
        if len(pts)>1:
            step = iw/(len(pts)-1)
            coords=[]
            for i,v in enumerate(pts):
                xp = pad + i*step
                yp = pad + ih - int(v/mx*ih)
                coords += [xp, yp]
            # Fill
            fill_pts = [pad, pad+ih] + coords + [pad+iw, pad+ih]
            self.create_polygon(fill_pts, fill='#001a30', outline='')
            # Line
            self.create_line(coords, fill=C['acc'], width=2, smooth=True)
            # Last dot
            self.create_oval(coords[-2]-3, coords[-1]-3,
                             coords[-2]+3, coords[-1]+3,
                             fill=C['acc'], outline='')

# ─── TTK STYLE ─────────────────────────────────────────────────────────────────
def _style():
    s = ttk.Style()
    s.theme_use('default')
    s.configure('.', background=C['bg'], foreground=C['text'],
                fieldbackground=C['bg3'], borderwidth=0, font=_UI)
    s.configure('TFrame',  background=C['bg'])
    s.configure('P.TFrame',background=C['panel'])
    s.configure('G.TFrame',background=C['glass'])
    s.configure('TLabel',  background=C['bg'],    foreground=C['text'])
    s.configure('P.TLabel',background=C['panel'], foreground=C['text'])
    s.configure('G.TLabel',background=C['glass'], foreground=C['text'])
    s.configure('Mu.TLabel',background=C['panel'],foreground=C['muted'])
    s.configure('TEntry',
        fieldbackground=C['bg3'], foreground=C['text'],
        insertbackground=C['acc'], relief='flat', padding=5)
    s.configure('TCombobox',
        fieldbackground=C['bg3'], foreground=C['text'],
        selectbackground=C['acc'], relief='flat', padding=5)
    s.map('TCombobox', fieldbackground=[('readonly',C['bg3'])])
    s.configure('TSpinbox',
        fieldbackground=C['bg3'], foreground=C['text'],
        insertbackground=C['acc'], relief='flat', padding=5)
    s.configure('TNotebook', background=C['bg2'], borderwidth=0, tabmargins=[0,0,0,0])
    s.configure('TNotebook.Tab',
        background=C['bg2'], foreground=C['text2'], padding=[14,8], font=_B)
    s.map('TNotebook.Tab',
        background=[('selected',C['glass'])],
        foreground=[('selected',C['acc'])])
    s.configure('Treeview',
        background=C['bg2'], foreground=C['text'],
        fieldbackground=C['bg2'], rowheight=28, borderwidth=0, font=_MN)
    s.configure('Treeview.Heading',
        background=C['bg3'], foreground=C['acc2'], font=_B, relief='flat')
    s.map('Treeview',
        background=[('selected',C['acc_dim'])],
        foreground=[('selected',C['acc2'])])
    s.configure('TScrollbar',
        background=C['bg2'], troughcolor=C['bg'],
        arrowcolor=C['muted'], borderwidth=0, relief='flat')
    s.configure('TProgressbar',
        background=C['acc'], troughcolor=C['bg3'],
        borderwidth=0, thickness=4)
    s.configure('Red.TButton',
        background=C['acc'], foreground='#fff', font=_B, padding=[18,7], relief='flat')
    s.map('Red.TButton',
        background=[('active',C['acc2']),('disabled',C['muted'])],
        foreground=[('disabled','#555')])
    s.configure('Ghost.TButton',
        background=C['glass2'], foreground=C['text2'], font=_UI, padding=[10,6], relief='flat')
    s.map('Ghost.TButton',
        background=[('active',C['border'])], foreground=[('active',C['text'])])
    s.configure('Sm.TButton',
        background=C['glass2'], foreground=C['text2'], font=(_UI[0],8), padding=[6,4], relief='flat')
    s.map('Sm.TButton',
        background=[('active',C['border'])], foreground=[('active',C['text'])])
    s.configure('Stop.TButton',
        background='#120005', foreground=C['red'], font=_B, padding=[14,7], relief='flat')
    s.map('Stop.TButton',
        background=[('active','#1f000a'),('disabled',C['bg3'])],
        foreground=[('disabled',C['muted'])])
    s.configure('TCheckbutton', background=C['panel'], foreground=C['text2'], font=_UI)
    s.map('TCheckbutton', background=[('active',C['panel'])])
    s.configure('TScale', background=C['panel'], troughcolor=C['bg3'],
                sliderlength=14, sliderrelief='flat')

# ─── LOGO ──────────────────────────────────────────────────────────────────────
def _logo(size=36):
    try:
        raw = urllib.request.urlopen(LOGO_URL, timeout=5).read()
        if HAS_PIL:
            import io as _io
            img  = Image.open(_io.BytesIO(raw)).resize((size,size),Image.LANCZOS)
            mask = Image.new('L',(size,size),0)
            ImageDraw.Draw(mask).ellipse((0,0,size,size),fill=255)
            res  = Image.new('RGBA',(size,size),(0,0,0,0))
            res.paste(img, mask=mask)
            return ImageTk.PhotoImage(res)
        else:
            import tempfile
            with tempfile.NamedTemporaryFile(suffix='.png',delete=False) as f:
                f.write(raw); tmp=f.name
            p=tk.PhotoImage(file=tmp)
            try: os.unlink(tmp)
            except: pass
            return p
    except: return None

# ══════════════════════════════════════════════════════════════════════════════
# MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════
class App:
    def __init__(self, root):
        self.root        = root
        self.findings    : list[dict] = []
        self.scan_active = False
        self._logo_img   = None
        self._sort_rev   : dict[str,bool] = {}
        self._start_time = None
        self._elapsed_id = None
        self._code_content = ''
        _style()
        self._build()
        threading.Thread(target=self._fetch_logo, daemon=True).start()
        self._log(f'JSSecretHunter v{VERSION} ready','ok')
        self._log(f'Platform : {platform.system()} {platform.release()}','dim')
        self._log(f'DISPLAY  : {os.environ.get("DISPLAY","N/A")}','dim')
        src = REGEX_F.name if REGEX_F.exists() else 'built-in fallback'
        self._log(f'Patterns : {len(_compiled)} from {src}','info')
        if not REGEX_F.exists():
            self._log('⚠ secretfinder_regexes.txt not found!','warn')

    def _fetch_logo(self):
        p = _logo(36)
        if p:
            self._logo_img = p
            self.root.after(0, lambda: self._logo_lbl.configure(image=p, text=''))

    # ── BUILD ──────────────────────────────────────────────────────────────────
    def _build(self):
        self.root.title(f'JSSecretHunter  ·  v{VERSION}  ·  github.com/mohidqx')
        self.root.geometry('1400x900')
        self.root.minsize(1100,700)
        self.root.configure(bg=C['bg'])
        if _W:
            try:
                from ctypes import windll; windll.shcore.SetProcessDpiAwareness(1)
            except: pass
        self._hdr()
        self._body()
        self._statusbar()

    # ── HEADER ─────────────────────────────────────────────────────────────────
    def _hdr(self):
        hdr = tk.Frame(self.root, bg=C['hdr_bg'], height=54)
        hdr.pack(fill='x'); hdr.pack_propagate(False)
        tk.Frame(hdr, bg=C['acc'], width=4).pack(side='left', fill='y')

        # Logo + title
        self._logo_lbl = tk.Label(hdr, text='⬡', font=('',18),
                                   bg=C['hdr_bg'], fg=C['acc'])
        self._logo_lbl.pack(side='left', padx=(12,6))
        tk.Label(hdr, text='JSSecretHunter', font=_BIG,
                 bg=C['hdr_bg'], fg=C['text']).pack(side='left')
        tk.Label(hdr, text=f'  v{VERSION}', font=_UI,
                 bg=C['hdr_bg'], fg=C['muted']).pack(side='left')
        tk.Label(hdr, text='  AUTHORIZED USE ONLY  ',
                 font=(_UI[0],8,'bold'), bg=C['acc_dim'],
                 fg=C['acc']).pack(side='left', padx=12)

        # Center: Scan Status + progress + elapsed
        ctr = tk.Frame(hdr, bg=C['hdr_bg'])
        ctr.pack(side='left', fill='both', expand=True, padx=20)

        row1 = tk.Frame(ctr, bg=C['hdr_bg'])
        row1.pack(fill='x', pady=(6,0))
        tk.Label(row1, text='Scan Status:', font=_B,
                 bg=C['hdr_bg'], fg=C['text2']).pack(side='left')
        self._scan_status_lbl = tk.Label(row1, text='  Ready',
                                          font=_UI, bg=C['hdr_bg'], fg=C['muted'])
        self._scan_status_lbl.pack(side='left')
        self._elapsed_lbl = tk.Label(row1, text='Elapsed: 00:00',
                                      font=_UI, bg=C['hdr_bg'], fg=C['cyan'])
        self._elapsed_lbl.pack(side='right', padx=10)

        self.hdr_prog_var = tk.DoubleVar()
        self._hdr_pb = ttk.Progressbar(ctr, variable=self.hdr_prog_var,
                                        maximum=100, style='TProgressbar')
        self._hdr_pb.pack(fill='x', pady=(4,6))

        # Right
        rr = tk.Frame(hdr, bg=C['hdr_bg'])
        rr.pack(side='right', padx=12)
        ttk.Button(rr, text='⟳ Auto-Update', style='Ghost.TButton',
                   command=lambda: threading.Thread(
                       target=do_update, args=(self._log,), daemon=True).start()
                   ).pack(side='right', padx=4)
        tk.Label(rr, text='github.com/mohidqx', font=(_UI[0],9),
                 bg=C['hdr_bg'], fg=C['muted']).pack(side='right', padx=8)

        tk.Frame(self.root, bg=C['border2'] if True else C['acc'], height=1).pack(fill='x')

    # ── BODY ───────────────────────────────────────────────────────────────────
    def _body(self):
        pw = tk.PanedWindow(self.root, orient='horizontal',
                             bg=C['border'], sashwidth=3, sashrelief='flat', bd=0)
        pw.pack(fill='both', expand=True)
        pw.add(self._left(),  minsize=290, width=295)
        pw.add(self._right(), minsize=700)

    # ══════════════════════════════════════════════════════════════════════════
    # LEFT PANEL
    # ══════════════════════════════════════════════════════════════════════════
    def _left(self):
        outer  = tk.Frame(self.root, bg=C['bg2'])
        canvas = tk.Canvas(outer, bg=C['bg2'], highlightthickness=0, bd=0)
        vsb    = ttk.Scrollbar(outer, orient='vertical', command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side='left', fill='both', expand=True)
        vsb.pack(side='right', fill='y')
        inner = tk.Frame(canvas, bg=C['bg2'])
        win   = canvas.create_window((0,0), window=inner, anchor='nw')
        canvas.bind('<Configure>', lambda e: canvas.itemconfigure(win, width=e.width))
        inner.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        for ev,d in [('<MouseWheel>',-1),('<Button-4>',-1),('<Button-5>',1)]:
            canvas.bind_all(ev, lambda e,dd=d:
                canvas.yview_scroll(dd if e.type=='38' or e.type=='39'
                                    else int(-e.delta/60) if hasattr(e,'delta') and e.delta
                                    else dd, 'units'))

        p = inner

        # ── Section helper ──────────────────────────────────────────────────
        def sec(title, right_widget=None):
            hf = tk.Frame(p, bg=C['acc_dim'])
            hf.pack(fill='x', pady=(8,0))
            tk.Label(hf, text=f' {title}', font=(_UI[0],8,'bold'),
                     bg=C['acc_dim'], fg=C['acc']).pack(side='left', pady=3, padx=4)
            if right_widget:
                right_widget(hf)
            body = tk.Frame(p, bg=C['panel'],
                            highlightbackground=C['border'], highlightthickness=1)
            body.pack(fill='x')
            return body

        def lbl(parent, text, fg=None):
            tk.Label(parent, text=text, font=_UI,
                     bg=C['panel'], fg=fg or C['text2']).pack(
                anchor='w', padx=8, pady=(4,1))

        def entry_row(parent, var, btn_text=None, btn_cmd=None):
            row = tk.Frame(parent, bg=C['panel'])
            row.pack(fill='x', padx=8, pady=(0,6))
            e = ttk.Entry(row, textvariable=var, font=_MN)
            e.pack(side='left', fill='x', expand=True)
            if btn_text:
                ttk.Button(row, text=btn_text, style='Sm.TButton',
                           command=btn_cmd).pack(side='right', padx=(4,0))
            return e

        # ── TARGET ──────────────────────────────────────────────────────────
        t = sec('TARGET')
        lbl(t, 'URL  (crawls all JS from page)')
        url_row = tk.Frame(t, bg=C['panel'])
        url_row.pack(fill='x', padx=8, pady=(0,4))
        self.url_var = tk.StringVar()
        self._url_entry = ttk.Entry(url_row, textvariable=self.url_var, font=_MN)
        self._url_entry.pack(side='left', fill='x', expand=True)
        self._url_ok_lbl = tk.Label(url_row, text='', font=('',10),
                                     bg=C['panel'], fg=C['green'])
        self._url_ok_lbl.pack(side='right', padx=(4,0))
        self.url_var.trace_add('write', self._validate_url)

        lbl(t, 'Bulk URL list  (.txt)')
        self.bulk_var = tk.StringVar()
        entry_row(t, self.bulk_var, '…', self._browse_bulk)

        lbl(t, 'Local JS file / directory')
        self.local_var = tk.StringVar()
        entry_row(t, self.local_var, '📁', self._browse_local)

        # ── OPTIONS ─────────────────────────────────────────────────────────
        def opt_right(hf):
            tk.Label(hf, text='Thread usage', font=(_UI[0],7),
                     bg=C['acc_dim'], fg=C['muted']).pack(side='right', padx=4)
            MiniBar(hf, bars=8, bg=C['acc_dim'], width=60, height=14).pack(
                side='right', padx=(0,4), pady=2)
        o = sec('OPTIONS', opt_right)

        og = tk.Frame(o, bg=C['panel'])
        og.pack(fill='x', padx=8, pady=4)
        for i in range(4): og.columnconfigure(i, weight=1)

        def spin(lbl_t, var, r, c, lo=1, hi=100, w=5):
            tk.Label(og, text=lbl_t, font=_UI,
                     bg=C['panel'], fg=C['text2']).grid(row=r,column=c,sticky='w',pady=2)
            ttk.Spinbox(og, from_=lo, to=hi, textvariable=var,
                        width=w).grid(row=r,column=c+1,sticky='w',padx=(3,12))

        self.threads_var = tk.IntVar(value=8)
        self.timeout_var = tk.IntVar(value=15)
        self.delay_var   = tk.DoubleVar(value=0.3)
        self.retry_var   = tk.IntVar(value=3)
        spin('Threads',    self.threads_var, 0, 0)
        spin('Timeout(s)', self.timeout_var, 0, 2, 5, 120)
        spin('Delay(s)',   self.delay_var,   1, 0, w=6)
        spin('Retries',    self.retry_var,   1, 2, 1, 10)

        ck = tk.Frame(o, bg=C['panel'])
        ck.pack(fill='x', padx=8, pady=(2,2))
        self.scan_page_var = tk.BooleanVar(value=True)
        self.dedup_var     = tk.BooleanVar(value=True)
        ttk.Checkbutton(ck, text='Scan HTML page',
                        variable=self.scan_page_var).pack(side='left')
        ttk.Checkbutton(ck, text='Dedup results',
                        variable=self.dedup_var).pack(side='left', padx=10)

        # Scan Depth slider
        dp = tk.Frame(o, bg=C['panel'])
        dp.pack(fill='x', padx=8, pady=(0,6))
        tk.Label(dp, text='Scan Depth', font=_UI,
                 bg=C['panel'], fg=C['text2']).pack(side='left')
        self.depth_var = tk.IntVar(value=2)
        sd = ttk.Scale(dp, from_=1, to=5, variable=self.depth_var, orient='horizontal')
        sd.pack(side='left', fill='x', expand=True, padx=6)
        # Depth labels
        dlf = tk.Frame(o, bg=C['panel'])
        dlf.pack(fill='x', padx=8, pady=(0,6))
        for i,n in enumerate('12345'):
            tk.Label(dlf, text=n, font=(_UI[0],7),
                     bg=C['panel'], fg=C['muted']).pack(side='left', expand=True)

        # ── OUTPUT DIR ──────────────────────────────────────────────────────
        def od_right(hf):
            ttk.Button(hf, text='PDF', style='Sm.TButton',
                       command=self._export_pdf).pack(side='right', padx=2, pady=2)
            ttk.Button(hf, text='JSON', style='Sm.TButton',
                       command=self._export_json).pack(side='right', padx=2, pady=2)
            tk.Label(hf, text='Quick view:', font=(_UI[0],7),
                     bg=C['acc_dim'], fg=C['muted']).pack(side='right', padx=4)
        od = sec('OUTPUT DIRECTORY', od_right)
        self.outdir_var = tk.StringVar(value=str(Path.cwd()/'output'))
        entry_row(od, self.outdir_var, '📂', self._browse_outdir)

        # ── REGEX FILE ──────────────────────────────────────────────────────
        def rf_right(hf):
            self._pat_bar = MiniBar(hf, bars=6, bg=C['acc_dim'], width=50, height=14)
            self._pat_bar.pack(side='right', padx=(0,4), pady=2)
            tk.Label(hf, text='Custom profile applied',
                     font=(_UI[0],7), bg=C['acc_dim'], fg=C['green']).pack(
                side='right', padx=4)
        rf = sec('REGEX FILE', rf_right)
        self._rf_status = tk.Label(rf, text=f'Loaded {len(_compiled)} patterns. Custom profile applied.',
                                    font=(_UI[0],8), bg=C['panel'], fg=C['green'])
        self._rf_status.pack(anchor='w', padx=8, pady=(4,2))
        self.regex_file_var = tk.StringVar(value=str(REGEX_F))
        entry_row(rf, self.regex_file_var, '…', self._browse_regex)
        rb = tk.Frame(rf, bg=C['panel'])
        rb.pack(fill='x', padx=8, pady=(0,6))
        ttk.Button(rb, text='⟳ Reload Patterns', style='Sm.TButton',
                   command=self._reload_pats).pack(side='left')
        self._custom_lbl = tk.Label(rb, text='Custom profile applied',
                                     font=(_UI[0],8), bg=C['panel'], fg=C['green'])
        self._custom_lbl.pack(side='left', padx=8)

        # ── PROXIES ─────────────────────────────────────────────────────────
        px = sec('PROXIES  (one per line: http/https/socks5://host:port)')
        self._proxy_txt = tk.Text(px, bg=C['bg3'], fg=C['text2'],
                                   insertbackground=C['acc'],
                                   font=_MN, height=4, relief='flat', wrap='none')
        self._proxy_txt.pack(fill='x', padx=8, pady=(4,4))

        # Quick presets row
        pr = tk.Frame(px, bg=C['panel'])
        pr.pack(fill='x', padx=8, pady=(0,4))
        tk.Label(pr, text='Quick presets:', font=(_UI[0],8),
                 bg=C['panel'], fg=C['text2']).pack(side='left')
        for label in ['Proxy presets', 'Different proxy', 'UMSP proxy']:
            ttk.Button(pr, text=label, style='Sm.TButton',
                       command=lambda l=label: self._proxy_preset(l)
                       ).pack(side='left', padx=(4,0))

        # Validation label
        self._proxy_val_lbl = tk.Label(px, text='Validation list: 0 proxies loaded',
                                        font=(_UI[0],8), bg=C['panel'], fg=C['muted'])
        self._proxy_val_lbl.pack(anchor='w', padx=8, pady=(0,4))

        pb = tk.Frame(px, bg=C['panel'])
        pb.pack(fill='x', padx=8, pady=(0,8))
        ttk.Button(pb, text='Apply Proxies', style='Sm.TButton',
                   command=self._apply_proxies).pack(side='left')
        ttk.Button(pb, text='Clear', style='Sm.TButton',
                   command=lambda: self._proxy_txt.delete('1.0','end')).pack(side='left', padx=4)
        self._proxy_lbl = tk.Label(pb, text='No proxies',
                                    font=(_UI[0],8), bg=C['panel'], fg=C['muted'])
        self._proxy_lbl.pack(side='left', padx=8)

        # ── ACTIONS ─────────────────────────────────────────────────────────
        tk.Frame(p, bg=C['bg2'], height=8).pack(fill='x')
        ab = tk.Frame(p, bg=C['bg2'])
        ab.pack(fill='x', padx=8, pady=4)
        self.scan_btn = ttk.Button(ab, text='▶  START SCAN',
                                    style='Red.TButton', command=self._start_scan)
        self.scan_btn.pack(side='left', fill='x', expand=True)
        self.stop_btn = ttk.Button(ab, text='■  STOP', style='Stop.TButton',
                                    command=self._stop_scan, state='disabled')
        self.stop_btn.pack(side='right', padx=(6,0))

        # ── STATS ───────────────────────────────────────────────────────────
        sg = tk.Frame(p, bg=C['bg2'])
        sg.pack(fill='x', padx=8, pady=4)
        for i in range(4): sg.columnconfigure(i, weight=1)
        self._s_total = self._stat(sg,'0','TOTAL',   0,C['text'])
        self._s_crit  = self._stat(sg,'0','CRITICAL',1,C['red'])
        self._s_high  = self._stat(sg,'0','HIGH',    2,C['amber'])
        self._s_med   = self._stat(sg,'0','MEDIUM',  3,C['cyan'])

        return outer

    def _stat(self, parent, val, lbl, col, fg):
        box = tk.Frame(parent, bg=C['glass'],
                       highlightbackground=C['border'], highlightthickness=1)
        box.grid(row=0, column=col, sticky='nsew', padx=1)
        n = tk.Label(box, text=val, font=(_BIG[0],18,'bold'), bg=C['glass'], fg=fg)
        n.pack(pady=(6,0))
        tk.Label(box, text=lbl, font=(_UI[0],7,'bold'),
                 bg=C['glass'], fg=C['muted']).pack(pady=(0,6))
        return n

    # ══════════════════════════════════════════════════════════════════════════
    # RIGHT PANEL
    # ══════════════════════════════════════════════════════════════════════════
    def _right(self):
        outer = tk.Frame(self.root, bg=C['bg'])
        nb    = ttk.Notebook(outer)
        nb.pack(fill='both', expand=True)
        nb.add(self._tab_results(nb),  text='  🔎  Results   ')
        nb.add(self._tab_detail(nb),   text='  📄  Detail    ')
        nb.add(self._tab_patterns(nb), text='  ⚙  Patterns  ')
        nb.add(self._tab_log(nb),      text='  📋  Log       ')
        return outer

    # ── RESULTS TAB ────────────────────────────────────────────────────────────
    def _tab_results(self, nb):
        f = ttk.Frame(nb)

        # Main horizontal split: table+code LEFT, charts RIGHT
        main_pw = tk.PanedWindow(f, orient='horizontal',
                                  bg=C['border'], sashwidth=3, sashrelief='flat', bd=0)
        main_pw.pack(fill='both', expand=True)

        left  = tk.Frame(main_pw, bg=C['bg'])
        right = tk.Frame(main_pw, bg=C['glass'],
                         highlightbackground=C['border'], highlightthickness=1)
        main_pw.add(left,  minsize=500)
        main_pw.add(right, minsize=170, width=200)

        # ── Filter toolbar ──────────────────────────────────────────────────
        tb = tk.Frame(left, bg=C['glass2'], pady=6)
        tb.pack(fill='x')
        tk.Label(tb, text='Filter:', font=_UI,
                 bg=C['glass2'], fg=C['muted']).pack(side='left', padx=(12,4))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add('write', lambda *_: self._apply_filter())
        ttk.Entry(tb, textvariable=self.filter_var, width=20, font=_MN).pack(side='left')

        self.sev_filter = tk.StringVar(value='ALL')
        cb = ttk.Combobox(tb, textvariable=self.sev_filter, width=10,
                           values=['ALL','CRITICAL','HIGH','MEDIUM'], state='readonly')
        cb.pack(side='left', padx=5)
        cb.bind('<<ComboboxSelected>>', lambda *_: self._apply_filter())

        ttk.Button(tb, text='✕ Clear', style='Sm.TButton',
                   command=self._clear_results).pack(side='left', padx=4)
        ttk.Button(tb, text='📋 Copy', style='Ghost.TButton',
                   command=self._copy_sel).pack(side='right', padx=4)
        ttk.Button(tb, text='💾 Export', style='Ghost.TButton',
                   command=self._export).pack(side='right', padx=4)

        # ── Table + code vertical split ─────────────────────────────────────
        vert_pw = tk.PanedWindow(left, orient='vertical',
                                  bg=C['border'], sashwidth=3, sashrelief='flat', bd=0)
        vert_pw.pack(fill='both', expand=True)

        # Table frame
        tf = tk.Frame(left, bg=C['bg'])
        self._build_tree(tf)

        # Code viewer frame
        cf = tk.Frame(left, bg=C['code_bg'])
        self._build_code(cf)

        vert_pw.add(tf, minsize=120)
        vert_pw.add(cf, minsize=80, height=160)

        # ── Right charts ────────────────────────────────────────────────────
        tk.Label(right, text='SEVERITY BREAKDOWN',
                 font=(_UI[0],8,'bold'), bg=C['glass'], fg=C['muted']).pack(
            anchor='w', padx=8, pady=(10,0))

        self._donut = DonutChart(right, width=190, height=120, bg=C['glass'])
        self._donut.pack(padx=8, pady=4)

        # Legend
        leg = tk.Frame(right, bg=C['glass'])
        leg.pack(fill='x', padx=12, pady=(0,8))
        for label, clr in [('High',C['amber']),('Medium',C['cyan']),('Medium',C['cyan']),('High',C['amber'])]:
            rw = tk.Frame(leg, bg=C['glass'])
            rw.pack(fill='x', pady=1)
            tk.Frame(rw, bg=clr, width=8, height=8).pack(side='left', padx=(0,4))
            tk.Label(rw, text=label, font=(_UI[0],8), bg=C['glass'],
                     fg=C['text2']).pack(side='left')

        tk.Frame(right, bg=C['border'], height=1).pack(fill='x', padx=8, pady=4)

        tk.Label(right, text='FINDINGS OVER TIME',
                 font=(_UI[0],8,'bold'), bg=C['glass'], fg=C['muted']).pack(
            anchor='w', padx=8)
        self._linechart = LineChart(right, width=190, height=90, bg=C['glass'])
        self._linechart.pack(padx=8, pady=(4,4))

        # Y-axis labels for line chart
        for v in ['50','40','30','20','10','0']:
            tk.Label(right, text=v, font=(_UI[0],6), bg=C['glass'],
                     fg=C['muted']).pack(anchor='w', padx=8)

        return f

    def _build_tree(self, parent):
        cols = ('severity','type','source','line','value','_copy')
        self.tree = ttk.Treeview(parent, columns=cols, show='headings', selectmode='browse')
        self.tree.tag_configure('CRITICAL', background=C['row_h'], foreground=C['crit_fg'])
        self.tree.tag_configure('HIGH',     background=C['row_m'], foreground=C['high_fg'])
        self.tree.tag_configure('MEDIUM',   background=C['row_n'], foreground=C['med_fg'])

        widths = {'severity':80,'type':180,'source':220,'line':45,'value':300,'_copy':50}
        hdrs   = {'severity':'SEVERITY ▲','type':'TYPE','source':'SOURCE',
                  'line':'LINE','value':'VALUE','_copy':''}
        for col in cols:
            self.tree.heading(col, text=hdrs[col],
                              command=lambda c=col: self._sort(c) if c!='_copy' else None)
            self.tree.column(col, width=widths[col], minwidth=30,
                             stretch=(col=='value'))

        vsb = ttk.Scrollbar(parent, orient='vertical',   command=self.tree.yview)
        hsb = ttk.Scrollbar(parent, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        parent.rowconfigure(0, weight=1); parent.columnconfigure(0, weight=1)
        self.tree.bind('<<TreeviewSelect>>', self._on_select)
        self.tree.bind('<Double-1>', self._tree_dbl)
        self.tree.bind('<Button-1>', self._tree_click)

    def _build_code(self, parent):
        tk.Frame(parent, bg=C['border'], height=1).pack(fill='x')
        self.code_txt = tk.Text(parent, bg=C['code_bg'], fg=C['text'],
                                 insertbackground=C['acc'],
                                 font=_MN, relief='flat', bd=0,
                                 wrap='none', state='disabled')
        code_vsb = ttk.Scrollbar(parent, orient='vertical',   command=self.code_txt.yview)
        code_hsb = ttk.Scrollbar(parent, orient='horizontal', command=self.code_txt.xview)
        self.code_txt.configure(yscrollcommand=code_vsb.set, xscrollcommand=code_hsb.set)
        self.code_txt.pack(side='left', fill='both', expand=True)
        code_vsb.pack(side='right', fill='y')
        code_hsb.pack(side='bottom', fill='x')
        # Tags for syntax highlighting
        self.code_txt.tag_config('lineno', foreground=C['muted'])
        self.code_txt.tag_config('kw',     foreground=C['acc2'])
        self.code_txt.tag_config('str',    foreground=C['green'])
        self.code_txt.tag_config('hl',     background='#2a1000', foreground=C['amber'])
        self.code_txt.tag_config('cmt',    foreground=C['muted'])

    def _show_code(self, finding):
        """Show JS source around the finding line."""
        self.code_txt.configure(state='normal')
        self.code_txt.delete('1.0','end')
        content = self._code_cache.get(finding['source'],'')
        if not content:
            self.code_txt.insert('end', f'  // Source: {finding["source"]}\n', 'cmt')
            self.code_txt.insert('end', f'  // Context: {finding["context"]}\n', 'str')
            self.code_txt.configure(state='disabled')
            return
        lines   = content.splitlines()
        target  = finding['line']
        start   = max(0, target-10)
        end     = min(len(lines), target+10)
        kws     = re.compile(r'\b(var|let|const|function|return|class|import|export|from|if|else|try|catch|new)\b')
        strs    = re.compile(r'(["\'])(?:(?!\1).)*\1')
        cmts    = re.compile(r'//.*$|/\*[\s\S]*?\*/')
        for i, ln in enumerate(lines[start:end], start+1):
            prefix = f'{i:4d}  '
            is_hl  = (i == target)
            tag    = 'hl' if is_hl else None
            self.code_txt.insert('end', prefix, 'lineno' if not is_hl else 'hl')
            self.code_txt.insert('end', ln + '\n', tag or '')
        self.code_txt.see(f'{target - start}.0')
        self.code_txt.configure(state='disabled')

    # ── DETAIL TAB ─────────────────────────────────────────────────────────────
    def _tab_detail(self, nb):
        f = ttk.Frame(nb)
        self.detail = scrolledtext.ScrolledText(
            f, bg=C['bg2'], fg=C['text'], insertbackground=C['acc'],
            font=_MN, relief='flat', bd=0, wrap='word', state='disabled')
        self.detail.pack(fill='both', expand=True, padx=2, pady=2)
        for tag, fg in [('key',C['acc']),('val',C['green']),('crit',C['red']),
                        ('high',C['amber']),('med',C['cyan']),('dim',C['muted'])]:
            self.detail.tag_config(tag, foreground=fg)
        return f

    # ── PATTERNS TAB ───────────────────────────────────────────────────────────
    def _tab_patterns(self, nb):
        f = ttk.Frame(nb)
        hdr = tk.Frame(f, bg=C['bg'])
        hdr.pack(fill='x', padx=12, pady=(10,6))
        tk.Label(hdr, text='Loaded Regex Patterns', font=_H,
                 bg=C['bg'], fg=C['acc']).pack(side='left')
        self.pat_q = tk.StringVar()
        self.pat_q.trace_add('write', lambda *_: self._fill_pats())
        ttk.Entry(hdr, textvariable=self.pat_q, width=26, font=_MN).pack(side='right')
        tk.Label(hdr, text='Search:', font=_UI,
                 bg=C['bg'], fg=C['muted']).pack(side='right', padx=(0,4))
        pf = tk.Frame(f, bg=C['bg'])
        pf.pack(fill='both', expand=True, padx=12, pady=(0,8))
        self.ptree = ttk.Treeview(pf, columns=('n','p'), show='headings')
        self.ptree.heading('n', text='PATTERN NAME')
        self.ptree.heading('p', text='REGEX')
        self.ptree.column('n', width=220, minwidth=100)
        self.ptree.column('p', width=500, minwidth=200, stretch=True)
        pv = ttk.Scrollbar(pf, orient='vertical',   command=self.ptree.yview)
        ph = ttk.Scrollbar(pf, orient='horizontal', command=self.ptree.xview)
        self.ptree.configure(yscrollcommand=pv.set, xscrollcommand=ph.set)
        self.ptree.grid(row=0, column=0, sticky='nsew')
        pv.grid(row=0, column=1, sticky='ns')
        ph.grid(row=1, column=0, sticky='ew')
        pf.rowconfigure(0, weight=1); pf.columnconfigure(0, weight=1)
        self._pcnt = tk.Label(f, text='', font=_UI, bg=C['bg'], fg=C['muted'])
        self._pcnt.pack(anchor='e', padx=12, pady=(0,4))
        self._fill_pats()
        return f

    def _fill_pats(self):
        self.ptree.delete(*self.ptree.get_children())
        q = getattr(self,'pat_q',None)
        q = q.get().lower() if q else ''
        n = 0
        for name, pat in _rex_raw.items():
            if q and q not in name.lower() and q not in pat.lower(): continue
            self.ptree.insert('','end', values=(name, pat)); n+=1
        self._pcnt.configure(text=f'{n} patterns shown')

    # ── LOG TAB ────────────────────────────────────────────────────────────────
    def _tab_log(self, nb):
        f  = ttk.Frame(nb)
        tb = tk.Frame(f, bg=C['glass2'], pady=6)
        tb.pack(fill='x')
        tk.Label(tb, text='Scan Log', font=_B,
                 bg=C['glass2'], fg=C['text2']).pack(side='left', padx=12)
        ttk.Button(tb, text='💾 Save', style='Sm.TButton',
                   command=self._save_log).pack(side='right', padx=8)
        ttk.Button(tb, text='✕ Clear', style='Sm.TButton',
                   command=self._clear_log).pack(side='right', padx=4)
        self.log_w = scrolledtext.ScrolledText(
            f, bg=C['bg'], fg=C['text2'], insertbackground=C['acc'],
            font=_MN, relief='flat', bd=0, wrap='word', state='disabled')
        self.log_w.pack(fill='both', expand=True, padx=2, pady=2)
        for tag, fg in [('ok',C['green']),('warn',C['amber']),
                        ('error',C['red']),('info',C['cyan']),('dim',C['muted'])]:
            self.log_w.tag_config(tag, foreground=fg)
        return f

    # ── STATUS BAR ─────────────────────────────────────────────────────────────
    def _statusbar(self):
        sb = tk.Frame(self.root, bg=C['hdr_bg'], height=26,
                      highlightbackground=C['border'], highlightthickness=1)
        sb.pack(fill='x', side='bottom'); sb.pack_propagate(False)
        self.status_var   = tk.StringVar(value='Ready')
        self.js_count_var = tk.StringVar(value='')

        tk.Label(sb, textvariable=self.status_var,
                 font=(_UI[0],8), bg=C['hdr_bg'], fg=C['muted']).pack(side='left',padx=10)
        tk.Label(sb, textvariable=self.js_count_var,
                 font=(_UI[0],8), bg=C['hdr_bg'], fg=C['cyan']).pack(side='left',padx=4)

        # Thread + memory + scan summary
        self._sb_scan_var = tk.StringVar(value='')
        tk.Label(sb, textvariable=self._sb_scan_var,
                 font=(_UI[0],8,'bold'), bg=C['hdr_bg'], fg=C['green']).pack(side='left',padx=10)

        tk.Label(sb, text=f'Python {sys.version.split()[0]}  ·  {platform.system()}  ·  {len(_rex_raw)} patterns',
                 font=(_UI[0],8), bg=C['hdr_bg'], fg=C['muted']).pack(side='right',padx=10)

        self._thread_lbl = tk.Label(sb, text='', font=(_UI[0],8),
                                     bg=C['hdr_bg'], fg=C['text2'])
        self._thread_lbl.pack(side='right', padx=8)
        self._mem_lbl = tk.Label(sb, text='', font=(_UI[0],8),
                                  bg=C['hdr_bg'], fg=C['text2'])
        self._mem_lbl.pack(side='right', padx=4)

    # ══════════════════════════════════════════════════════════════════════════
    # BROWSE HELPERS
    # ══════════════════════════════════════════════════════════════════════════
    def _browse_bulk(self):
        p=filedialog.askopenfilename(filetypes=[('Text','*.txt'),('All','*.*')])
        if p: self.bulk_var.set(p)

    def _browse_local(self):
        p=filedialog.askdirectory()
        if not p: p=filedialog.askopenfilename(filetypes=[('JS','*.js'),('All','*.*')])
        if p: self.local_var.set(p)

    def _browse_outdir(self):
        p=filedialog.askdirectory()
        if p: self.outdir_var.set(p)

    def _browse_regex(self):
        p=filedialog.askopenfilename(filetypes=[('Text','*.txt'),('Python','*.py'),('All','*.*')])
        if p: self.regex_file_var.set(p)

    def _validate_url(self, *_):
        url = self.url_var.get().strip()
        if re.match(r'https?://\S+', url):
            self._url_ok_lbl.configure(text='✓ ✓', fg=C['green'])
        elif url:
            self._url_ok_lbl.configure(text='✗', fg=C['red'])
        else:
            self._url_ok_lbl.configure(text='')

    # ══════════════════════════════════════════════════════════════════════════
    # PROXY HELPERS
    # ══════════════════════════════════════════════════════════════════════════
    def _apply_proxies(self):
        raw   = self._proxy_txt.get('1.0','end').strip()
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        _PM.load(lines)
        n = _PM.count
        self._proxy_lbl.configure(
            text=f'{n} proxies active' if n else 'No proxies',
            fg=C['green'] if n else C['muted'])
        self._proxy_val_lbl.configure(
            text=f'Validation list: {n} patterns mattore loaded',
            fg=C['green'] if n else C['muted'])
        self._log(f'Proxies: {n} loaded','info' if n else 'warn')

    def _proxy_preset(self, label):
        presets = {
            'Proxy presets': 'http://proxy1.example.com:8080\nhttp://proxy2.example.com:3128',
            'Different proxy': 'socks5://127.0.0.1:9050',
            'UMSP proxy': 'http://user:pass@proxy.umsp.net:8080',
        }
        self._proxy_txt.delete('1.0','end')
        self._proxy_txt.insert('end', presets.get(label,''))

    # ══════════════════════════════════════════════════════════════════════════
    # RELOAD PATTERNS
    # ══════════════════════════════════════════════════════════════════════════
    def _reload_pats(self):
        global _rex_raw, _compiled
        path = Path(self.regex_file_var.get().strip())
        new  = load_regexes(path)
        if not new:
            messagebox.showerror('Reload',f'No valid patterns:\n{path}'); return
        _rex_raw  = new
        _compiled = {n: re.compile(p) for n,p in _rex_raw.items()}
        self._rf_status.configure(text=f'Loaded {len(_compiled)} patterns. Custom profile applied.')
        self._fill_pats()
        self._log(f'Reloaded {len(_compiled)} patterns from {path.name}','ok')

    # ══════════════════════════════════════════════════════════════════════════
    # LOG HELPERS
    # ══════════════════════════════════════════════════════════════════════════
    def _log(self, msg, tag='dim'):
        def _do():
            self.log_w.configure(state='normal')
            ts = datetime.now().strftime('%H:%M:%S')
            self.log_w.insert('end', f'[{ts}] {msg}\n', tag)
            self.log_w.see('end')
            self.log_w.configure(state='disabled')
        self.root.after(0, _do)

    def _clear_log(self):
        self.log_w.configure(state='normal')
        self.log_w.delete('1.0','end')
        self.log_w.configure(state='disabled')

    def _save_log(self):
        p = filedialog.asksaveasfilename(
            defaultextension='.txt', filetypes=[('Text','*.txt')],
            initialfile=f'jssh_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt')
        if p:
            self.log_w.configure(state='normal')
            Path(p).write_text(self.log_w.get('1.0','end'), encoding='utf-8')
            self.log_w.configure(state='disabled')
            self._log(f'Log saved → {p}','ok')

    def _set_status(self, msg):
        self.root.after(0, lambda: self.status_var.set(msg))

    def _set_hdr_status(self, msg, color=None):
        self.root.after(0, lambda:
            self._scan_status_lbl.configure(text=f'  {msg}',
                                             fg=color or C['muted']))

    # ══════════════════════════════════════════════════════════════════════════
    # ELAPSED TIMER
    # ══════════════════════════════════════════════════════════════════════════
    def _start_elapsed(self):
        self._start_time = time.time()
        self._tick_elapsed()

    def _tick_elapsed(self):
        if not self.scan_active or not self._start_time:
            return
        el  = int(time.time() - self._start_time)
        mm  = el//60; ss = el%60
        self.root.after(0, lambda:
            self._elapsed_lbl.configure(text=f'Elapsed: {mm:02d}:{ss:02d}'))
        self._elapsed_id = self.root.after(1000, self._tick_elapsed)

    def _stop_elapsed(self):
        if self._elapsed_id:
            self.root.after_cancel(self._elapsed_id)
            self._elapsed_id = None

    # ══════════════════════════════════════════════════════════════════════════
    # SCAN
    # ══════════════════════════════════════════════════════════════════════════
    def _start_scan(self):
        targets = self._get_targets()
        if not targets:
            messagebox.showwarning('No Target',
                'Enter a URL, bulk list, or local path.')
            return
        self.scan_active  = True
        self.findings     = []
        self._code_cache : dict[str,str] = {}
        self.scan_btn.configure(state='disabled')
        self.stop_btn.configure(state='normal')
        self._clear_tree()
        self._upd_stats()
        self.hdr_prog_var.set(0)
        self._set_status('Scanning…')
        self._set_hdr_status('Scanning…', C['amber'])
        self._start_elapsed()
        threading.Thread(target=self._worker, args=(targets,), daemon=True).start()

    def _stop_scan(self):
        self.scan_active = False
        self.stop_btn.configure(state='disabled')
        self._log('Stop requested.','warn')
        self._set_hdr_status('Stopped', C['amber'])

    def _get_targets(self):
        out = []
        if self.url_var.get().strip():
            out.append(('url', self.url_var.get().strip()))
        if self.bulk_var.get().strip():
            try:
                for ln in Path(self.bulk_var.get().strip()).read_text().splitlines():
                    ln=ln.strip()
                    if ln and not ln.startswith('#'):
                        out.append(('url',ln))
            except Exception as e:
                self._log(f'Bulk error: {e}','error')
        if self.local_var.get().strip():
            out.append(('local', self.local_var.get().strip()))
        return out

    def _worker(self, targets):
        sev_order = {'MEDIUM':0,'HIGH':1,'CRITICAL':2}
        min_sev   = self.sev_filter.get() if hasattr(self,'sev_filter') else 'ALL'
        delay     = float(self.delay_var.get())
        retries   = int(self.retry_var.get())
        all_js    : list[tuple[str,str]] = []  # (url_or_path, kind)

        try:
            for kind, target in targets:
                if not self.scan_active: break
                if kind == 'url':
                    self._log(f'Fetching: {target}','info')
                    self._set_status(f'Fetching {target[:50]}…')
                    html = fetch(target, self.timeout_var.get(), retries, delay)
                    if not html:
                        self._log(f'Failed: {target}','error'); continue
                    links = extract_js(html, target)
                    if self.scan_page_var.get():
                        links.insert(0, target)
                    self._log(f'Found {len(links)} JS files on {target}','ok')
                    all_js.extend([(l,'url') for l in links])
                else:
                    path = Path(target)
                    if path.is_dir():
                        files = list(path.rglob('*.js'))
                        all_js.extend([(str(f),'local') for f in files])
                        self._log(f'{len(files)} local files in {target}','ok')
                    elif path.is_file():
                        all_js.append((str(path),'local'))
                        self._log(f'Local: {target}','ok')

            if not all_js:
                self._log('No JS files found.','warn'); return

            total = len(all_js)
            self.root.after(0, lambda:
                self.js_count_var.set(f'{total} JS queued'))
            self.root.after(0, lambda:
                self._thread_lbl.configure(
                    text=f'▶ {self.threads_var.get()}/{self.threads_var.get()} threads'))

            done    = 0
            found_t = 0

            with ThreadPoolExecutor(max_workers=self.threads_var.get()) as ex:
                fmap = {ex.submit(self._scan_one, src, kind, delay, retries): src
                        for src, kind in all_js if self.scan_active}
                for fut in as_completed(fmap):
                    if not self.scan_active:
                        ex.shutdown(wait=False, cancel_futures=True); break
                    done += 1
                    pct   = (done/total)*100
                    self.root.after(0, lambda p=pct: self.hdr_prog_var.set(p))
                    try: results = fut.result()
                    except Exception as e:
                        self._log(f'Error: {e}','error'); results=[]

                    if results:
                        self.findings.extend(results)
                        found_t += len(results)
                        self.root.after(0, lambda r=results: self._add_rows(r))
                        self.root.after(0, self._upd_stats)
                        self.root.after(0, lambda n=found_t:
                            self._sb_scan_var.configure(
                                text=f'SCAN STATUS: Running. Total {n} findings'))
                        self.root.after(0, lambda n=found_t:
                            self._linechart.add(n))
                        self.root.after(0, lambda:
                            self._donut.update_data(self.findings))
                    self._set_status(f'[{done}/{total}] {len(self.findings)} secrets')

        except Exception as e:
            self._log(f'Worker error:\n{traceback.format_exc()}','error')
        finally:
            self._finish()

    def _scan_one(self, src, kind, delay, retries):
        """Fetch JS content and run ALL regex patterns on it."""
        if kind == 'url':
            content = fetch(src, self.timeout_var.get(), retries, delay)
            if not content:
                self._log(f'Skip: {src.split("/")[-1][:50]}','warn')
                return []
        else:
            try: content = Path(src).read_text(errors='replace')
            except Exception as e:
                self._log(f'Read error: {e}','warn'); return []

        # Cache content for code viewer
        self._code_cache[src] = content

        results = scan_content(content, src)
        if results:
            self._log(f'✓ {len(results)} secrets — {src.split("/")[-1][:55]}','ok')
        return results

    def _finish(self):
        def _do():
            self.scan_active = False
            self._stop_elapsed()
            self.scan_btn.configure(state='normal')
            self.stop_btn.configure(state='disabled')
            self.hdr_prog_var.set(100)
            n    = len(self.findings)
            crit = sum(1 for f in self.findings if f['severity']=='CRITICAL')
            high = sum(1 for f in self.findings if f['severity']=='HIGH')
            med  = sum(1 for f in self.findings if f['severity']=='MEDIUM')
            self._set_status(f'Done — {n} secrets found')
            self._set_hdr_status('Complete', C['green'])
            self._sb_scan_var.configure(
                text=f'SCAN STATUS: Complete. Total {n} findings, {high} H findings, {crit} C findings')
            self._thread_lbl.configure(text=f'✓ {self.threads_var.get()}/{self.threads_var.get()} threads')
            self._log(f'── Complete: {n} total secrets [{crit} CRIT, {high} HIGH, {med} MED] ──','ok')
            if self.findings: self._autosave()
            self._donut.update_data(self.findings)
        self.root.after(0, _do)

    def _autosave(self):
        try:
            out = Path(self.outdir_var.get())
            out.mkdir(parents=True, exist_ok=True)
            ts  = datetime.now().strftime('%Y%m%d_%H%M%S')
            fmt = 'json'
            p   = out/f'jssh_{ts}.{fmt}'
            write_report(self.findings, p, fmt)
            self._log(f'Auto-saved → {p}','ok')
        except Exception as e:
            self._log(f'Auto-save error: {e}','error')

    # ══════════════════════════════════════════════════════════════════════════
    # TREE HELPERS
    # ══════════════════════════════════════════════════════════════════════════
    def _add_rows(self, results):
        for f in results:
            src = f['source'].split('/')[-1][:40]
            self.tree.insert('','end',
                values=(f['severity'], f['type'], src, f['line'],
                        f['value'][:80], '⎘ Copy'),
                tags=(f['severity'],))

    def _clear_tree(self):
        self.tree.delete(*self.tree.get_children())

    def _clear_results(self):
        self.findings = []
        self._clear_tree()
        self._upd_stats()
        self.detail.configure(state='normal')
        self.detail.delete('1.0','end')
        self.detail.configure(state='disabled')
        self.code_txt.configure(state='normal')
        self.code_txt.delete('1.0','end')
        self.code_txt.configure(state='disabled')
        self._donut.update_data([])

    def _apply_filter(self):
        q   = self.filter_var.get().lower()
        sev = self.sev_filter.get()
        self._clear_tree()
        for f in self.findings:
            if sev!='ALL' and f['severity']!=sev: continue
            if q and q not in json.dumps(f).lower(): continue
            src = f['source'].split('/')[-1][:40]
            self.tree.insert('','end',
                values=(f['severity'],f['type'],src,f['line'],
                        f['value'][:80],'⎘ Copy'),
                tags=(f['severity'],))

    def _sort(self, col):
        rev  = self._sort_rev.get(col,False)
        data = [(self.tree.set(c,col),c) for c in self.tree.get_children('')]
        data.sort(reverse=rev)
        for i,(_,c) in enumerate(data): self.tree.move(c,'',i)
        self._sort_rev[col]=not rev

    def _on_select(self, _=None):
        sel = self.tree.selection()
        if not sel: return
        vals = self.tree.item(sel[0])['values']
        if not vals: return
        for f in self.findings:
            if str(f['severity'])==str(vals[0]) and str(f['type'])==str(vals[1]) and str(f['line'])==str(vals[3]):
                self._show_detail(f)
                self._show_code(f)
                break

    def _tree_click(self, event):
        """Handle click on Copy column."""
        region = self.tree.identify('region', event.x, event.y)
        if region != 'cell': return
        col = self.tree.identify_column(event.x)
        if col == '#6':  # _copy column
            item = self.tree.identify_row(event.y)
            if item:
                vals = self.tree.item(item)['values']
                self.root.clipboard_clear()
                self.root.clipboard_append(str(vals[4]) if len(vals)>4 else '')
                self._set_status('Value copied to clipboard.')

    def _tree_dbl(self, event):
        sel = self.tree.selection()
        if not sel: return
        vals = self.tree.item(sel[0])['values']
        if vals:
            self.root.clipboard_clear()
            self.root.clipboard_append('\t'.join(str(v) for v in vals[:-1]))
            self._set_status('Row copied.')

    def _show_detail(self, f):
        st = {'CRITICAL':'crit','HIGH':'high','MEDIUM':'med'}.get(f['severity'],'dim')
        self.detail.configure(state='normal')
        self.detail.delete('1.0','end')
        self.detail.insert('end','─'*66+'\n','dim')
        self.detail.insert('end',f"  SECRET FOUND  [{f['severity']}]\n", st)
        self.detail.insert('end','─'*66+'\n\n','dim')
        for k,v,t in [('Type',f['type'],'key'),
                      ('Source',f['source'],None),
                      ('Line',str(f['line']),'dim'),
                      ('Severity',f['severity'],st)]:
            self.detail.insert('end',f'  {k:<12}: ','dim')
            self.detail.insert('end', v+'\n', t)
        self.detail.insert('end','\n  Match:\n','dim')
        self.detail.insert('end',f"  {f['value']}\n",'val')
        self.detail.insert('end','\n  Context:\n','dim')
        self.detail.insert('end',f"  {f['context']}\n")
        self.detail.insert('end','\n'+'─'*66+'\n','dim')
        self.detail.configure(state='disabled')

    # ══════════════════════════════════════════════════════════════════════════
    # EXPORT
    # ══════════════════════════════════════════════════════════════════════════
    def _export(self):
        if not self.findings:
            messagebox.showinfo('Export','No findings.'); return
        fmt = 'json'
        p   = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=[('JSON','*.json'),('CSV','*.csv'),('Text','*.txt')],
            initialfile=f'jssh_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
        if p:
            ext = Path(p).suffix.lstrip('.')
            write_report(self.findings, Path(p), ext if ext in ('json','csv','txt') else 'json')
            self._log(f'Exported → {p}','ok')
            messagebox.showinfo('Export',f'{len(self.findings)} findings saved.')

    def _export_json(self):
        if not self.findings: return
        out = Path(self.outdir_var.get()); out.mkdir(parents=True, exist_ok=True)
        p   = out/f'jssh_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        write_report(self.findings, p, 'json')
        self._log(f'JSON exported → {p}','ok')

    def _export_pdf(self):
        messagebox.showinfo('PDF Export',
            'PDF export requires: pip install reportlab\n'
            'Use JSON/CSV export for now.')

    def _copy_sel(self):
        sel = self.tree.selection()
        if not sel: messagebox.showinfo('Copy','Select a row first.'); return
        vals = self.tree.item(sel[0])['values']
        self.root.clipboard_clear()
        self.root.clipboard_append('\t'.join(str(v) for v in vals[:-1]))
        self._set_status('Copied.')

    # ══════════════════════════════════════════════════════════════════════════
    # STATS
    # ══════════════════════════════════════════════════════════════════════════
    def _upd_stats(self):
        n    = len(self.findings)
        crit = sum(1 for f in self.findings if f['severity']=='CRITICAL')
        high = sum(1 for f in self.findings if f['severity']=='HIGH')
        med  = sum(1 for f in self.findings if f['severity']=='MEDIUM')
        self._s_total.configure(text=str(n))
        self._s_crit.configure( text=str(crit))
        self._s_high.configure( text=str(high))
        self._s_med.configure(  text=str(med))

# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    if platform.system()=='Linux':
        disp = os.environ.get('DISPLAY','')
        if not disp:
            print('[ERROR] DISPLAY not set.')
            print('  WSL2: export DISPLAY=$(ip route show default | awk \'{print $3}\'):0.0')
            sys.exit(1)
        print(f'[INFO] DISPLAY={disp}')

    root = tk.Tk()
    root.withdraw()
    App(root)
    root.deiconify()
    root.mainloop()

if __name__=='__main__':
    main()
