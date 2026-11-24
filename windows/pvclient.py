"""Persian VPN for Windows.

The window: sign in with the User Manager username and password, connect,
see the remaining volume and days. The tunnel itself is pvwin.exe (Go:
Xray or AmneziaWG on a Wintun adapter, every working protocol of the
Linux servers, the fastest picked continuously), a Windows service this
app installs once (the only time administrator rights are asked for) and
then talks to on a local port. Updates come from the signed config: the
app replaces itself and hands the service its new engine.

Server settings come from the same signed config as the Android app: the
copy built in, replaced by a newer validly signed one from the config URLs.
"""

import base64
import hashlib
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (QApplication, QCheckBox, QDialog, QFileDialog, QFrame, QHBoxLayout,
                               QLabel, QLineEdit, QListWidget, QListWidgetItem, QMessageBox,
                               QPlainTextEdit, QProgressBar, QPushButton, QStackedWidget,
                               QSystemTrayIcon, QMenu, QVBoxLayout, QWidget)

APP_NAME = "Persian VPN"
try:
    from _build import BUILD            # the GitHub build number, written when building
except ImportError:
    BUILD = 0
SERVICE = ("127.0.0.1", 47811)
HERE = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "PersianVPN")
STATE = os.path.join(DATA, "state.json")
CONFIG_CACHE = os.path.join(DATA, "config.signed.json")
PVC_KEY = bytes.fromhex("76eb86bc2d0bea3f596d86ce523e008f442ef27675478a7f61719792ef083d02")


# ---------------------------------------------------------------- storage

def _dpapi(data, protect):
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    inp = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = BLOB()
    fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    if not fn(ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)):
        raise OSError("DPAPI failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def seal(text):
    raw = text.encode()
    if sys.platform == "win32":
        return "dpapi:" + base64.b64encode(_dpapi(raw, True)).decode()
    return "plain:" + base64.b64encode(raw).decode()


def unseal(value):
    kind, _, b64 = (value or "").partition(":")
    if not b64:
        return ""
    raw = base64.b64decode(b64)
    return (_dpapi(raw, False) if kind == "dpapi" else raw).decode()


def load_state():
    try:
        with open(STATE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(st):
    os.makedirs(DATA, exist_ok=True)
    with open(STATE + ".tmp", "w", encoding="utf-8") as f:
        json.dump(st, f)
    os.replace(STATE + ".tmp", STATE)


# ---------------------------------------------------------------- signed config

def decode_public(text):
    """The public mirror's encoding (PVC1:), as in the Android app."""
    t = text.strip()
    if not t.startswith("PVC1:"):
        return t
    raw = base64.b64decode(t[5:])
    nonce, body, out = raw[:16], raw[16:], bytearray()
    for block in range((len(body) + 31) // 32):
        ks = hashlib.sha256(PVC_KEY + nonce + block.to_bytes(4, "big")).digest()
        chunk = body[block * 32:block * 32 + 32]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return out.decode()


def verify(envelope_text, pub_b64):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        env = json.loads(decode_public(envelope_text))
        payload, sig = base64.b64decode(env["payload"]), base64.b64decode(env["sig"])
        key = serialization.load_der_public_key(base64.b64decode(pub_b64.strip()))
        key.verify(sig, payload, ec.ECDSA(hashes.SHA256()))
        return json.loads(payload)
    except (ValueError, KeyError, InvalidSignature):
        return None


def bundled(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return f.read()


class Config:
    def __init__(self):
        self.pub = bundled("config_key.public.txt")
        self.raw = bundled("app_config.signed.json")       # the signed envelope, for the service
        self.cfg = verify(self.raw, self.pub)
        if self.cfg is None:
            raise SystemExit("built-in config is not signed with the built-in key")
        try:
            with open(CONFIG_CACHE, encoding="utf-8") as f:
                text = f.read()
            cached = verify(text, self.pub)
            if cached and cached.get("version", 0) > self.cfg.get("version", 0):
                self.cfg, self.raw = cached, text
        except OSError:
            pass

    def install(self, text):
        cfg = verify(text, self.pub)
        if not cfg or cfg.get("version", 0) <= self.cfg.get("version", 0):
            return False
        os.makedirs(DATA, exist_ok=True)
        plain = decode_public(text)
        with open(CONFIG_CACHE, "w", encoding="utf-8") as f:
            f.write(plain)
        self.cfg, self.raw = cfg, plain
        return True

    def refresh(self):
        for url in self.cfg.get("config_urls", []):
            try:
                if self.install(https(url, self.cfg.get("config_pins", []), any_cert=True).decode()):
                    return True
            except OSError:
                continue
        return False


def https(url, pins, body=None, any_cert=False, timeout=15):
    """GET/POST with the certificate checked against the config's pins."""
    pins = {p.replace(":", "").lower() for p in pins}
    u = urllib.parse.urlsplit(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((u.hostname, u.port or 443), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=u.hostname) as s:
            der = s.getpeercert(binary_form=True)
            if pins and hashlib.sha256(der).hexdigest() not in pins:
                raise OSError("certificate pin mismatch")
            if not pins and not any_cert:
                raise OSError("no pins")
            path = u.path + ("?" + u.query if u.query else "")
            head = "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n" % ("POST" if body else "GET", path, u.hostname)
            if body:
                head += "Content-Type: application/json\r\nContent-Length: %d\r\n" % len(body)
            s.sendall(head.encode() + b"\r\n" + (body or b""))
            data = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    status = int(head.split()[1])
    if b"chunked" in head.lower():
        out, rest_ = b"", rest
        while rest_:
            size_line, _, rest_ = rest_.partition(b"\r\n")
            n = int(size_line.split(b";")[0], 16)
            if n == 0:
                break
            out += rest_[:n]
            rest_ = rest_[n + 2:]
        rest = out
    if status >= 400:
        err = OSError("HTTP %d" % status)
        err.status = status
        raise err
    return rest


def account_status(cfg, user, password):
    body = json.dumps({"username": user, "password": password}).encode()
    last = None
    for url in cfg.get("status_urls", []):
        try:
            return json.loads(https(url, cfg.get("status_pins", []), body, timeout=40))
        except OSError as e:
            last = e
            if getattr(e, "status", 0) in (401, 429):
                raise
    raise last or OSError("no status server")


def gib(n):
    return "%.1f GB" % (n / 1024 ** 3) if n is not None else "نامحدود"


# ---------------------------------------------------------------- service

def service(cmd, timeout=6, **kw):
    """One request to the pvwin service; OSError when it is not there."""
    with socket.create_connection(SERVICE, timeout=timeout) as c:
        c.sendall(json.dumps(dict(kw, cmd=cmd)).encode() + b"\n")
        f = c.makefile("rb")
        line = f.readline()
    if not line:
        raise OSError("service closed the connection")
    return json.loads(line)


def service_version():
    try:
        return int(service("status").get("version", 0))
    except (OSError, ValueError):
        return None


def install_service():
    """Runs "pvwin install" with administrator rights (one Windows prompt)."""
    import ctypes
    exe = os.path.join(HERE, "pvwin.exe")
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, "install", HERE, 0) > 32


def ensure_service(raw_envelope, wait=time.sleep):
    """The service running, at this app's version or newer. Returns None when
    fine, or a message for the user."""
    have = service_version()
    if have is not None and have >= BUILD:
        return None
    if have is not None:
        # an older engine takes the newer one itself when the signed config names it
        try:
            service("upgrade", envelope=raw_envelope, path=os.path.join(HERE, "pvwin.exe"))
        except OSError:
            pass
        for _ in range(20):
            wait(0.5)
            v = service_version()
            if v is not None and v >= BUILD:
                return None
    if sys.platform != "win32":
        return "service not available"
    if not install_service():
        return "برای نصب سرویس VPN باید یک بار اجازه‌ی Administrator بدهید."
    for _ in range(60):
        wait(0.5)
        v = service_version()
        if v is not None and v >= BUILD:
            return None
    return "سرویس VPN نصب نشد. برنامه را یک بار با «Run as administrator» باز کنید."


# ---------------------------------------------------------------- updates

def download(url, pins, dest, size, progress):
    """A big file over HTTPS with the config's pins (its hash is checked by the caller)."""
    pins = {p.replace(":", "").lower() for p in pins}
    u = urllib.parse.urlsplit(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((u.hostname, u.port or 443), timeout=20) as raw:
        with ctx.wrap_socket(raw, server_hostname=u.hostname) as s:
            if pins and hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest() not in pins:
                raise OSError("certificate pin mismatch")
            s.sendall(("GET %s HTTP/1.0\r\nHost: %s\r\n\r\n" % (u.path, u.hostname)).encode())
            f = s.makefile("rb")
            status = f.readline().split()
            if len(status) < 2 or status[1] != b"200":
                raise OSError("HTTP %s" % (status[1].decode() if len(status) > 1 else "?"))
            while f.readline() not in (b"\r\n", b"\n", b""):
                pass
            got, h = 0, hashlib.sha256()
            with open(dest, "wb") as out:
                while True:
                    chunk = f.read(256 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
                    h.update(chunk)
                    got += len(chunk)
                    if got > size:
                        raise OSError("too big")
                    progress(int(got * 100 / size) if size else 0)
    return h.hexdigest()


def tester_hash(username):
    return hashlib.sha256(("pv-tester\n" + username.strip().lower()).encode()).hexdigest()[:16]


def update_for(cfg, username):
    """The Windows build for this user: the test build for testers when it is
    newer than the public one, else the public one ({} when none)."""
    pub = cfg.get("windows_update") or {}
    beta = cfg.get("windows_update_beta") or {}
    if beta and username and tester_hash(username) in beta.get("testers", []) and \
            int(beta.get("version_code", 0)) > int(pub.get("version_code", 0)):
        return beta
    return pub


def update_required(cfg, build):
    """«آپدیت اجباری»: the owner stopped versions below min_version_code."""
    pub = cfg.get("windows_update") or {}
    return build < int(pub.get("min_version_code", 0)) and int(pub.get("version_code", 0)) > build \
        and bool(pub.get("urls"))


def fetch_update(cfg, progress, upd=None):
    """Downloads the Windows build named in the signed config; path or None."""
    upd = upd if upd is not None else (cfg.get("windows_update") or {})
    os.makedirs(DATA, exist_ok=True)
    dest = os.path.join(DATA, "PersianVPN-new.exe")
    for url in upd.get("urls", []):
        try:
            if download(url, cfg.get("config_pins", []), dest, int(upd["size"]), progress) == upd["sha256"].lower():
                return dest
        except (OSError, KeyError, ValueError):
            continue
    try:
        os.remove(dest)
    except OSError:
        pass
    return None


def replace_self(new):
    """Puts the downloaded exe in place of the running one and starts it."""
    me = sys.executable
    old = me + ".old"
    try:
        if os.path.exists(old):
            os.remove(old)
        os.rename(me, old)              # Windows lets a running program be renamed
        os.replace(new, me)
    except OSError:
        if not os.path.exists(me) and os.path.exists(old):
            os.rename(old, me)
        return False
    # PYINSTALLER_RESET_ENVIRONMENT: the new .exe must unpack itself, not reuse
    # this process's folder (deleted when this one closes)
    subprocess.Popen([me], close_fds=True, env=dict(os.environ, PYINSTALLER_RESET_ENVIRONMENT="1"))
    return True


# ---------------------------------------------------------------- window

STYLE = """
QWidget { color: #FFFFFF; font-size: 11pt; font-family: Tahoma; }
#Root { background: qlineargradient(x1:0, y1:0, x2:0.6, y2:1, stop:0 #0A2540, stop:1 #0B5563); }
#Card { background: rgba(255,255,255,0.07); border: 1px solid rgba(255,255,255,0.16); border-radius: 18px; }
#Title { font-size: 18pt; font-weight: bold; }
#Hint { color: rgba(255,255,255,0.65); font-size: 10pt; }
QLineEdit { background: rgba(255,255,255,0.07); border: 1px solid rgba(255,255,255,0.22);
            border-radius: 10px; padding: 8px 10px; }
QLineEdit:focus { border-color: #2EE6C5; }
QPushButton { background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.22);
              border-radius: 16px; padding: 8px 18px; }
QPushButton:hover { background: rgba(255,255,255,0.14); }
#Primary { background: #2EE6C5; color: #04211C; border: none; font-weight: bold; font-size: 12pt;
           border-radius: 22px; padding: 11px; }
#Big { border-radius: 80px; min-width: 160px; max-width: 160px; min-height: 160px; max-height: 160px;
       font-size: 15pt; font-weight: bold; border: 4px solid #2EE6C5; background: rgba(46,230,197,0.08); }
#Big[state="on"] { background: #2EE6C5; color: #04211C; }
#Big[state="busy"] { border-color: #F5C451; }
#Profile { font-size: 13pt; font-weight: bold; color: #2EE6C5; }
QProgressBar { background: rgba(255,255,255,0.10); border: none; border-radius: 4px; max-height: 8px; }
QProgressBar::chunk { background: #2EE6C5; border-radius: 4px; }
QProgressBar[low="true"]::chunk { background: #F5C451; }
QListWidget { background: #0B2F45; border: 1px solid rgba(255,255,255,0.18); border-radius: 10px; }
QDialog, QMessageBox, QInputDialog { background: #0B2F45; }
QMessageBox QLabel { color: #FFFFFF; min-width: 260px; }
QMessageBox QPushButton { min-width: 80px; }
#Link { background: transparent; border: none; color: #2EE6C5; padding: 2px 6px; }
QListWidget::item { padding: 6px; }
QListWidget::item:selected { background: rgba(46,230,197,0.25); color: #FFFFFF; }
QCheckBox::indicator { width: 18px; height: 18px; }
QHeaderView { background: #0E3A52; border: none; }
QHeaderView::section { background: #0E3A52; color: #E6F4F1; border: none;
    border-bottom: 1px solid rgba(255,255,255,0.16); padding: 6px; font-weight: bold; }
QTableCornerButton::section { background: #0E3A52; border: none; }
QScrollBar:horizontal, QScrollBar:vertical { background: transparent; border: none; margin: 0; }
QScrollBar:horizontal { height: 10px; }
QScrollBar:vertical { width: 10px; }
QScrollBar::handle { background: rgba(255,255,255,0.28); border-radius: 5px; min-width: 30px; min-height: 30px; }
QScrollBar::handle:hover { background: rgba(46,230,197,0.6); }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; border: none; background: none; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }
QMenu { background: #0E3A52; border: 1px solid rgba(255,255,255,0.18); padding: 4px; }
QMenu::item { padding: 6px 18px; border-radius: 6px; }
QMenu::item:selected { background: #00A58E; }
QToolTip { background: #12324A; color: #FFFFFF; border: 1px solid rgba(255,255,255,0.2); }
"""


def dark_palette(app):
    """Fusion with a dark palette: Windows' own style (light mode) painted table
    headers, scroll bars, menus and some dialogs white under our white text."""
    from PySide6.QtGui import QColor, QPalette
    app.setStyle("Fusion")
    p = QPalette()
    for role, color in ((QPalette.Window, "#0B2F45"), (QPalette.WindowText, "#FFFFFF"),
                        (QPalette.Base, "#0E3A52"), (QPalette.AlternateBase, "#12445F"),
                        (QPalette.Text, "#FFFFFF"), (QPalette.Button, "#12445F"),
                        (QPalette.ButtonText, "#FFFFFF"), (QPalette.ToolTipBase, "#12324A"),
                        (QPalette.ToolTipText, "#FFFFFF"), (QPalette.Highlight, "#00A58E"),
                        (QPalette.HighlightedText, "#FFFFFF"), (QPalette.PlaceholderText, "#8FB3C4"),
                        (QPalette.Link, "#2EE6C5")):
        p.setColor(role, QColor(color))
    p.setColor(QPalette.Disabled, QPalette.Text, QColor("#7F9BAA"))
    p.setColor(QPalette.Disabled, QPalette.ButtonText, QColor("#7F9BAA"))
    p.setColor(QPalette.Disabled, QPalette.WindowText, QColor("#7F9BAA"))
    app.setPalette(p)


# ---------------------------------------------------------------- programs outside the VPN

SYSTEM_PROCESSES = {
    "system", "system idle process", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "winlogon.exe", "fontdrvhost.exe", "dwm.exe", "memory compression",
    "conhost.exe", "sihost.exe", "taskhostw.exe", "runtimebroker.exe", "ctfmon.exe", "dllhost.exe",
    "searchindexer.exe", "spoolsv.exe", "wmiprvse.exe", "audiodg.exe", "lsaiso.exe", "secure system",
    "pvwin.exe", "tasklist.exe", "smartscreen.exe", "securityhealthservice.exe", "msmpeng.exe",
}


def running_programs():
    """File names of the programs running now (for picking), without Windows' own."""
    try:
        out = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True, timeout=15,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    names = {}
    for line in out.decode("mbcs" if os.name == "nt" else "utf-8", "replace").splitlines():
        name = line.split('","', 1)[0].strip('"')
        if name.lower().endswith(".exe") and name.lower() not in SYSTEM_PROCESSES:
            names.setdefault(name.lower(), name)
    me = os.path.basename(sys.executable).lower()
    return sorted((n for k, n in names.items() if k != me), key=str.lower)


def clean_bypass(names):
    """Plain program file names, each once (case kept: Windows reports it as on disk)."""
    out, seen = [], set()
    for n in names:
        n = os.path.basename(str(n).replace("\\", "/").strip())
        if n and n.lower().endswith(".exe") and n.lower() not in seen:
            seen.add(n.lower())
            out.append(n)
    return out


class BypassDialog(QDialog):
    """Programs whose traffic goes outside the VPN (e.g. Chrome through the VPN,
    Firefox not). Ticked = outside."""

    def __init__(self, parent, chosen):
        super().__init__(parent)
        self.setWindowTitle("برنامه‌های خارج از VPN")
        self.setLayoutDirection(Qt.RightToLeft)
        self.resize(380, 520)
        lay = QVBoxLayout(self)
        hint = QLabel("برنامه‌هایی که تیک بخورند مستقیم به اینترنت وصل می‌شوند و از VPN رد نمی‌شوند. "
                      "بقیه‌ی برنامه‌ها از VPN استفاده می‌کنند.")
        hint.setWordWrap(True)
        hint.setObjectName("Hint")
        lay.addWidget(hint)
        self.search = QLineEdit()
        self.search.setPlaceholderText("جست‌وجو…")
        self.search.textChanged.connect(self.filter)
        lay.addWidget(self.search)
        self.list = QListWidget()
        self.list.setLayoutDirection(Qt.LeftToRight)
        lay.addWidget(self.list, 1)
        names = clean_bypass(list(chosen) + running_programs())
        chosen_l = {n.lower() for n in chosen}
        for n in sorted(names, key=lambda x: (x.lower() not in chosen_l, x.lower())):
            self.add(n, n.lower() in chosen_l)
        row = QHBoxLayout()
        add = QPushButton("افزودن فایل برنامه…")
        add.clicked.connect(self.add_file)
        row.addWidget(add)
        every = QPushButton("انتخاب همه")
        every.clicked.connect(lambda: [self.list.item(i).setCheckState(Qt.Checked)
                                       for i in range(self.list.count()) if not self.list.item(i).isHidden()])
        row.addWidget(every)
        clear = QPushButton("همه از VPN")
        clear.clicked.connect(lambda: [self.list.item(i).setCheckState(Qt.Unchecked)
                                       for i in range(self.list.count())])
        row.addWidget(clear)
        lay.addLayout(row)
        note = QLabel("وقتی برنامه‌ای در این فهرست باشد، اتصال فقط با پروتکل‌هایی برقرار می‌شود "
                      "که این امکان را دارند.")
        note.setWordWrap(True)
        note.setObjectName("Hint")
        lay.addWidget(note)
        ok = QPushButton("ذخیره")
        ok.setObjectName("Primary")
        ok.clicked.connect(self.accept)
        lay.addWidget(ok)

    def add(self, name, checked):
        for i in range(self.list.count()):
            if self.list.item(i).text().lower() == name.lower():
                self.list.item(i).setCheckState(Qt.Checked if checked else self.list.item(i).checkState())
                return
        it = QListWidgetItem(name)
        it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
        it.setCheckState(Qt.Checked if checked else Qt.Unchecked)
        self.list.insertItem(0, it) if checked else self.list.addItem(it)

    def add_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "انتخاب برنامه", os.environ.get("ProgramFiles", ""),
                                              "Programs (*.exe)")
        if path:
            self.add(os.path.basename(path), True)

    def filter(self, text):
        t = text.strip().lower()
        for i in range(self.list.count()):
            it = self.list.item(i)
            it.setHidden(bool(t) and t not in it.text().lower())

    def chosen(self):
        return clean_bypass(self.list.item(i).text() for i in range(self.list.count())
                            if self.list.item(i).checkState() == Qt.Checked)


def running_program_paths():
    """Full paths of the programs running now (the shield needs the file, not the name)."""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-Process | Where-Object Path | Select-Object -ExpandProperty Path -Unique"],
            capture_output=True, timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    win = os.environ.get("SystemRoot", r"C:\Windows").lower()
    me = os.path.abspath(sys.executable).lower()
    paths = {}
    for line in out.decode("mbcs" if os.name == "nt" else "utf-8", "replace").splitlines():
        p = line.strip()
        low = p.lower()
        if low.endswith(".exe") and not low.startswith(win) and low != me \
                and os.path.basename(low) not in SYSTEM_PROCESSES:
            paths.setdefault(low, p)
    return sorted(paths.values(), key=lambda x: os.path.basename(x).lower())


def clean_shield(paths):
    seen, out = set(), []
    for p in paths:
        p = (p or "").strip()
        if os.path.isabs(p) and p.lower().endswith(".exe") and p.lower() not in seen:
            seen.add(p.lower())
            out.append(p)
    return sorted(out, key=lambda x: os.path.basename(x).lower())


PROTOCOL_LABELS = {"vless-reality-vision": "Reality", "vless-xhttp-reality": "XHTTP", "hysteria2": "Hysteria2",
                   "shadowsocks-2022": "Shadowsocks", "amneziawg": "AmneziaWG", "vless-xhttp-cdn": "CDN",
                   "vless-dns": "DNS"}


def _size(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024


def format_diag(d, user=""):
    """The test report (text, the same sections as the Android app's)."""
    import platform
    out = ["Persian VPN Windows %s · engine %s · %s" % (BUILD, d.get("version", "?"), platform.platform()),
           "user: %s · %s" % (user, time.strftime("%Y-%m-%d %H:%M:%S")),
           "VPN: %s · %s" % (d.get("state", "?"), "، ".join(d.get("protocols") or []) or "-")]
    if d.get("error"):
        out.append("آخرین خطا: %s" % d["error"])
    out += ["", "② داخل تانل (همان راهی که برنامه‌ها می‌روند)"]
    e = d.get("engine") or {}
    out.append("  engine: %s" % (e.get("running") or "-"))
    if e.get("error"):
        out.append("  ✗ %s" % e["error"])
    a = e.get("awg")
    if a:
        age = a.get("handshake_age_s", -1)
        out.append("  ✓ AmneziaWG handshake %ss پیش" % age if 0 <= age <= 175
                   else "  ✗ AmneziaWG handshake نشده یا قدیمی (%s)" % age)
        out.append("  ↓ %s  ↑ %s" % (_size(a.get("rx_bytes")), _size(a.get("tx_bytes"))))
        if a.get("port"):
            out.append("  پورت: %s" % a["port"])
        for line in a.get("roam") or []:
            out.append("    %s" % line)
    names = {"trace": "صفحه با IP (بدون DNS)", "name": "صفحه با اسم (DNS سمت سرور)",
             "dns_udp": "DNS روی UDP (مثل برنامه‌ها)", "download": "دانلود ۲ مگابایت"}
    steps = e.get("steps") or []
    for st in steps:
        ok = st.get("ok")
        detail = st.get("info", "") if ok else (st.get("error") or "")[:120]
        out.append("  %s %s %sms %s" % ("✓" if ok else "✗", names.get(st.get("name"), st.get("name")),
                                         st.get("ms", 0), detail))
    failed = {st.get("name") for st in steps if not st.get("ok")}
    if steps and not failed:
        out.append("  → تانل سالم است")
    elif {"trace", "name"} <= failed:
        out.append("  → خود پروتکل کار نمی‌کند (سرور یا فیلتر)")
    out += ["", "④ همه‌ی پروتکل‌ها (هر کدام جدا%s)" % ("؛ از داخل تانل فعلی" if d.get("state") == "connected" else "")]
    for p in d.get("probes") or []:
        out.append("  %s:" % p.get("name"))
        r = p.get("result") or {}
        errs = r.get("errors") or {}
        for k, v in sorted(r.items()):
            if k == "errors":
                continue
            label = PROTOCOL_LABELS.get(k, k)
            out.append("    ✓ %s %sms" % (label, v) if isinstance(v, (int, float)) and v >= 0
                       else "    ✗ %s %s" % (label, str(errs.get(k, ""))[:110]))
    if not d.get("probes"):
        out.append("  (اول وصل شوید)")
    out += ["", "⑥ گزارش اتصال (آخرین خط‌ها)"]
    out += ["  %s" % line for line in (d.get("log") or [])[-60:]]
    out += ["", "— پایان —"]
    return "\n".join(out)


class DiagDialog(QDialog):
    """«تست و عیب‌یابی»: the report to copy and send."""
    done = Signal(str)

    def __init__(self, parent, user):
        super().__init__(parent)
        self.setWindowTitle("🔍 تست و عیب‌یابی")
        self.setLayoutDirection(Qt.RightToLeft)
        self.resize(620, 640)
        lay = QVBoxLayout(self)
        hint = QLabel("تانل از داخل، همه‌ی پروتکل‌ها و گزارش اتصال تست می‌شود (حدود ۲۰ ثانیه). "
                      "بعد «کپی» را بزنید و متن را برای پشتیبانی بفرستید.")
        hint.setWordWrap(True)
        hint.setObjectName("Hint")
        lay.addWidget(hint)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setLayoutDirection(Qt.LeftToRight)
        self.text.setPlainText("در حال تست…")
        lay.addWidget(self.text, 1)
        row = QHBoxLayout()
        self.again = QPushButton("تست دوباره")
        self.again.clicked.connect(self.run)
        row.addWidget(self.again)
        copy = QPushButton("کپی")
        copy.clicked.connect(lambda: QApplication.clipboard().setText(self.text.toPlainText()))
        row.addWidget(copy)
        close = QPushButton("بستن")
        close.clicked.connect(self.accept)
        row.addWidget(close)
        lay.addLayout(row)
        self.user = user
        self.done.connect(self.text.setPlainText)
        self.done.connect(lambda _: self.again.setEnabled(True))
        self.run()

    def run(self):
        self.again.setEnabled(False)
        self.text.setPlainText("در حال تست…")

        def work():
            try:
                txt = format_diag(service("diag", timeout=90), self.user)
            except (OSError, ValueError) as e:
                txt = "سرویس VPN جواب نداد: %s\n(برنامه را یک بار ببندید و باز کنید)" % e
            self.done.emit(txt)
        threading.Thread(target=work, daemon=True).start()


class ShieldDialog(QDialog):
    """«سپر VPN»: programs that may use the internet only through the VPN.
    While the VPN is not connected, Windows Firewall blocks them."""

    def __init__(self, parent, chosen):
        super().__init__(parent)
        self.setWindowTitle("🛡 سپر VPN")
        self.setLayoutDirection(Qt.RightToLeft)
        self.resize(460, 540)
        lay = QVBoxLayout(self)
        hint = QLabel("برنامه‌هایی که تیک بخورند فقط از راه VPN اینترنت دارند. وقتی VPN وصل نیست "
                      "(قطع، در حال اتصال، یا بعد از روشن شدن کامپیوتر) هیچ اینترنتی ندارند. "
                      "بقیه‌ی برنامه‌ها مثل قبل کار می‌کنند.")
        hint.setWordWrap(True)
        hint.setObjectName("Hint")
        lay.addWidget(hint)
        self.search = QLineEdit()
        self.search.setPlaceholderText("جست‌وجو…")
        self.search.textChanged.connect(self.filter)
        lay.addWidget(self.search)
        self.list = QListWidget()
        self.list.setLayoutDirection(Qt.LeftToRight)
        lay.addWidget(self.list, 1)
        chosen_l = {p.lower() for p in chosen}
        for p in clean_shield(list(chosen) + running_program_paths()):
            self.add(p, p.lower() in chosen_l)
        row = QHBoxLayout()
        add = QPushButton("افزودن فایل برنامه…")
        add.clicked.connect(self.add_file)
        row.addWidget(add)
        every = QPushButton("انتخاب همه")
        every.clicked.connect(lambda: [self.list.item(i).setCheckState(Qt.Checked)
                                       for i in range(self.list.count()) if not self.list.item(i).isHidden()])
        row.addWidget(every)
        clear = QPushButton("هیچ‌کدام")
        clear.clicked.connect(lambda: [self.list.item(i).setCheckState(Qt.Unchecked)
                                       for i in range(self.list.count())])
        row.addWidget(clear)
        lay.addLayout(row)
        note = QLabel("دیوار آتش ویندوز (Windows Firewall) باید روشن باشد. برنامه‌ای که در «خارج از VPN» "
                      "است نمی‌تواند در سپر هم باشد.")
        note.setWordWrap(True)
        note.setObjectName("Hint")
        lay.addWidget(note)
        ok = QPushButton("ذخیره")
        ok.setObjectName("Primary")
        ok.clicked.connect(self.accept)
        lay.addWidget(ok)

    def add(self, path, checked):
        for i in range(self.list.count()):
            if self.list.item(i).data(Qt.UserRole).lower() == path.lower():
                if checked:
                    self.list.item(i).setCheckState(Qt.Checked)
                return
        it = QListWidgetItem("%s  —  %s" % (os.path.basename(path), os.path.dirname(path)))
        it.setData(Qt.UserRole, path)
        it.setToolTip(path)
        it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
        it.setCheckState(Qt.Checked if checked else Qt.Unchecked)
        self.list.insertItem(0, it) if checked else self.list.addItem(it)

    def add_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "انتخاب برنامه", os.environ.get("ProgramFiles", ""),
                                              "Programs (*.exe)")
        if path:
            self.add(os.path.normpath(path), True)

    def filter(self, text):
        t = text.strip().lower()
        for i in range(self.list.count()):
            it = self.list.item(i)
            it.setHidden(bool(t) and t not in it.data(Qt.UserRole).lower())

    def chosen(self):
        return clean_shield(self.list.item(i).data(Qt.UserRole) for i in range(self.list.count())
                            if self.list.item(i).checkState() == Qt.Checked)


class Window(QWidget):
    status_ready = Signal(object)

    def __init__(self):
        super().__init__()
        self.setObjectName("Root")
        self.setWindowTitle(APP_NAME)
        self.setLayoutDirection(Qt.RightToLeft)
        self.resize(380, 560)
        self.config = Config()
        self.state = load_state()
        self.status_ready.connect(self.show_status)
        self.poller = QTimer(self)
        self.poller.setInterval(2000)
        self.poller.timeout.connect(self.poll)
        self.connected = False
        self.wanted = False

        lay = QVBoxLayout(self)
        lay.setContentsMargins(22, 22, 22, 22)
        title = QLabel(APP_NAME)
        title.setObjectName("Title")
        title.setAlignment(Qt.AlignCenter)
        lay.addWidget(title)
        self.pages = QStackedWidget()
        lay.addWidget(self.pages, 1)
        self.pages.addWidget(self.login_page())
        self.pages.addWidget(self.main_page())
        if self.state.get("user") and self.state.get("pass"):
            self.enter()

        self.tray = QSystemTrayIcon(self.windowIcon(), self)
        menu = QMenu()
        menu.addAction("نمایش", self.showNormal)
        menu.addAction("خروج", self.quit)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(lambda *_: self.showNormal())
        self.tray.show()
        self.poller.start()
        threading.Thread(target=self.background_start, daemon=True).start()

    def background_start(self):
        """Newer signed config, then a newer Windows build if it names one."""
        self.config.refresh()
        upd = update_for(self.config.cfg, self.state.get("user", ""))
        if int(upd.get("version_code", 0)) > BUILD and getattr(sys, "frozen", False):
            self.status_ready.emit(("update", upd))

    # pages
    def login_page(self):
        w = QFrame()
        w.setObjectName("Card")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(20, 24, 20, 24)
        lay.setSpacing(12)
        lay.addWidget(QLabel("ورود به حساب"))
        self.e_user = QLineEdit()
        self.e_user.setPlaceholderText("نام کاربری")
        self.e_user.setLayoutDirection(Qt.LeftToRight)
        self.e_pass = QLineEdit()
        self.e_pass.setPlaceholderText("رمز عبور")
        self.e_pass.setEchoMode(QLineEdit.Password)
        self.e_pass.setLayoutDirection(Qt.LeftToRight)
        self.e_pass.returnPressed.connect(self.do_login)
        lay.addWidget(self.e_user)
        lay.addWidget(self.e_pass)
        b = QPushButton("ورود")
        b.setObjectName("Primary")
        b.clicked.connect(self.do_login)
        lay.addWidget(b)
        self.login_msg = QLabel("")
        self.login_msg.setObjectName("Hint")
        self.login_msg.setWordWrap(True)
        lay.addWidget(self.login_msg)
        lay.addStretch()
        return w

    def main_page(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(14)
        self.l_user = QLabel("")
        self.l_user.setAlignment(Qt.AlignCenter)
        self.l_user.setObjectName("Hint")
        lay.addWidget(self.l_user)
        row = QHBoxLayout()
        row.addStretch()
        self.big = QPushButton("اتصال")
        self.big.setObjectName("Big")
        self.big.clicked.connect(self.toggle)
        row.addWidget(self.big)
        row.addStretch()
        lay.addLayout(row)
        self.l_state = QLabel("قطع")
        self.l_state.setAlignment(Qt.AlignCenter)
        lay.addWidget(self.l_state)
        card = QFrame()
        card.setObjectName("Card")
        cl = QVBoxLayout(card)
        cl.setSpacing(6)
        top = QHBoxLayout()
        self.l_profile = QLabel("…")
        self.l_profile.setObjectName("Profile")
        self.l_profile.setWordWrap(True)
        top.addWidget(self.l_profile, 1)
        again = QPushButton("↻")
        again.setObjectName("Link")
        again.setToolTip("به‌روزرسانی")
        again.clicked.connect(self.refresh_account)
        top.addWidget(again)
        cl.addLayout(top)
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setRange(0, 1000)
        self.bar.hide()
        cl.addWidget(self.bar)
        self.l_account = QLabel("")
        self.l_account.setWordWrap(True)
        cl.addWidget(self.l_account)
        lay.addWidget(card)
        self.account_timer = QTimer(self)
        self.account_timer.setInterval(5 * 60 * 1000)        # used volume, while the app is open
        self.account_timer.timeout.connect(self.refresh_account)
        self.account_timer.start()
        self.b_bypass = QPushButton("")
        self.b_bypass.clicked.connect(self.edit_bypass)
        lay.addWidget(self.b_bypass)
        self.show_bypass()
        self.b_shield = QPushButton("")
        self.b_shield.clicked.connect(self.edit_shield)
        lay.addWidget(self.b_shield)
        self.show_shield()
        self.auto = QCheckBox("بعد از باز شدن برنامه خودکار وصل شود")
        self.auto.setChecked(bool(self.state.get("auto")))
        self.auto.toggled.connect(lambda v: self.set_state(auto=v))
        lay.addWidget(self.auto)
        diag = QPushButton("🔍 تست و عیب‌یابی")
        diag.clicked.connect(lambda: DiagDialog(self, self.creds()[0]).exec())
        lay.addWidget(diag)
        out = QPushButton("خروج از حساب")
        out.clicked.connect(self.logout)
        lay.addWidget(out)
        lay.addStretch()
        return w

    # account
    def set_state(self, **kw):
        self.state.update(kw)
        save_state(self.state)

    def creds(self):
        return self.state.get("user", ""), unseal(self.state.get("pass", ""))

    def do_login(self):
        user, pw = self.e_user.text().strip(), self.e_pass.text()
        if not user or not pw:
            return
        self.login_msg.setText("در حال بررسی…")

        def job():
            try:
                st = account_status(self.config.cfg, user, pw)
                self.status_ready.emit(("login", user, pw, st))
            except OSError as e:
                self.status_ready.emit(("login_error", getattr(e, "status", 0)))
        threading.Thread(target=job, daemon=True).start()

    def show_status(self, msg):
        kind = msg[0]
        if kind == "login":
            _, user, pw, st = msg
            self.set_state(user=user, **{"pass": seal(pw)})
            self.e_pass.clear()
            self.enter(st)
        elif kind == "login_error":
            self.login_msg.setText({401: "نام کاربری یا رمز اشتباه است.",
                                    429: "تلاش زیاد؛ چند دقیقه بعد دوباره امتحان کنید."}
                                   .get(msg[1], "سرور در دسترس نیست. اینترنت را بررسی کنید."))
        elif kind == "status":
            self.render_account(msg[1])
        elif kind == "engine":
            self.on_engine(msg[1])
        elif kind == "connect_failed":
            self.wanted = self.connected = False
            self.set_look("off", msg[1])
        elif kind == "update":
            self.offer_update(msg[1])
        elif kind == "update_ready":
            if msg[1] and replace_self(msg[1]):
                QApplication.quit()       # the new version starts and updates the service
            else:
                self.set_look("off", "دریافت نسخه‌ی جدید ناموفق بود.")

    def enter(self, st=None):
        self.pages.setCurrentIndex(1)
        self.l_user.setText(self.state.get("user", ""))
        if st:
            self.render_account(st)
        else:
            self.refresh_account()
        if self.state.get("auto"):
            QTimer.singleShot(500, self.connect_vpn)
        if self.shield():
            threading.Thread(target=self.sync_shield, daemon=True).start()

    def refresh_account(self):
        user, pw = self.creds()

        def job():
            try:
                self.status_ready.emit(("status", account_status(self.config.cfg, user, pw)))
            except OSError:
                pass
        threading.Thread(target=job, daemon=True).start()

    def render_account(self, st):
        cur = st.get("current") or {}
        state = {"active": "فعال", "volume_finished": "حجم تمام شده", "expired": "زمان تمام شده",
                 "waiting": "در انتظار شروع", "no_profile": "بدون اشتراک"}.get(st.get("state"), st.get("state", ""))
        self.l_profile.setText(cur.get("display") or cur.get("profile") or "بدون اشتراک فعال")
        lines = ["وضعیت: %s" % state]
        limit, used = cur.get("limit_bytes"), cur.get("used_bytes")
        if cur and limit:
            frac = min(1.0, (used or 0) / limit)
            self.bar.setValue(int(frac * 1000))
            self.bar.setProperty("low", frac > 0.85)
            self.bar.style().unpolish(self.bar)
            self.bar.style().polish(self.bar)
            self.bar.show()
            lines.append("مصرف: %s از %s" % (gib(used or 0), gib(limit)))
        else:
            self.bar.hide()
        if cur:
            if cur.get("remaining_bytes") is not None or limit is None:
                lines.append("حجم باقی‌مانده: %s" % gib(cur.get("remaining_bytes")))
            if cur.get("days_left") is not None:
                lines.append("روزهای باقی‌مانده: %d" % cur["days_left"])
            if cur.get("end"):
                lines.append("پایان: %s" % cur["end"][:16])
        for n in st.get("next") or []:
            what = n.get("display") or n.get("profile") or ""
            extra = []
            if n.get("limit_bytes"):
                extra.append(gib(n["limit_bytes"]))
            if n.get("validity_days"):
                extra.append("%d روز" % n["validity_days"])
            lines.append("بعدی: %s%s" % (what, " (%s)" % "، ".join(extra) if extra else ""))
        self.l_account.setText("\n".join(lines))

    # programs outside the VPN
    def bypass(self):
        return clean_bypass(self.state.get("bypass") or [])

    def show_bypass(self):
        n = len(self.bypass())
        self.b_bypass.setText("برنامه‌های خارج از VPN" + (" (%d)" % n if n else ""))

    def edit_bypass(self):
        d = BypassDialog(self, self.bypass())
        if d.exec() != QDialog.Accepted:
            return
        new = d.chosen()
        if new == self.bypass():
            return
        shielded = [p for p in self.shield() if os.path.basename(p).lower() in {n.lower() for n in new}]
        if shielded:
            QMessageBox.warning(self, APP_NAME, "این برنامه‌ها در «سپر VPN» هستند و نمی‌توانند خارج از VPN باشند:\n"
                                + "\n".join(os.path.basename(p) for p in shielded))
            new = [n for n in new if n.lower() not in {os.path.basename(p).lower() for p in shielded}]
        self.set_state(bypass=new)
        self.show_bypass()
        if self.wanted:
            self.connect_vpn()              # the service starts over with the new list

    # «سپر VPN»: programs only through the VPN (the service keeps the firewall rules)
    def shield(self):
        return clean_shield(self.state.get("shield") or [])

    def show_shield(self):
        n = len(self.shield())
        self.b_shield.setText("🛡 سپر VPN" + (" (%d)" % n if n else ""))

    def edit_shield(self):
        d = ShieldDialog(self, self.shield())
        if d.exec() != QDialog.Accepted:
            return
        new = d.chosen()
        names = {os.path.basename(p).lower() for p in new}
        bypass = [b for b in self.bypass() if b.lower() not in names]
        moved = len(bypass) != len(self.bypass())
        try:
            r = service("shield", timeout=20, programs=new)
            if not r.get("ok"):
                raise OSError(r.get("error") or "?")
        except OSError as e:
            QMessageBox.warning(self, APP_NAME, "سرویس VPN جواب نداد؛ سپر ذخیره نشد.\n%s" % e)
            return
        self.set_state(shield=new, bypass=bypass)
        self.show_shield()
        self.show_bypass()
        if moved:
            QMessageBox.information(self, APP_NAME, "برنامه‌هایی که در سپر گذاشتید از «خارج از VPN» برداشته شدند.")
            if self.wanted:
                self.connect_vpn()

    def sync_shield(self):
        """The service keeps its own copy; send ours once in case it was reinstalled."""
        try:
            r = service("status")
            if sorted(p.lower() for p in (r.get("shield") or [])) != sorted(p.lower() for p in self.shield()):
                service("shield", timeout=20, programs=self.shield())
        except OSError:
            pass

    def logout(self):
        self.disconnect_vpn()
        self.state.pop("pass", None)
        save_state(self.state)
        self.pages.setCurrentIndex(0)

    # VPN (the pvwin service does the work; this window asks and shows)
    def toggle(self):
        if self.wanted:
            self.disconnect_vpn()
        else:
            self.connect_vpn()

    def connect_vpn(self):
        if update_required(self.config.cfg, BUILD) and getattr(sys, "frozen", False):
            QMessageBox.warning(self, APP_NAME, "این نسخه دیگر وصل نمی‌شود؛ برای ادامه برنامه را به‌روز کنید.")
            self.offer_update(self.config.cfg.get("windows_update") or {}, required=True)
            return
        if not (self.config.cfg.get("linux_servers") or self.config.cfg.get("servers")):
            QMessageBox.warning(self, APP_NAME, "سروری برای این نسخه تعریف نشده است.")
            return
        user, pw = self.creds()
        bypass = self.bypass()
        self.wanted = True
        self.set_look("busy", "در حال آماده‌سازی…")
        raw = self.config.raw

        def job():
            problem = ensure_service(raw)
            if problem is None:
                try:
                    r = service("connect", timeout=15, envelope=raw, user=user, bypass=bypass,
                                **{"pass": pw})
                    problem = None if r.get("ok") else r.get("error", "خطا")
                except OSError as e:
                    problem = "سرویس VPN جواب نداد: %s" % e
            if problem:
                self.status_ready.emit(("connect_failed", problem))
        threading.Thread(target=job, daemon=True).start()

    def disconnect_vpn(self):
        self.wanted = False
        self.connected = False
        self.set_look("off", "قطع")
        threading.Thread(target=lambda: self.safe_service("disconnect"), daemon=True).start()

    @staticmethod
    def safe_service(cmd):
        try:
            return service(cmd)
        except OSError:
            return None

    def poll(self):
        def job():
            r = self.safe_service("status")
            if r is not None:
                self.status_ready.emit(("engine", r))
        threading.Thread(target=job, daemon=True).start()

    def on_engine(self, r):
        st = r.get("state", "off")
        if st == "connected":
            if not self.connected:
                self.connected = True
                self.refresh_account()
            self.wanted = True
            self.set_look("on", "متصل")
        elif st == "probing" and self.wanted:
            self.connected = False
            self.set_look("busy", "در حال انتخاب بهترین سرور…")
        elif st == "retry" and self.wanted:
            self.connected = False
            self.set_look("busy", "در حال اتصال دوباره…")
        elif st == "off" and self.wanted and self.l_state.text() != "در حال آماده‌سازی…":
            self.wanted = self.connected = False
            self.set_look("off", "قطع")

    def offer_update(self, upd, required=False):
        beta = "🧪 نسخه‌ی آزمایشی (فقط برای تست)\n" if upd.get("testers") else ""
        if not upd.get("testers") and update_required(self.config.cfg, BUILD):
            required = True
            beta = "⚠ به‌روزرسانی لازم است: این نسخه دیگر وصل نمی‌شود.\n"
        if QMessageBox.question(self, APP_NAME, "نسخه‌ی جدید برنامه آماده است (%s).\nالان به‌روز شود؟\n\n%s%s"
                                % (upd.get("version_name", upd.get("version_code")), beta, upd.get("notes", ""))) \
                != QMessageBox.Yes:
            return
        self.set_look("busy", "در حال دریافت نسخه‌ی جدید…")
        cfg = self.config.cfg

        def job():
            path = fetch_update(cfg, lambda pct: None, upd)
            self.status_ready.emit(("update_ready", path))
        threading.Thread(target=job, daemon=True).start()

    def set_look(self, state, text):
        self.big.setProperty("state", state)
        self.big.setText({"on": "قطع", "busy": "لغو", "off": "اتصال"}[state])
        self.big.style().unpolish(self.big)
        self.big.style().polish(self.big)
        self.l_state.setText(text)
        self.tray.setToolTip("%s — %s" % (APP_NAME, text)) if hasattr(self, "tray") else None

    def closeEvent(self, e):
        if self.tray.isVisible():
            e.ignore()
            self.hide()
            self.tray.showMessage(APP_NAME, "برنامه در کنار ساعت ویندوز فعال است.")
        else:
            self.quit()

    def quit(self):
        if self.wanted:
            self.safe_service("disconnect")
        QApplication.quit()


def main():
    if getattr(sys, "frozen", False):
        try:
            os.remove(sys.executable + ".old")       # left by the last update
        except OSError:
            pass
    app = QApplication(sys.argv)
    dark_palette(app)
    app.setStyleSheet(STYLE)
    icon = os.path.join(HERE, "icon-512.png")
    if os.path.isfile(icon):
        app.setWindowIcon(QIcon(icon))
    app.setQuitOnLastWindowClosed(False)
    w = Window()
    w.show()
    if "--smoke" in sys.argv:          # CI: the window builds with the bundled config
        app.processEvents()
        w.render_account({"state": "active", "current": {
            "display": "30G-1M", "limit_bytes": 30 * 1024 ** 3, "used_bytes": 27 * 1024 ** 3,
            "remaining_bytes": 3 * 1024 ** 3, "days_left": 20, "end": "2026-12-01 10:00:00"},
            "next": [{"display": "60G-1M", "limit_bytes": 60 * 1024 ** 3, "validity_days": 30}]})
        assert w.l_profile.text() == "30G-1M" and "بعدی" in w.l_account.text()
        d = BypassDialog(w, ["firefox.exe"])
        assert d.chosen() == ["firefox.exe"], d.chosen()
        shots = os.environ.get("PV_SHOTS")    # CI: pictures to look at the colours
        if shots:
            os.makedirs(shots, exist_ok=True)
            app.processEvents()
            w.grab().save(os.path.join(shots, "client-main.png"))
            d.show()
            app.processEvents()
            d.grab().save(os.path.join(shots, "client-bypass.png"))
        print("smoke ok, config version", w.config.cfg.get("version"))
        sys.exit(0)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
