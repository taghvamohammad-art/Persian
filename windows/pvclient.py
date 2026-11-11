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
from PySide6.QtWidgets import (QApplication, QCheckBox, QFrame, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QPushButton, QStackedWidget, QSystemTrayIcon, QMenu,
                               QVBoxLayout, QWidget)

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


def fetch_update(cfg, progress):
    """Downloads the Windows build named in the signed config; path or None."""
    upd = cfg.get("windows_update") or {}
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
    subprocess.Popen([me], close_fds=True)
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
"""


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
        upd = self.config.cfg.get("windows_update") or {}
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
        self.l_account = QLabel("…")
        self.l_account.setWordWrap(True)
        cl.addWidget(self.l_account)
        lay.addWidget(card)
        self.auto = QCheckBox("بعد از باز شدن برنامه خودکار وصل شود")
        self.auto.setChecked(bool(self.state.get("auto")))
        self.auto.toggled.connect(lambda v: self.set_state(auto=v))
        lay.addWidget(self.auto)
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
        lines = ["وضعیت: %s" % state]
        if cur:
            if cur.get("remaining_bytes") is not None or cur.get("limit_bytes") is None:
                lines.append("حجم باقی‌مانده: %s" % gib(cur.get("remaining_bytes")))
            if cur.get("days_left") is not None:
                lines.append("روزهای باقی‌مانده: %d" % cur["days_left"])
        self.l_account.setText("\n".join(lines))

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
        if not (self.config.cfg.get("linux_servers") or self.config.cfg.get("servers")):
            QMessageBox.warning(self, APP_NAME, "سروری برای این نسخه تعریف نشده است.")
            return
        user, pw = self.creds()
        self.wanted = True
        self.set_look("busy", "در حال آماده‌سازی…")
        raw = self.config.raw

        def job():
            problem = ensure_service(raw)
            if problem is None:
                try:
                    r = service("connect", timeout=15, envelope=raw, user=user, **{"pass": pw})
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

    def offer_update(self, upd):
        if QMessageBox.question(self, APP_NAME, "نسخه‌ی جدید برنامه آماده است (%s).\nالان به‌روز شود؟\n\n%s"
                                % (upd.get("version_name", upd.get("version_code")), upd.get("notes", ""))) \
                != QMessageBox.Yes:
            return
        self.set_look("busy", "در حال دریافت نسخه‌ی جدید…")
        cfg = self.config.cfg

        def job():
            path = fetch_update(cfg, lambda pct: None)
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
    app.setStyleSheet(STYLE)
    icon = os.path.join(HERE, "icon-512.png")
    if os.path.isfile(icon):
        app.setWindowIcon(QIcon(icon))
    app.setQuitOnLastWindowClosed(False)
    w = Window()
    w.show()
    if "--smoke" in sys.argv:          # CI: the window builds with the bundled config
        app.processEvents()
        print("smoke ok, config version", w.config.cfg.get("version"))
        sys.exit(0)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
