"""Persian VPN for Windows.

The window: sign in with the User Manager username and password, connect,
see the remaining volume and days. The tunnel itself is pvwin.exe (Go:
Xray with a Wintun adapter, every working protocol of the Linux servers
at once, the fastest picked continuously); this app starts it, shows its
events and stops it. Needs administrator rights (the adapter, routes and
leak filters), asked for when the app starts.

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
import tempfile
import threading
import urllib.parse
import urllib.request

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (QApplication, QCheckBox, QFrame, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QPushButton, QStackedWidget, QSystemTrayIcon, QMenu,
                               QVBoxLayout, QWidget)

APP_NAME = "Persian VPN"
VERSION = "1.0"
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
        self.cfg = verify(bundled("app_config.signed.json"), self.pub)
        if self.cfg is None:
            raise SystemExit("built-in config is not signed with the built-in key")
        try:
            with open(CONFIG_CACHE, encoding="utf-8") as f:
                cached = verify(f.read(), self.pub)
            if cached and cached.get("version", 0) > self.cfg.get("version", 0):
                self.cfg = cached
        except OSError:
            pass

    def install(self, text):
        cfg = verify(text, self.pub)
        if not cfg or cfg.get("version", 0) <= self.cfg.get("version", 0):
            return False
        os.makedirs(DATA, exist_ok=True)
        with open(CONFIG_CACHE, "w", encoding="utf-8") as f:
            f.write(decode_public(text))
        self.cfg = cfg
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


# ---------------------------------------------------------------- engine

class Engine(QObject):
    event = Signal(dict)

    def __init__(self):
        super().__init__()
        self.proc = None

    def start(self, servers, user, password):
        self.stop()
        fd, path = tempfile.mkstemp(suffix=".json", prefix="pv-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(servers, f)
        env = dict(os.environ, PV_PASS=password)
        flags = 0x08000000 if sys.platform == "win32" else 0      # no console window
        self.proc = subprocess.Popen([os.path.join(HERE, "pvwin.exe"), "-servers", path, "-user", user],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     env=env, creationflags=flags, cwd=HERE)
        proc = self.proc

        def read():
            for line in proc.stdout:
                try:
                    self.event.emit(json.loads(line))
                except ValueError:
                    pass
            try:
                os.remove(path)
            except OSError:
                pass
            if proc is self.proc:
                self.event.emit({"event": "exited"})
        threading.Thread(target=read, daemon=True).start()

    def stop(self):
        p, self.proc = self.proc, None
        if p and p.poll() is None:
            try:
                p.stdin.close()            # pvwin stops cleanly (routes, filters) on this
                p.wait(10)
            except (OSError, subprocess.TimeoutExpired):
                p.kill()


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
        self.engine = Engine()
        self.engine.event.connect(self.on_event)
        self.status_ready.connect(self.show_status)
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
        threading.Thread(target=self.config.refresh, daemon=True).start()

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

    # VPN
    def toggle(self):
        if self.wanted:
            self.disconnect_vpn()
        else:
            self.connect_vpn()

    def connect_vpn(self):
        servers = self.config.cfg.get("linux_servers") or []
        if not servers:
            QMessageBox.warning(self, APP_NAME, "سروری برای این نسخه تعریف نشده است.")
            return
        user, pw = self.creds()
        self.wanted = True
        self.set_look("busy", "در حال انتخاب بهترین سرور…")
        self.engine.start(servers, user, pw)

    def disconnect_vpn(self):
        self.wanted = False
        self.connected = False
        self.engine.stop()
        self.set_look("off", "قطع")

    def on_event(self, ev):
        e = ev.get("event")
        if not self.wanted:
            return
        if e == "probing":
            self.set_look("busy", "در حال انتخاب بهترین سرور…")
        elif e == "connected":
            self.connected = True
            self.set_look("on", "متصل")
            self.refresh_account()
        elif e == "retry":
            self.connected = False
            self.set_look("busy", "در حال اتصال دوباره…")
        elif e in ("exited", "error"):
            self.connected = False
            self.wanted = False
            self.set_look("off", "اتصال برقرار نشد. برنامه باید با دسترسی Administrator اجرا شود."
                          if e == "exited" else "اتصال برقرار نشد.")

    def set_look(self, state, text):
        self.big.setProperty("state", state)
        self.big.setText({"on": "قطع", "busy": "لغو", "off": "اتصال"}[state])
        self.big.style().unpolish(self.big)
        self.big.style().polish(self.big)
        self.l_state.setText(text)
        self.tray.setToolTip("%s — %s" % (APP_NAME, text)) if hasattr(self, "tray") else None

    def closeEvent(self, e):
        if self.wanted and self.tray.isVisible():
            e.ignore()
            self.hide()
            self.tray.showMessage(APP_NAME, "برنامه در کنار ساعت ویندوز فعال است.")
        else:
            self.quit()

    def quit(self):
        self.engine.stop()
        QApplication.quit()


def main():
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
        w.engine.stop()
        print("smoke ok, config version", w.config.cfg.get("version"))
        sys.exit(0)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
