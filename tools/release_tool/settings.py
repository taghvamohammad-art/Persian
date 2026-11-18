"""Settings of the release tool, in %APPDATA%\\PersianVPNRelease\\settings.json.

The GitHub token is encrypted with Windows DPAPI (CryptProtectData): only
the same Windows user on the same computer can decrypt it.
"""

import base64
import json
import os
import sys

APP_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "PersianVPNRelease")
UNLOCK_FILE = os.path.join(APP_DIR, "unlock.json")
FILE = os.path.join(APP_DIR, "settings.json")
DEFAULT_REPO = "taghvamohammad-art/Persian"
DEFAULT_PUBLIC_REPO = "taghvamohammad-art/pv-config"
DEFAULT_BACKUP_REPO = "taghvamohammad-art/pv-backups"
STATUS_FILE = os.path.join(APP_DIR, "backup_status.json")
LOG_FILE = os.path.join(APP_DIR, "backup.log")
DEFAULT_WORKSPACES = [r"C:\vpnapp\open-sstp-client\tools"]


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


# Android (the phone version): there is no DPAPI; secrets are locked with a
# key derived from the app password the user types when the app opens.
MASTER_KEY = None


def _aes(raw, decrypt=False):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if decrypt:
        return AESGCM(MASTER_KEY).decrypt(raw[:12], raw[12:], b"pv-settings")
    nonce = os.urandom(12)
    return nonce + AESGCM(MASTER_KEY).encrypt(nonce, raw, b"pv-settings")


def _encrypt(text):
    if not text:
        return ""
    raw = text.encode()
    if MASTER_KEY:
        return "aes:" + base64.b64encode(_aes(raw)).decode()
    if sys.platform == "win32":
        return "dpapi:" + base64.b64encode(_dpapi(raw, True)).decode()
    return "plain:" + base64.b64encode(raw).decode()   # non-Windows (tests only)


def _decrypt(value):
    if not value:
        return ""
    kind, _, b64 = value.partition(":")
    raw = base64.b64decode(b64)
    if kind == "dpapi":
        return _dpapi(raw, False).decode()
    if kind == "aes":
        if not MASTER_KEY:
            raise ValueError("locked")
        return _aes(raw, decrypt=True).decode()
    return raw.decode()


ROUTER_FIELDS = ("id", "name", "role", "host", "port", "user", "password", "hostkey", "params")


class Settings:
    def __init__(self, workspace="", repo=DEFAULT_REPO, token="", public_repo=DEFAULT_PUBLIC_REPO):
        self.workspace = workspace
        self.repo = repo
        self.token = token
        self.public_repo = public_repo
        self.backup_repo = DEFAULT_BACKUP_REPO
        self.backup_password = ""
        self.auto_backup = False
        self.backup_hours = 6
        self.testers = []          # usernames that get test builds
        # [{"id", "name", "role": "main"|"secondary", "host", "port", "user", "password", "hostkey"}]
        self.routers = []

    @classmethod
    def load(cls):
        s = cls()
        try:
            with open(FILE, encoding="utf-8") as f:
                d = json.load(f)
            s.workspace = d.get("workspace", "")
            s.repo = d.get("repo", DEFAULT_REPO)
            s.public_repo = d.get("public_repo", DEFAULT_PUBLIC_REPO)
            s.token = _decrypt(d.get("token", ""))
            s.backup_repo = d.get("backup_repo", DEFAULT_BACKUP_REPO)
            s.backup_password = _decrypt(d.get("backup_password", ""))
            s.auto_backup = bool(d.get("auto_backup", False))
            s.backup_hours = int(d.get("backup_hours", 6))
            s.testers = [str(t) for t in d.get("testers", []) if str(t).strip()]
            for r in d.get("routers", []):
                r = {k: r.get(k, "") for k in ROUTER_FIELDS}
                r["password"] = _decrypt(r["password"])
                r["port"] = int(r["port"] or 22)
                r["role"] = r["role"] or "main"
                s.routers.append(r)
        except (OSError, ValueError):
            pass
        if not s.workspace:
            s.workspace = next((p for p in DEFAULT_WORKSPACES if os.path.isdir(p)), "")
        return s

    def router(self, rid):
        return next((r for r in self.routers if r["id"] == rid), None)

    def new_router_id(self):
        n = 1
        while self.router("r%d" % n):
            n += 1
        return "r%d" % n

    def backup_dir(self):
        return os.path.join(self.workspace or APP_DIR, "backups")

    def save(self):
        os.makedirs(APP_DIR, exist_ok=True)
        tmp = FILE + ".tmp"
        routers = [dict(r, password=_encrypt(r.get("password", ""))) for r in self.routers]
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"workspace": self.workspace, "repo": self.repo,
                       "public_repo": self.public_repo,
                       "token": _encrypt(self.token),
                       "backup_repo": self.backup_repo,
                       "backup_password": _encrypt(self.backup_password),
                       "auto_backup": self.auto_backup, "backup_hours": self.backup_hours,
                       "testers": self.testers,
                       "routers": routers}, f, ensure_ascii=False, indent=2)
        os.replace(tmp, FILE)


def load_status():
    try:
        with open(STATUS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_status(status):
    os.makedirs(APP_DIR, exist_ok=True)
    with open(STATUS_FILE + ".tmp", "w", encoding="utf-8") as f:
        json.dump(status, f, ensure_ascii=False, indent=1)
    os.replace(STATUS_FILE + ".tmp", STATUS_FILE)


def encrypt_blob(obj):
    """A dict with secrets (a Linux server's keys) stored like passwords."""
    return _encrypt(json.dumps(obj)) if obj else ""


def decrypt_blob(value):
    try:
        return json.loads(_decrypt(value)) if value else None
    except (ValueError, OSError):
        return None


# ---------------------------------------------------------------- app password (phone)

def has_app_password():
    return os.path.isfile(UNLOCK_FILE)


def _derive(password, salt):
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(password.encode("utf-8"))


def set_app_password(password):
    """A new app password: the settings are written again locked with it."""
    global MASTER_KEY
    salt = os.urandom(16)
    key = _derive(password, salt)
    old, MASTER_KEY = MASTER_KEY, key
    check = _aes(b"pv-unlock-ok")
    os.makedirs(APP_DIR, exist_ok=True)
    with open(UNLOCK_FILE + ".tmp", "w") as f:
        json.dump({"salt": base64.b64encode(salt).decode(), "check": base64.b64encode(check).decode()}, f)
    os.replace(UNLOCK_FILE + ".tmp", UNLOCK_FILE)
    return old


def unlock(password):
    """True and the key set when the password is right."""
    global MASTER_KEY
    try:
        with open(UNLOCK_FILE) as f:
            d = json.load(f)
        key = _derive(password, base64.b64decode(d["salt"]))
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        raw = base64.b64decode(d["check"])
        if AESGCM(key).decrypt(raw[:12], raw[12:], b"pv-settings") != b"pv-unlock-ok":
            return False
    except Exception:
        return False
    MASTER_KEY = key
    return True
