"""Settings of the release tool, in %APPDATA%\\PersianVPNRelease\\settings.json.

The GitHub token is encrypted with Windows DPAPI (CryptProtectData): only
the same Windows user on the same computer can decrypt it.
"""

import base64
import json
import os
import sys

APP_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "PersianVPNRelease")
FILE = os.path.join(APP_DIR, "settings.json")
DEFAULT_REPO = "taghvamohammad-art/Persian"
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


def _encrypt(text):
    if not text:
        return ""
    raw = text.encode()
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
    return raw.decode()


class Settings:
    def __init__(self, workspace="", repo=DEFAULT_REPO, token=""):
        self.workspace = workspace
        self.repo = repo
        self.token = token

    @classmethod
    def load(cls):
        s = cls()
        try:
            with open(FILE, encoding="utf-8") as f:
                d = json.load(f)
            s.workspace = d.get("workspace", "")
            s.repo = d.get("repo", DEFAULT_REPO)
            s.token = _decrypt(d.get("token", ""))
        except (OSError, ValueError):
            pass
        if not s.workspace:
            s.workspace = next((p for p in DEFAULT_WORKSPACES if os.path.isdir(p)), "")
        return s

    def save(self):
        os.makedirs(APP_DIR, exist_ok=True)
        tmp = FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"workspace": self.workspace, "repo": self.repo,
                       "token": _encrypt(self.token)}, f, ensure_ascii=False, indent=2)
        os.replace(tmp, FILE)
