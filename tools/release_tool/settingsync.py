"""Keeps the Windows tool and the phone app on the same settings.

One copy of the settings (servers, their keys and tokens, the workspace
files) lives on the main MikroTik, in pvsync/settings.enc, locked with the
backup password like the tool's own backups. It has a revision number:

  - before every job the tool reads it; a newer copy from the other device
    is taken in (when this device has changed nothing since the last sync),
  - every save on this device writes a new revision (in the background),
  - when both devices changed something since their last sync, nothing is
    overwritten silently: the user picks which copy stays.

The local sync state (last revision and a fingerprint of the settings at
that moment) is in sync_state.json next to settings.json.
"""

import datetime as _dt
import hashlib
import json
import os
import platform
import secrets
import sys
import threading
import time

import backup as bk
import settings as st
import toolbackup as tb
from publisher import ReleaseError

FORMAT = "pv-tool-sync"
REMOTE_DIR = "pvsync"
REMOTE_FILE = REMOTE_DIR + "/settings.enc"
PULL_EVERY = 90            # seconds: a job right after a sync does not check again

_lock = threading.RLock()
_last_pull = 0.0


class SyncConflict(ReleaseError):
    """Both devices changed the settings: the user decides."""

    def __init__(self, remote, summary):
        self.remote = remote
        self.summary = summary
        ReleaseError.__init__(self, "تنظیمات این دستگاه و دستگاه دیگر هر دو تغییر کرده‌اند.\n\n" + summary)


# ---------------------------------------------------------------- local state

def _state_file():
    return os.path.join(st.APP_DIR, "sync_state.json")


def load_state():
    try:
        with open(_state_file(), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state):
    os.makedirs(st.APP_DIR, exist_ok=True)
    path = _state_file()
    with open(path + ".tmp", "w", encoding="utf-8") as f:
        json.dump(state, f, indent=1)
    os.replace(path + ".tmp", path)


def device_id():
    state = load_state()
    if not state.get("device"):
        state["device"] = secrets.token_hex(6)
        save_state(state)
    return state["device"]


def device_name():
    if sys.platform == "win32":
        return "ویندوز (%s)" % (platform.node() or "?")
    return "گوشی"


# ---------------------------------------------------------------- content

def content(settings):
    """What is synced: the export of the settings, without what belongs to
    one device (its workspace path) or changes on every call."""
    snap = tb.snapshot(settings)
    snap.pop("created", None)
    snap["settings"].pop("workspace", None)
    snap["settings"]["routers"] = [_norm(r) for r in snap["settings"]["routers"]]
    return snap


def _norm(r):
    """The same router written the same way on both devices."""
    r = {k: r.get(k, "") for k in st.ROUTER_FIELDS}
    r["port"] = int(r["port"] or 22)
    r["role"] = r["role"] or "main"
    r["xray_box"] = bool(r["xray_box"])
    for key in ("params", "xray_params"):
        if not isinstance(r[key], dict):
            r[key] = {}
    return r


def fingerprint(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def summary(local, remote):
    """In words: how the two copies differ (for the conflict question)."""
    out = []
    lr = {r["id"]: r for r in local["settings"]["routers"]}
    rr = {r["id"]: r for r in remote["settings"]["routers"]}

    def label(r):
        return "%s (%s)" % (r.get("name") or r["id"], r.get("host", ""))
    for rid in sorted(set(lr) | set(rr)):
        a, b = lr.get(rid), rr.get(rid)
        if a and not b:
            out.append("• فقط در این دستگاه: سرور %s" % label(a))
        elif b and not a:
            out.append("• فقط در دستگاه دیگر: سرور %s" % label(b))
        elif a != b:
            keys = [k for k in st.ROUTER_FIELDS if a.get(k) != b.get(k)]
            if "params" in keys or "xray_params" in keys:
                pa, pb_ = a.get("params") or {}, b.get("params") or {}
                sub = sorted(k for k in set(pa) | set(pb_) if pa.get(k) != pb_.get(k)) if isinstance(pa, dict) and isinstance(pb_, dict) else []
                keys = [k for k in keys if k not in ("params", "xray_params")] + ["کلیدها/تنظیمات" + (
                    " (%s)" % "، ".join(sub[:6]) if sub else "")]
            out.append("• سرور %s فرق دارد: %s" % (label(a), "، ".join(keys)))
    for k in sorted(set(local["settings"]) | set(remote["settings"])):
        if k != "routers" and local["settings"].get(k) != remote["settings"].get(k):
            out.append("• تنظیم «%s» فرق دارد" % k)
    for name in sorted(set(local.get("files", {})) | set(remote.get("files", {}))):
        if local.get("files", {}).get(name) != remote.get("files", {}).get(name):
            out.append("• فایل %s فرق دارد" % name)
    return "\n".join(out) or "• (فرق محسوسی پیدا نشد)"


# ---------------------------------------------------------------- the router

def main_router(settings):
    return next((r for r in settings.routers if r.get("role") == "main"), None)


def connect_main(settings):
    r = main_router(settings)
    if r is None:
        raise ReleaseError("روتر اصلی در تنظیمات نیست.")
    from routeros import SSHRouter
    return SSHRouter(r["host"], r["port"], r["user"], r["password"], r.get("hostkey", "")).connect()


def read_remote(c, password):
    """(the shared copy as a dict) or None when there is none yet."""
    try:
        blob = c.get(REMOTE_FILE)
    except (IOError, OSError, KeyError):
        return None
    if not blob:
        return None
    try:
        data = json.loads(bk.decrypt(blob, password).decode("utf-8"))
    except ReleaseError:
        raise ReleaseError("نسخه‌ی مشترک تنظیمات روی روتر با رمز بکاپ این دستگاه باز نشد؛ "
                           "رمز بکاپ دو دستگاه باید یکی باشد.")
    if data.get("format") != FORMAT:
        raise ReleaseError("فایل %s روی روتر، تنظیمات مشترک نیست." % REMOTE_FILE)
    return data


def write_remote(c, password, rev, data):
    payload = {"format": FORMAT, "rev": rev, "device": device_id(), "device_name": device_name(),
               "time": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
               "fp": fingerprint(data), "data": data}
    blob = bk.encrypt(json.dumps(payload, ensure_ascii=False).encode("utf-8"), password)
    c.put(REMOTE_FILE, blob)            # makes pvsync/ when missing
    return payload


def _remember(rev, fp):
    state = load_state()
    state.update(rev=rev, fp=fp, time=time.time())
    save_state(state)


def _take(settings, remote):
    """Put the other device's copy in place (this device's workspace stays)."""
    data = dict(remote["data"])
    data["settings"] = dict(data["settings"])
    workspace = settings.workspace
    tb.apply(data, settings, workspace)
    _remember(remote["rev"], fingerprint(content(settings)))


# ---------------------------------------------------------------- sync

def sync(settings, connect=None, log=print, force=False, choose=None):
    """One sync with the main router. Returns one of
    "off" (no backup password or main router), "same", "pushed", "pulled".
    choose(conflict) -> True (take the other copy) / False (keep this one);
    without it a conflict raises SyncConflict."""
    global _last_pull
    if not settings.backup_password or main_router(settings) is None:
        return "off"
    with _lock:
        if not force and time.time() - _last_pull < PULL_EVERY and not changed(settings):
            return "same"
        c = (connect or (lambda: connect_main(settings)))()
        try:
            result = _sync(c, settings, log, choose)
        finally:
            try:
                c.close()
            except Exception:   # noqa: BLE001
                pass
        _last_pull = time.time()
        return result


def changed(settings):
    """This device changed its settings since the last sync."""
    return fingerprint(content(settings)) != load_state().get("fp")


def _sync(c, settings, log, choose):
    pw = settings.backup_password
    state = load_state()
    local = content(settings)
    local_fp = fingerprint(local)
    local_changed = local_fp != state.get("fp")
    remote = read_remote(c, pw)

    if remote is None:
        write_remote(c, pw, 1, local)
        _remember(1, local_fp)
        log("✓ تنظیمات برای همگام‌سازی روی روتر اصلی گذاشته شد.")
        return "pushed"

    remote_moved = remote.get("rev") != state.get("rev")
    if remote.get("fp") == local_fp:                     # already the same content
        _remember(remote["rev"], local_fp)
        return "same"
    if not remote_moved:                                # only this device changed
        write_remote(c, pw, remote["rev"] + 1, local)
        _remember(remote["rev"] + 1, local_fp)
        log("✓ تغییرات تنظیمات به نسخه‌ی مشترک رفت.")
        return "pushed"
    if not local_changed:                               # only the other device changed
        _take(settings, remote)
        log("✓ تنظیمات تازه‌ی %s (%s) دریافت شد." % (remote.get("device_name") or "دستگاه دیگر",
                                                       remote.get("time", "")))
        return "pulled"

    conflict = SyncConflict(remote, summary(local, remote["data"]))
    if choose is None:
        raise conflict
    return resolve(c, settings, remote, choose(conflict), log)


def keep_aside(settings, data, who):
    """The copy that lost a conflict, kept on this device (locked with the
    backup password, readable with the tool's settings import)."""
    folder = os.path.join(st.APP_DIR, "sync_old")
    os.makedirs(folder, exist_ok=True)
    snap = dict(data, format=tb.FORMAT, version=1)
    snap["settings"] = dict(snap["settings"], workspace=settings.workspace)
    path = os.path.join(folder, "%s-%s%s" % (who, _dt.datetime.now().strftime("%Y%m%d-%H%M%S"), bk.EXT))
    with open(path, "wb") as f:
        f.write(bk.encrypt(json.dumps(snap, ensure_ascii=False).encode("utf-8"), settings.backup_password))
    return path


def resolve(c, settings, remote, take_remote, log=print):
    keep_aside(settings, content(settings) if take_remote else remote["data"], "this" if take_remote else "other")
    if take_remote:
        _take(settings, remote)
        log("✓ نسخه‌ی %s جایگزین شد." % (remote.get("device_name") or "دستگاه دیگر"))
        return "pulled"
    local = content(settings)
    write_remote(c, settings.backup_password, remote["rev"] + 1, local)
    _remember(remote["rev"] + 1, fingerprint(local))
    log("✓ نسخه‌ی این دستگاه نسخه‌ی مشترک شد.")
    return "pushed"


def resolve_now(settings, conflict, take_remote, log=print):
    """After the user answered a SyncConflict raised by sync()."""
    global _last_pull
    with _lock:
        c = connect_main(settings)
        try:
            # the shared copy may have moved again meanwhile: start over with the answer
            remote = read_remote(c, settings.backup_password) or conflict.remote
            res = resolve(c, settings, remote, take_remote, log)
        finally:
            c.close()
        _last_pull = time.time()
        return res


# ---------------------------------------------------------------- after every save

def push_in_background(settings, log=None):
    """Settings.save() hook: send the change without waiting (a failure is
    harmless: the next sync before a job sends it)."""
    def work():
        try:
            if changed(settings):
                sync(settings, force=True, log=log or (lambda *_: None))
        except SyncConflict:
            pass                       # the next job asks
        except Exception as e:          # noqa: BLE001 - offline, wrong password ...
            if log:
                log("⚠ همگام‌سازی تنظیمات انجام نشد: %s" % str(e)[:200])
    threading.Thread(target=work, daemon=True).start()


def install_hook(log=None):
    st.ON_SAVE = lambda s: push_in_background(s, log)
