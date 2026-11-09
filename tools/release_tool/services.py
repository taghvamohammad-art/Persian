"""Services that run in containers on the main router: umstatus and the bot.

Everything here goes over the tool's SSH connection (routeros.SSHRouter) and
is idempotent: running a step twice leaves the router as running it once.
"""

import io
import json
import os
import re
import secrets
import time
import zipfile

from publisher import ReleaseError
from routeros import RouterOSError, q

BRIDGE = "br-containers"
NET = "172.17.0.0/24"
GW = "172.17.0.1"
IMAGE = "library/python:3.12-alpine"
REGISTRY = "https://registry-1.docker.io"

UMSTATUS = {"comment": "umstatus", "veth": "veth-umstatus", "ip": "172.17.0.2", "dir": "umstatus",
            "cmd": "python3 /app/umstatus.py serve"}
UMBOT = {"comment": "umbot", "veth": "veth-umbot", "ip": "172.17.0.3", "dir": "umbot",
         "cmd": "python3 /app/run_umbot.py"}

BOT_REPO = "taghvamohammad-art/um-reseller-bot"
BOT_RUNNER = b"""# started by the container: python3 /app/run_umbot.py
import runpy, sys
sys.path.insert(0, "/app")
sys.argv = ["umbot", "/app/.env"]
runpy.run_module("umbot", run_name="__main__")
"""
# keys of the bot's .env that the tool manages itself
BOT_MANAGED = ("MT_URL", "MT_USER", "MT_PASSWORD", "MT_CA_FILE", "MT_ALLOW_HTTP", "MT_TLS_VERIFY",
               "DB_PATH", "LOG_FILE")
BOT_DEFAULTS = [("BOT_TOKEN", ""), ("ADMIN_IDS", ""), ("INVITE_TTL_HOURS", "48"), ("STOCK_PREFIX", ""),
                ("USERNAME_PREFIX", "25g"), ("USERNAME_DIGITS", "5"), ("PASSWORD_LENGTH", "6")]


# ---------------------------------------------------------------- small RouterOS helpers

def count(r, menu, where=""):
    out = r.run(":put [:len [%s find%s]]" % (menu, (" where " + where) if where else "")).strip()
    try:
        return int(out.splitlines()[-1])
    except (ValueError, IndexError):
        raise RouterOSError("جواب غیرمنتظره از روتر: %s" % out[:200])


def get(r, menu, where, prop):
    out = r.run(':local i [%s find where %s]; :if ([:len $i] = 0) do={:put "<none>"} '
                'else={:put [%s get ($i->0) %s]}' % (menu, where, menu, prop))
    v = out.strip()
    return None if v == "<none>" else v


def place_first(r, chain):
    """'place-before=…' so a new filter rule lands before the drop rules."""
    if count(r, "/ip firewall filter") == 0:
        return ""
    return " place-before=0"


def ensure_input_accept(r, src, protocol, ports, comment):
    """Accept rule in the input chain (only matters when the router has rules)."""
    if count(r, "/ip firewall filter") == 0:
        return
    if count(r, "/ip firewall filter", "comment=%s" % q(comment)) == 0:
        r.run("/ip firewall filter add chain=input src-address=%s protocol=%s dst-port=%s action=accept "
              "comment=%s place-before=0" % (src, protocol, ports, q(comment)))


def ensure_dir(r, path):
    try:
        r.makedirs(path)
    except (IOError, OSError):
        if count(r, "/file", "name=%s" % q(path)) == 0:
            r.run("/file add name=%s type=directory" % q(path))


def file_text(r, path):
    try:
        return r.get(path).decode("utf-8", "replace")
    except (IOError, OSError, KeyError):
        return None


# ---------------------------------------------------------------- container plumbing

def device_mode_container(r):
    v = r.run(":put [/system device-mode get container]").strip().lower()
    return v in ("yes", "true")


def has_package(r, name):
    return count(r, "/system package", "name=%s" % q(name)) > 0


def ensure_network(r, svc, log=print):
    if count(r, "/interface bridge", "name=%s" % q(BRIDGE)) == 0:
        log("ساخت bridge کانتینرها…")
        r.run("/interface bridge add name=%s" % BRIDGE)
    if count(r, "/ip address", "interface=%s" % q(BRIDGE)) == 0:
        r.run("/ip address add address=%s/24 interface=%s" % (GW, BRIDGE))
    if count(r, "/interface veth", "name=%s" % q(svc["veth"])) == 0:
        r.run("/interface veth add name=%s address=%s/24 gateway=%s" % (svc["veth"], svc["ip"], GW))
    if count(r, "/interface bridge port", "interface=%s" % q(svc["veth"])) == 0:
        r.run("/interface bridge port add bridge=%s interface=%s" % (BRIDGE, svc["veth"]))
    # containers reach the internet (the bot talks to Telegram)
    if count(r, "/ip firewall nat", "chain=srcnat and action=masquerade") == 0:
        r.run("/ip firewall nat add chain=srcnat src-address=%s action=masquerade comment=pv-containers" % NET)


def ensure_rest(r, log=print):
    """The www service (REST) reachable from the containers; returns its port."""
    port = (get(r, "/ip service", "name=www", "port") or "80").strip()
    disabled = (get(r, "/ip service", "name=www", "disabled") or "").strip()
    if disabled in ("true", "yes"):
        log("فعال کردن سرویس www (REST) برای کانتینرها…")
        r.run("/ip service set www disabled=no")
    addr = (get(r, "/ip service", "name=www", "address") or "").strip()
    if addr and NET not in addr.split(","):
        r.run("/ip service set www address=%s" % q(addr + "," + NET))
    ensure_input_accept(r, NET, "tcp", port, "pv-containers-rest")
    return int(port)


def ensure_api_user(r, name, ip, policy, password):
    if count(r, "/user group", "name=%s" % q(name)) == 0:
        r.run("/user group add name=%s policy=%s" % (q(name), policy))
    else:
        r.run("/user group set [find where name=%s] policy=%s" % (q(name), policy))
    if count(r, "/user", "name=%s" % q(name)) == 0:
        r.run("/user add name=%s group=%s address=%s/32 password=%s" % (q(name), q(name), ip, q(password)))
    else:
        r.run("/user set [find where name=%s] group=%s address=%s/32 password=%s"
              % (q(name), q(name), ip, q(password)))


STATES = ("running", "stopped", "extracting", "downloading", "starting", "stopping", "error")


def container_props(r, svc):
    """All properties of the container as a dict ({} when there is none)."""
    out = r.run(':local i [/container find where comment=%s]; :if ([:len $i] = 0) do={:put "<none>"} '
                'else={:put [/container get ($i->0)]}' % q(svc["comment"])).strip()
    if out == "<none>":
        return {}
    props = {}
    for part in out.split(";"):
        k, _, v = part.partition("=")
        props[k.strip()] = v.strip()
    return props


def parse_state(props):
    if not props:
        return "none"
    if props.get("status"):
        return props["status"].lower()
    for st in STATES:          # newer RouterOS: flags as boolean properties
        if props.get(st) == "true":
            return st
    for k, v in props.items():  # e.g. "downloading/extracting=true"
        if v == "true" and ("extract" in k or "download" in k):
            return "extracting"
    return "unknown"


def container_status(r, svc):
    return parse_state(container_props(r, svc))


def wait_status(r, svc, want, timeout=900, log=print):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        props = container_props(r, svc)
        s = parse_state(props)
        if s != last:
            log("  کانتینر %s: %s" % (svc["comment"], s))
            if s == "unknown":
                flags = {k: v for k, v in props.items() if v in ("true", "yes") or "status" in k or "state" in k}
                log("  %s" % flags)
            last = s
        if s in want:
            return s
        if s == "error":
            raise RouterOSError("کانتینر %s خطا داد. لاگ: /log print where topics~\"container\"" % svc["comment"])
        time.sleep(3)
    logs = r.run('/log print where topics~"container"', check=False).strip().splitlines()[-15:]
    raise RouterOSError("کانتینر %s در زمان مقرر آماده نشد (وضعیت: %s).\n%s"
                        % (svc["comment"], last, "\n".join(logs)))


def ensure_container(r, svc, log=print):
    """Create (image download) and start the container of svc."""
    if not has_package(r, "container"):
        raise RouterOSError("پکیج container روی روتر نصب نیست.")
    if not device_mode_container(r):
        raise RouterOSError("device-mode کانتینر روی روتر فعال نیست.")
    if not r.run(":put [/container config get registry-url]").strip():
        r.run("/container config set registry-url=%s tmpdir=container-tmp" % REGISTRY)
    if count(r, "/container mounts", "list=%s" % q(svc["dir"])) == 0:
        r.run("/container mounts add list=%s src=/%s dst=/app" % (q(svc["dir"]), svc["dir"]))
    if count(r, "/container", "comment=%s" % q(svc["comment"])) == 0:
        log("دانلود ایمیج پایتون برای %s (چند دقیقه)…" % svc["comment"])
        r.run("/container add remote-image=%s interface=%s root-dir=containers/%s mountlists=%s "
              "cmd=%s logging=yes start-on-boot=yes dns=1.1.1.1,8.8.8.8 comment=%s"
              % (IMAGE, svc["veth"], svc["comment"], q(svc["dir"]), q(svc["cmd"]), q(svc["comment"])))
    s = wait_status(r, svc, ("stopped", "running"), log=log)
    if s != "running":
        start(r, svc, log)


def start(r, svc, log=print):
    r.run("/container start [find where comment=%s]" % q(svc["comment"]))
    wait_status(r, svc, ("running",), timeout=120, log=log)


def stop(r, svc, log=print):
    if container_status(r, svc) in ("running", "starting"):
        r.run("/container stop [find where comment=%s]" % q(svc["comment"]))
        wait_status(r, svc, ("stopped",), timeout=120, log=log)


def restart(r, svc, log=print):
    stop(r, svc, log)
    start(r, svc, log)


# ---------------------------------------------------------------- umstatus

def umstatus_source():
    """umstatus.py shipped with the tool (bundled in the .exe)."""
    import sys
    here = os.path.dirname(os.path.abspath(__file__))
    for d in (getattr(sys, "_MEIPASS", None), here, os.path.join(here, "..", "..", "server", "umstatus")):
        if d and os.path.isfile(os.path.join(d, "umstatus.py")):
            with open(os.path.join(d, "umstatus.py"), "rb") as f:
                return f.read()
    raise ReleaseError("فایل umstatus.py همراه برنامه پیدا نشد.")


def update_umstatus(r, public_key, log=print):
    """Newest umstatus.py + the config-signing public key, then restart."""
    if count(r, "/container", "comment=%s" % q(UMSTATUS["comment"])) == 0:
        raise RouterOSError("کانتینر umstatus روی این روتر نیست.")
    log("ارسال umstatus.py…")
    r.put("umstatus/umstatus.py", umstatus_source())
    if public_key:
        r.put("umstatus/config_key.public.txt", public_key)
    log("راه‌اندازی دوباره‌ی umstatus…")
    restart(r, UMSTATUS, log)
    log("✓ umstatus به‌روز شد")


# ---------------------------------------------------------------- bot

def parse_env(text):
    out = {}
    for raw in (text or "").replace("﻿", "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out[k.strip()] = v
    return out


def render_env(values, rest_port, password):
    lines = ["# managed by the Persian VPN release tool"]
    for k, default in BOT_DEFAULTS:
        lines.append("%s=%s" % (k, values.get(k, default)))
    for k, v in values.items():
        if k not in dict(BOT_DEFAULTS) and k not in BOT_MANAGED:
            lines.append("%s=%s" % (k, v))
    lines += ["MT_URL=http://%s:%d" % (GW, rest_port), "MT_ALLOW_HTTP=1", "MT_USER=umbot",
              "MT_PASSWORD=%s" % password, "DB_PATH=/app/data/umbot.sqlite3", "LOG_FILE=/app/data/umbot.log"]
    return ("\n".join(lines) + "\n").encode()


def check_bot_values(values):
    if not re.fullmatch(r"\d+:[A-Za-z0-9_-]{20,}", values.get("BOT_TOKEN", "")):
        raise ReleaseError("توکن بات (BOT_TOKEN) درست نیست.")
    if not re.fullmatch(r"\d+(,\d+)*", values.get("ADMIN_IDS", "").replace(" ", "")):
        raise ReleaseError("ADMIN_IDS باید شناسه‌های عددی تلگرام باشد (با کاما جدا).")


def bot_code_from_zip(data):
    """{relative path: bytes} of the bot package from a GitHub zipball (or any zip)."""
    files = {}
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for n in z.namelist():
            m = re.search(r"(?:^|/)(umbot/[^/]+\.py)$", n)
            if m and "/tests/" not in "/" + n:
                files[m.group(1)] = z.read(n)
    if "umbot/__main__.py" not in files:
        raise ReleaseError("کد بات در فایل دریافتی پیدا نشد.")
    return files


def download_bot_code(gh_token, repo=BOT_REPO, ref="main"):
    import urllib.request
    req = urllib.request.Request("https://api.github.com/repos/%s/zipball/%s" % (repo, ref))
    req.add_header("Authorization", "Bearer " + gh_token)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "PersianVPN-Release")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return bot_code_from_zip(r.read())
    except urllib.error.HTTPError as e:
        if e.code in (403, 404):
            raise ReleaseError("توکن GitHub به مخزن %s دسترسی ندارد. آن را به توکن اضافه کنید." % repo)
        raise ReleaseError("دانلود کد بات ناموفق بود: HTTP %d" % e.code)
    except OSError as e:
        raise ReleaseError("دانلود کد بات ناموفق بود: %s" % e)


def bot_values(r):
    """Current settings of the bot on the router (without the managed keys)."""
    env = parse_env(file_text(r, "umbot/.env") or "")
    return {k: v for k, v in env.items() if k not in BOT_MANAGED}


def install_bot(r, code, values=None, db=None, overwrite_db=False, log=print):
    """Install or update the bot. values: .env settings (None = keep current);
    db: an existing umbot.sqlite3 (moving from the Windows server)."""
    current = parse_env(file_text(r, "umbot/.env") or "")
    merged = {k: v for k, v in current.items() if k not in BOT_MANAGED}
    if values is not None:
        merged.update({k: v for k, v in values.items() if k not in BOT_MANAGED})
    check_bot_values(merged)

    log("آماده‌سازی شبکه و دسترسی REST…")
    ensure_network(r, UMBOT, log)
    port = ensure_rest(r, log)
    password = current.get("MT_PASSWORD") or secrets.token_urlsafe(24)
    ensure_api_user(r, "umbot", UMBOT["ip"], "read,write,api,rest-api,web,sensitive", password)

    running = count(r, "/container", "comment=%s" % q(UMBOT["comment"])) > 0
    if running:
        stop(r, UMBOT, log)
    log("ارسال کد بات (%d فایل)…" % len(code))
    ensure_dir(r, "umbot/data")
    for path, data in code.items():
        r.put("umbot/" + path, data)
    r.put("umbot/run_umbot.py", BOT_RUNNER)
    r.put("umbot/.env", render_env(merged, port, password))
    if db is not None:
        exists = file_text(r, "umbot/data/umbot.sqlite3") is not None
        if exists and not overwrite_db:
            raise ReleaseError("روی روتر از قبل دیتابیس بات هست؛ برای جایگزینی تأیید لازم است.")
        log("ارسال دیتابیس بات…")
        r.put("umbot/data/umbot.sqlite3", db)
    log("کانتینر بات…")
    ensure_container(r, UMBOT, log)
    log("✓ بات روی روتر اجرا شد")


def bot_status(r):
    st = container_status(r, UMBOT)
    log = file_text(r, "umbot/data/umbot.log") or ""
    return st, log.splitlines()[-60:]


def stop_bot_autostart(r, log=print):
    """On the OLD router after a move: the same bot token must not run twice."""
    if count(r, "/container", "comment=%s" % q(UMBOT["comment"])) == 0:
        return False
    stop(r, UMBOT, log)
    r.run("/container set [find where comment=%s] start-on-boot=no" % q(UMBOT["comment"]))
    return True
