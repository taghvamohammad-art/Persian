"""Setting up a NEW router from a backup (main server) or as a secondary server.

Main server (restore_main): the new router becomes a copy of the backed-up
main router: packages, device-mode, certificates (same ones, so the apps'
pins stay valid), User Manager database (users, passwords, usage), the whole
configuration with the old public IP replaced by the new one, the router's
files, the service accounts and the containers (umstatus, the bot).

Secondary server (setup_secondary): SSTP with the same certificate, users
checked against the main router's User Manager over RADIUS.

Both run step by step and remember finished steps in a file on the router,
so pressing the button again after an interruption (or after the power
cycle that device-mode needs) continues where it stopped.
"""

import ipaddress
import json
import re
import secrets
import ssl
import time
import urllib.request

import services as sv
from publisher import ReleaseError
from routeros import RouterOSError, q

STATE_FILE = "pv-setup-state.json"
NEED_POWER_CYCLE = "power_cycle"
DONE = "done"

COMMANDS = {"add", "set", "remove", "enable", "disable", "comment", "move", "unset", "edit"}
SKIP_MENUS = {
    "/interface ethernet", "/interface ethernet switch", "/ip dhcp-client", "/ipv6 dhcp-client",
    "/system license", "/system routerboard", "/system routerboard settings", "/system device-mode",
    "/certificate", "/certificate settings", "/certificate scep-server",
    "/container", "/container config", "/container mounts", "/container envs",
    "/user-manager database", "/disk", "/disk settings", "/file",
}
UM_DATA = {"/user-manager user", "/user-manager user-profile", "/user-manager profile",
           "/user-manager limitation", "/user-manager profile-limitation", "/user-manager router",
           "/user-manager user-group", "/user-manager attribute", "/user-manager payment",
           "/user-manager session"}
WAN_IF = re.compile(r"\binterface=(ether|sfp|combo|qsfp)\S*")


# ---------------------------------------------------------------- export handling

def split_line(line):
    """('/ip firewall nat', 'add', 'chain=…') of a terse export line."""
    toks = line.split(" ")
    for i, t in enumerate(toks):
        if t in COMMANDS:
            return " ".join(toks[:i]), t, " ".join(toks[i + 1:])
    return line, "", ""


def replace_ip(text, old, new):
    if not old or not new or old == new:
        return text
    return re.sub(r"(?<![\d.])%s(?![\d])" % re.escape(old), new, text)


def filter_export(export, old_ip, new_ip):
    """Lines to apply on the new main router, plus what was left out and why."""
    keep, um_lines, skipped = [], [], []
    for line in export.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        menu, cmd, args = split_line(line)
        if menu in UM_DATA:
            um_lines.append(line)
            continue
        if menu in SKIP_MENUS:
            continue
        if menu == "/ip address" and WAN_IF.search(args):
            skipped.append(("آدرس کارت شبکه‌ی اینترنت (روتر جدید آدرس خودش را دارد)", line))
            continue
        if menu == "/ip route" and cmd == "add" and (
                "dst-address=" not in args or "dst-address=0.0.0.0/0" in args):
            skipped.append(("route پیش‌فرض (روتر جدید gateway خودش را دارد)", line))
            continue
        if menu == "/ip service" and re.match(r"(ssh\b|\[ ?find (where )?name=ssh ?\])", args):
            skipped.append(("تنظیم SSH اعمال نشد تا اتصال ابزار قطع نشود", line))
            continue
        if "***" in line:
            skipped.append(("مقدار مخفی در export", line))
            continue
        keep.append(replace_ip(line, old_ip, new_ip))
    return keep, um_lines, skipped


def first_public_ip(text):
    for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3})/\d+", text or ""):
        try:
            ip = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if ip.is_global:
            return str(ip)
    return None


def old_public_ip(manifest, parts):
    host = manifest.get("host", "")
    try:
        if ipaddress.ip_address(host).is_global:
            return host
    except ValueError:
        pass
    return first_public_ip(parts.get("info/addresses.txt", b"").decode("utf-8", "replace")) or host


# ---------------------------------------------------------------- state on the router

class State:
    def __init__(self, r, key):
        self.r, self.key = r, key
        try:
            d = json.loads(r.get(STATE_FILE))
        except Exception:
            d = {}
        self.done = set(d.get("done", [])) if d.get("key") == key else set()

    def has(self, step):
        return step in self.done

    def mark(self, step):
        self.done.add(step)
        self.r.put(STATE_FILE, json.dumps({"key": self.key, "done": sorted(self.done)}).encode())


# ---------------------------------------------------------------- packages, device-mode, reboot

def wait_back(connect, log=print, timeout=420, down_first=True):
    """New connection after a reboot."""
    if down_first:
        time.sleep(15)
    end = time.time() + timeout
    while True:
        try:
            r = connect()
            r.run(":put 1")
            return r
        except Exception as e:
            if time.time() > end:
                raise RouterOSError("روتر بعد از راه‌اندازی دوباره در دسترس نشد: %s" % e)
            time.sleep(5)


def reboot(r, connect, log=print):
    log("راه‌اندازی دوباره‌ی روتر…")
    try:
        r.run(":execute {/system reboot}", check=False, timeout=15)
    except Exception:
        pass
    r.close()
    return wait_back(connect, log)


def routeros_version(r):
    import backup as bk
    return bk.parse_version(r.run("/system resource print"))


def install_packages(r, connect, names, log=print, package_source=None):
    """Install extra packages (user-manager, container) and reboot.

    The router downloads them from mikrotik.com itself; if it can't,
    package_source(name, version) -> bytes supplies them (the PC downloads)."""
    missing = [n for n in names if not sv.has_package(r, n)]
    if not missing:
        return r
    ver = routeros_version(r)
    for name in missing:
        fname = "%s-%s.npk" % (name, ver)
        log("دانلود پکیج %s…" % fname)
        out = r.run('/tool fetch url="https://download.mikrotik.com/routeros/%s/%s" dst-path=%s'
                    % (ver, fname, fname), check=False, timeout=300)
        if "finished" not in out:
            if package_source is None:
                raise RouterOSError("روتر نتوانست پکیج %s را دانلود کند:\n%s" % (fname, out.strip()[-300:]))
            log("روتر دانلود نکرد؛ ارسال از این کامپیوتر…")
            r.put(fname, package_source(name, ver))
    r = reboot(r, connect, log)
    still = [n for n in names if not sv.has_package(r, n)]
    if still:
        raise RouterOSError("پکیج‌های %s نصب نشدند." % ", ".join(still))
    log("✓ پکیج‌ها نصب شدند: %s" % ", ".join(missing))
    return r


def request_container_mode(r, log=print):
    log("درخواست فعال‌سازی device-mode کانتینر…")
    r.run(":execute {/system device-mode update container=yes}", check=False, timeout=15)


# ---------------------------------------------------------------- certificates

def import_certs(r, manifest, parts, only=None, log=print):
    """Import the backed-up certificates under their original names."""
    pp = manifest.get("cert_passphrase", "")
    for c in manifest.get("certificates", []):
        if only is not None and c["name"] not in only:
            continue
        fp = c.get("fingerprint", "")
        if fp and sv.count(r, "/certificate", "fingerprint=%s" % q(fp)):
            name = sv.get(r, "/certificate", "fingerprint=%s" % q(fp), "name")
            if name != c["name"]:
                r.run("/certificate set [find where fingerprint=%s] name=%s" % (q(fp), q(c["name"])))
            continue
        for f in c["files"]:
            fname = "pvr-cert-%s.%s" % (c["index"], f.split("-", 1)[-1])
            r.put(fname, parts["certs/" + f])
            out = r.run("/certificate import file-name=%s passphrase=%s" % (fname, q(pp)), check=False)
            r.remove(fname)
            log("  " + " ".join(out.split())[:160])
        if fp and sv.count(r, "/certificate", "fingerprint=%s" % q(fp)):
            if sv.count(r, "/certificate", "name=%s and fingerprint!=%s" % (q(c["name"]), q(fp))):
                r.run("/certificate set [find where name=%s and fingerprint!=%s] name=%s"
                      % (q(c["name"]), q(fp), q(c["name"] + "-old")))
            r.run("/certificate set [find where fingerprint=%s] name=%s" % (q(fp), q(c["name"])))
        else:
            raise RouterOSError("گواهی %s بعد از ورود پیدا نشد." % c["name"])
        log("  گواهی %s ✓" % c["name"])


# ---------------------------------------------------------------- applying lines

def apply_lines(r, lines, log=print, progress=None):
    """Run each line on its own; returns [(line, error)] of the ones that failed."""
    failed = []
    for i, line in enumerate(lines):
        try:
            r.run(line, timeout=120)
        except RouterOSError as e:
            failed.append((line, str(e).splitlines()[-1]))
        if progress:
            progress(i + 1, len(lines))
    # a line may depend on one that comes later in the export: one more pass
    again = []
    for line, err in failed:
        try:
            r.run(line, timeout=120)
        except RouterOSError as e:
            again.append((line, str(e).splitlines()[-1]))
    return again


def health(url):
    """GET url (self-signed TLS): True when it answers 200."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(url, timeout=10, context=ctx) as resp:
            return resp.status == 200
    except Exception:
        return False


# ---------------------------------------------------------------- main server

def restore_main(connect, manifest, parts, new_ip, old_ip=None, log=print, progress=None,
                 health_url=None, public_key=None, package_source=None):
    """Make the router behind connect() a copy of the backed-up main router.

    Returns {"status": "done" | "power_cycle", "skipped": [...], "failed": [...], "checks": [...]}.
    """
    old_ip = old_ip or old_public_ip(manifest, parts)
    export = parts["export.rsc"].decode("utf-8", "replace")
    lines, um_lines, skipped = filter_export(export, old_ip, new_ip)
    result = {"status": DONE, "skipped": skipped, "failed": [], "checks": [], "old_ip": old_ip}
    has_um = manifest.get("has_user_manager") and any(p.startswith("um/") for p in parts)
    services = [s for s in (sv.UMSTATUS, sv.UMBOT) if any(p.startswith("files/%s/" % s["dir"]) for p in parts)]
    need_container = bool(services) or bool(manifest.get("container_roots"))

    r = connect()
    try:
        state = State(r, "main:" + manifest.get("created", ""))
        ver = routeros_version(r)
        log("روتر جدید: RouterOS %s (بکاپ: %s)" % (ver, manifest.get("routeros")))
        if ver.split(".")[:2] != str(manifest.get("routeros", "")).split(".")[:2]:
            result["checks"].append("⚠ نسخه‌ی RouterOS با بکاپ فرق دارد (%s ≠ %s)." % (ver, manifest.get("routeros")))

        # 1. packages
        pk = (["user-manager"] if has_um else []) + (["container"] if need_container else [])
        if pk and not state.has("packages"):
            r = install_packages(r, connect, pk, log, package_source)
            state = State(r, state.key)
            state.mark("packages")

        # 2. device-mode (needs a power cycle from the VPS panel)
        if need_container and not sv.device_mode_container(r):
            request_container_mode(r, log)
            result["status"] = NEED_POWER_CYCLE
            return result

        # 3. files
        if not state.has("files"):
            files = [p for p in parts if p.startswith("files/")]
            skip = ("files/user-manager5/", "files/um5files/")
            files = [p for p in files if not p.startswith(skip)]
            log("ارسال %d فایل…" % len(files))
            for i, p in enumerate(files):
                r.put(p[len("files/"):], parts[p])
                if progress:
                    progress(i + 1, len(files))
            if any(s is sv.UMSTATUS for s in services):
                r.put("umstatus/umstatus.py", sv.umstatus_source())
                if public_key:
                    r.put("umstatus/config_key.public.txt", public_key)
            state.mark("files")

        # 4. certificates
        if not state.has("certs"):
            log("گواهی‌ها…")
            import_certs(r, manifest, parts, log=log)
            state.mark("certs")

        # 5. User Manager database
        if has_um and not state.has("um"):
            log("دیتابیس یوزر منیجر…")
            r.run("/user-manager set enabled=yes")
            um_file = next(p for p in parts if p.startswith("um/"))
            name = "pvr-" + um_file[3:]
            r.put(name, parts[um_file])
            load_um(r, name)
            r.remove(name)
            # entries the database did not bring along come from the export
            for menu in ("/user-manager router", "/user-manager limitation", "/user-manager profile",
                         "/user-manager profile-limitation"):
                if sv.count(r, menu) == 0:
                    result["failed"] += apply_lines(r, [l for l in um_lines if split_line(l)[0] == menu])
            state.mark("um")

        # 6. configuration
        if not state.has("config"):
            log("اعمال تنظیمات (%d دستور)…" % len(lines))
            result["failed"] += apply_lines(r, lines, log, progress)
            state.mark("config")

        # 7. service accounts + containers
        if not state.has("services"):
            for svc in services:
                if svc is sv.UMSTATUS:
                    cfg = json.loads(r.get("umstatus/config.json"))
                    pw = cfg.get("router_password", "")
                    policy = "read,api,rest-api,web,sensitive"
                else:
                    pw = sv.parse_env(sv.file_text(r, "umbot/.env") or "").get("MT_PASSWORD", "")
                    policy = "read,write,api,rest-api,web,sensitive"
                if pw:
                    sv.ensure_api_user(r, svc["comment"], svc["ip"], policy, pw)
                sv.ensure_network(r, svc, log)
                sv.ensure_rest(r, log)
                sv.ensure_container(r, svc, log)
            state.mark("services")

        # 8. checks
        result["checks"] += verify_main(r, manifest, parts, um_lines, services, health_url
                                        or ("https://%s:8443/health" % new_ip))
        state.mark("verified")
        return result
    finally:
        r.close()


def load_um(r, name):
    """/user-manager database load, whichever spelling this version wants."""
    base = name.rsplit(".", 1)[0]
    errors = []
    for cmd in ("/user-manager database load name=%s" % q(base),
                "/user-manager database load name=%s" % q(name)):
        try:
            r.run(cmd, timeout=600)
            return
        except RouterOSError as e:
            errors.append(str(e).splitlines()[-1])
    raise RouterOSError("بارگذاری دیتابیس یوزر منیجر ناموفق بود:\n" + "\n".join(errors))


def verify_main(r, manifest, parts, um_lines, services, health_url):
    checks = []

    def check(ok, text):
        checks.append(("✓ " if ok else "✗ ") + text)

    for c in manifest.get("certificates", []):
        check(sv.count(r, "/certificate", "fingerprint=%s and name=%s" % (q(c["fingerprint"]), q(c["name"]))) > 0,
              "گواهی %s" % c["name"])
    sstp = r.run(":put [/interface sstp-server server get enabled]").strip()
    check(sstp in ("true", "yes"), "SSTP فعال")
    users = len([l for l in um_lines if split_line(l)[0] == "/user-manager user"])
    if manifest.get("has_user_manager"):
        n = sv.count(r, "/user-manager user")
        check(n >= users, "یوزرهای یوزر منیجر: %d از %d" % (n, users))
    for svc in services:
        check(sv.container_status(r, svc) == "running", "کانتینر %s" % svc["comment"])
    if any(s is sv.UMSTATUS for s in services):
        ok = False
        for _ in range(10):
            ok = health(health_url)
            if ok:
                break
            time.sleep(3)
        check(ok, "سرویس وضعیت از بیرون (%s)" % health_url)
    return checks


# ---------------------------------------------------------------- secondary server

SECONDARY_MENUS = {"/ip pool", "/ppp profile", "/interface sstp-server server", "/ip dns"}


def secondary_lines(export):
    """SSTP/PPP settings of the main router to copy onto a secondary."""
    out = []
    for line in export.splitlines():
        line = line.strip()
        menu, cmd, args = split_line(line)
        if menu in SECONDARY_MENUS and "***" not in line:
            out.append(line)
        elif menu == "/ip firewall nat" and "action=masquerade" in args and "172.17.0." not in args:
            out.append(line)
    return out


def sstp_cert_name(export):
    m = re.search(r"^/interface sstp-server server set .*\bcertificate=(\"[^\"]+\"|\S+)", export, re.M)
    return m.group(1).strip('"') if m else None


def setup_secondary(connect_sec, connect_main, manifest, parts, sec_ip, main_ip, name,
                    log=print, sec_ip_seen_by_main=None, radius_secret=None):
    """Secondary SSTP server whose users are checked by the main User Manager."""
    export = parts["export.rsc"].decode("utf-8", "replace")
    secret = radius_secret or secrets.token_urlsafe(24)
    seen = sec_ip_seen_by_main or sec_ip
    result = {"status": DONE, "failed": [], "checks": [], "secret": secret}
    tag = "pv-secondary-%s" % re.sub(r"[^A-Za-z0-9_-]", "-", name)

    # on the main router: accept this NAS
    log("ثبت سرور فرعی روی یوزر منیجر اصلی…")
    m = connect_main()
    try:
        if sv.count(m, "/user-manager router", "comment=%s" % q(tag)):
            m.run("/user-manager router remove [find where comment=%s]" % q(tag))
        if sv.count(m, "/user-manager router", "address=%s" % seen):
            m.run("/user-manager router remove [find where address=%s]" % seen)
        m.run("/user-manager router add name=%s address=%s shared-secret=%s comment=%s"
              % (q(tag), seen, q(secret), q(tag)))
        sv.ensure_input_accept(m, seen, "udp", "1812,1813", tag)
    finally:
        m.close()

    r = connect_sec()
    try:
        log("گواهی SSTP…")
        cert = sstp_cert_name(export)
        wanted = {c["name"] for c in manifest.get("certificates", [])}
        import_certs(r, manifest, parts, only=wanted, log=log)
        log("تنظیمات SSTP و PPP…")
        result["failed"] += apply_lines(r, secondary_lines(export))
        if sv.count(r, "/ip firewall nat", "chain=srcnat and action=masquerade") == 0:
            r.run("/ip firewall nat add chain=srcnat action=masquerade comment=pv-vpn")
        log("RADIUS به سرور اصلی…")
        if sv.count(r, "/radius", "comment=%s" % q(tag)):
            r.run("/radius remove [find where comment=%s]" % q(tag))
        r.run("/radius add address=%s secret=%s service=ppp timeout=3s comment=%s" % (main_ip, q(secret), q(tag)))
        r.run("/ppp aaa set use-radius=yes accounting=yes interim-update=1m")
        r.run("/interface sstp-server server set enabled=yes" + (" certificate=%s" % q(cert) if cert else ""))
        sstp = r.run(":put [/interface sstp-server server get enabled]").strip()
        result["checks"].append(("✓ " if sstp in ("true", "yes") else "✗ ") + "SSTP فعال")
        result["checks"].append("✓ RADIUS → %s" % main_ip)
    finally:
        r.close()
    return result


# ---------------------------------------------------------------- app config

def move_server_in_config(cfg, old_host, new_host):
    """config.json after the main server moved: every URL/host of the old one."""
    def fix(v):
        if isinstance(v, str):
            return replace_ip(v, old_host, new_host) if re.match(r"^[\d.]+$", old_host) else v.replace(old_host, new_host)
        if isinstance(v, list):
            return [fix(x) for x in v]
        if isinstance(v, dict):
            return {k: fix(x) for k, x in v.items()}
        return v
    out = dict(cfg)
    for k in ("servers", "status_urls", "config_urls"):
        if k in out:
            out[k] = fix(out[k])
    return out


def add_server_to_config(cfg, name, host, port=443):
    out = dict(cfg)
    servers = list(out.get("servers", []))
    if not any(s.get("host") == host for s in servers):
        servers.append({"name": name, "host": host, "port": port})
    out["servers"] = servers
    return out


def add_linux_server(cfg, entry):
    """A Linux server in the app config: its own list, so app versions that
    only know SSTP (which reads "servers") are not confused by it."""
    out = dict(cfg)
    servers = [s for s in out.get("linux_servers", []) if s.get("host") != entry["host"]]
    servers.append(entry)
    out["linux_servers"] = servers
    return out
