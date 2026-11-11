"""Second User Manager: an always-current copy of the main one.

Every 5 minutes the main router saves its User Manager database into the
umstatus folder; umstatus hands it (over its TLS port, with a secret
token) to the second router, which loads it. So users, profiles, charges
and used volume on UM2 are at most a few minutes behind, and nothing but
the main router is ever written by the bot. Clients that use RADIUS (the
Linux servers) fail over to UM2 by themselves; whatever UM2 counts while
the main router is down is replaced by the main copy when it comes back.

A copy that is much smaller than the last one loaded is not loaded (a
damaged or emptied main database must not wipe the backup).
"""

import re
import secrets

import provision as pv
import services as sv
from routeros import RouterOSError, q

SAVE_NAME = "umstatus/umsync-db"       # on the main router; umstatus serves it
TOKEN_FILE = "umstatus/umsync.token"
DST = "pv-umsync"                      # on UM2
CA_NAME = "pv-umsync-main"
EVERY = "5m"


def save_script():
    return (':do { /file remove [find name~"^%s"] } on-error={}\n'
            '/user-manager database save name=%s' % (SAVE_NAME, SAVE_NAME))


def load_script(url, verify):
    check = "yes-without-crl" if verify else "no"
    # keeps the size of the last good copy in a global; a much smaller one is not loaded
    return r""":global pvUmsyncSize
:do {
  /tool fetch url="%(url)s" check-certificate=%(check)s dst-path=%(dst)s.part output=file
} on-error={ :log warning "pv-umsync: main User Manager not reachable"; :error "unreachable" }
:local f [/file find name="%(dst)s.part"]
:if ([:len $f] = 0) do={ :error "no file" }
:local s [/file get $f size]
:if (($s < 1024) or (([:typeof $pvUmsyncSize] = "num") and ($s * 2 < $pvUmsyncSize))) do={
  :log warning ("pv-umsync: copy of " . $s . " bytes looks wrong, not loaded")
  /file remove $f
  :error "bad size"
}
/file remove [find name="%(dst)s.umb"]
/file set $f name="%(dst)s.umb"
:do { /user-manager database load name="%(dst)s" } on-error={
  /user-manager database load name="%(dst)s.umb"
}
:set pvUmsyncSize $s
""" % {"url": url, "check": check, "dst": DST}


def ensure_scheduler(r, name, interval, script, start_time=None):
    """One scheduler of that name with exactly this script."""
    r.run("/system scheduler remove [find name=%s]" % q(name))
    r.run("/system scheduler add name=%s interval=%s policy=read,write,policy,test,ftp,sensitive "
          "%son-event=%s" % (q(name), interval, ("start-time=%s " % start_time) if start_time else "", q(script)))


def umstatus_port(r):
    """The public port umstatus listens on (its dst-nat rule)."""
    out = r.run(':foreach n in=[/ip firewall nat find comment="umstatus"] do={'
                ':put [/ip firewall nat get $n dst-port]}', check=False).split()
    return int(out[0]) if out and out[0].isdigit() else 8443


def install_load(r, url, verify):
    script = load_script(url, verify)
    ensure_scheduler(r, "pv-umsync-load", EVERY, script)
    r.run("/system script remove [find name=pv-umsync-now]")
    r.run("/system script add name=pv-umsync-now policy=read,write,policy,test,ftp,sensitive source=%s"
          % q(script))
    out = r.run("/system script run pv-umsync-now", check=False, timeout=300)
    r.run("/system script remove [find name=pv-umsync-now]")
    return out, count_users(r)


def count_users(r):
    return int(r.run(":put [:len [/user-manager user find]]").strip() or 0)


def setup_um2(connect_main, connect_um2, main_host, log=print, main_url=None, verify=True):
    """Install / refresh the copy. main_url: how UM2 reaches main's umstatus
    (default https://main_host:<umstatus port>). Returns a summary dict."""
    with connect_main() as m:
        if sv.count(m, "/container", "comment=%s" % q(sv.UMSTATUS["comment"])) == 0:
            raise RouterOSError("روی روتر اصلی کانتینر umstatus نیست؛ همگام‌سازی از طریق آن انجام می‌شود.")
        log("روتر اصلی: umstatus تازه و کلید همگام‌سازی…")
        token = secrets.token_urlsafe(24)
        m.put(TOKEN_FILE, token.encode())
        m.put("umstatus/umstatus.py", sv.umstatus_source())
        sv.restart(m, sv.UMSTATUS, log)
        log("روتر اصلی: ذخیره‌ی دیتابیس یوزر منیجر هر ۵ دقیقه…")
        ensure_scheduler(m, "pv-umsync-save", EVERY, save_script())
        m.run(save_script(), timeout=300)
        port = umstatus_port(m)
        cert = m.get("umstatus/umstatus.crt")
        main_users = count_users(m)
    url = (main_url or "https://%s:%d" % (main_host, port)) + "/v1/umsync/" + token

    r = connect_um2()
    try:
        if not sv.has_package(r, "user-manager"):
            log("روتر دوم: نصب پکیج user-manager (یک بار ری‌استارت می‌شود)…")
            r = pv.install_packages(r, connect_um2, ["user-manager"], log)
        if r.run(":put [/user-manager get enabled]").strip() not in ("true", "yes"):
            r.run("/user-manager set enabled=yes")
        if verify:
            log("روتر دوم: اعتماد به گواهی umstatus روتر اصلی…")
            r.put("pv-umsync-main.crt", cert)
            r.run("/certificate remove [find name=%s]" % q(CA_NAME))
            r.run('/certificate import file-name=pv-umsync-main.crt passphrase="" name=%s' % q(CA_NAME))
            r.remove("pv-umsync-main.crt")
        log("روتر دوم: دریافت و بارگذاری هر ۵ دقیقه…")
        out, um2_users = install_load(r, url, verify)
        if um2_users != main_users and verify:
            log("⚠ گواهی umstatus روتر اصلی روی روتر دوم پذیرفته نشد (احتمالاً با IP جور نیست)؛ "
                "بدون بررسی گواهی امتحان می‌شود.")
            out, um2_users = install_load(r, url, False)
    finally:
        r.close()
    if um2_users != main_users:
        raise RouterOSError("کپی اول بارگذاری نشد (اصلی %d یوزر، دوم %d یوزر).\n%s"
                            % (main_users, um2_users, out.strip()[-400:]))
    log("✓ یوزر منیجر دوم همگام شد (%d یوزر)؛ از این به بعد هر ۵ دقیقه." % um2_users)
    return {"users": um2_users, "url": re.sub(r"/v1/umsync/.*", "/v1/umsync/…", url)}
