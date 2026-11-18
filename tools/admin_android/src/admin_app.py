"""Persian Admin: the release tool on the phone (Android, Flet).

Same code as the Windows tool for everything that talks to the routers,
the Linux servers and GitHub (publisher, services, linux, backup, ...);
only this file, the screens, is new. The settings come over from the
Windows tool in one password-locked file ("📱 انتقال به گوشی") and are kept
locked with an app password asked when the app opens.
"""

import asyncio
import datetime as _dt
import os
import re
import sys
import tempfile
import time
import traceback

import flet as ft

import backup as bk
import linux
import monitor
import provision as pv
import publisher as pb
import selfupdate as su
import services as sv
import settings as st
import toolbackup as tb
from routeros import SSHRouter

FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")
ROLES = [("main", "اصلی (یوزر منیجر)"), ("um2", "یوزر منیجر دوم (پشتیبان)"),
         ("secondary", "فرعی (SSTP)"), ("linux", "سرور لینوکس (Xray و AmneziaWG)")]
UM_ROLES = ("main", "um2")
ROLE_SHORT = {"main": "میکروتیک اصلی", "um2": "یوزر منیجر دوم", "secondary": "میکروتیک فرعی", "linux": "لینوکس"}
STATE_FA = {"running": "✓", "active": "✓", "stopped": "✗ متوقف", "failed": "✗ خطا", "inactive": "✗"}
BOT_FIELDS = [("BOT_TOKEN", "توکن بات (از BotFather)"), ("ADMIN_IDS", "شناسه‌ی عددی ادمین‌ها (با کاما)"),
              ("USERNAME_PREFIX", "پیشوند نام یوزر جدید"), ("USERNAME_DIGITS", "تعداد رقم نام یوزر"),
              ("PASSWORD_LENGTH", "طول رمز یوزر"), ("STOCK_PREFIX", "فروش یوزرهای آماده با این پیشوند (خالی = همه)"),
              ("INVITE_TTL_HOURS", "اعتبار لینک دعوت (ساعت)"),
              ("REPORT_HOUR", "ساعت گزارش شبانه‌ی فروش (۰ تا ۲۳ یا off)")]


def fa(x):
    return str(x).translate(FA_DIGITS)


def human_size(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d %s" if unit == "B" else "%.1f %s") % (n, unit)
        n /= 1024


def ago(iso):
    try:
        t = _dt.datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return "هرگز"
    mins = int((_dt.datetime.now().astimezone() - t).total_seconds() // 60)
    if mins < 1:
        return "همین الان"
    if mins < 60:
        return "%s دقیقه پیش" % fa(mins)
    if mins < 48 * 60:
        return "%s ساعت پیش" % fa(mins // 60)
    return "%s روز پیش" % fa(mins // 1440)


def router_label(r):
    return "%s  (%s)" % (r.get("name") or r["id"], r["host"])


def linux_connector(r):
    def connect():
        return linux.LinuxHost(r["host"], r["port"], r["user"], r["password"], r.get("hostkey", "")).connect()
    return connect


def router_connector(r):
    def connect():
        return SSHRouter(r["host"], r["port"], r["user"], r["password"], r.get("hostkey", "")).connect()
    return connect


def connector_for(r):
    return linux_connector(r) if r.get("role") == "linux" else router_connector(r)


def pc_package(name, version):
    """A RouterOS package from mikrotik.com through this phone (when the router cannot download it)."""
    import io
    import urllib.request
    import zipfile
    url = "https://download.mikrotik.com/routeros/%s/all_packages-x86-%s.zip" % (version, version)
    try:
        with urllib.request.urlopen(url, timeout=300) as resp:
            data = resp.read()
    except OSError as e:
        raise pb.ReleaseError("دانلود پکیج‌ها از mikrotik.com ناموفق بود: %s" % e)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for n in z.namelist():
            if n.endswith("%s-%s.npk" % (name, version)):
                return z.read(n)
    raise pb.ReleaseError("پکیج %s در فایل mikrotik.com نبود." % name)


def workspace_dir():
    return os.path.join(st.APP_DIR, "workspace")


def tmp_dir():
    d = os.environ.get("FLET_APP_STORAGE_TEMP") or tempfile.gettempdir()
    os.makedirs(d, exist_ok=True)
    return tempfile.mkdtemp(prefix="pv-", dir=d)


def refresh(control):
    """update() that does nothing while the control is not on screen (another tab)."""
    try:
        control.update()
    except (RuntimeError, AttributeError):
        pass


class Cancel(Exception):
    """A step was cancelled or failed (and already reported)."""


# ====================================================================== small widgets

def title(text):
    return ft.Text(text, size=16, weight=ft.FontWeight.BOLD)


def hint(text):
    return ft.Text(text, size=12, color=ft.Colors.GREY_600)


def card(head, *controls):
    return ft.Card(content=ft.Container(padding=ft.Padding.all(14),
                                        content=ft.Column([title(head)] + list(controls), spacing=10)))


def ltr_field(label, value="", password=False, **kw):
    return ft.TextField(label=label, value=str(value or ""), password=password, can_reveal_password=password,
                        rtl=False, text_align=ft.TextAlign.LEFT, **kw)


def dropdown(label, items, value=None, on_select=None):
    """items: [(key, text)]"""
    d = ft.Dropdown(label=label, options=[ft.DropdownOption(key=k, text=t) for k, t in items],
                    value=value if value in [k for k, _ in items] else (items[0][0] if items else None),
                    expand=True, on_select=on_select)
    return d


class Panel:
    """Progress bar and log of one page; safe to feed from the worker thread."""

    def __init__(self, app, height=220):
        self.app = app
        self.bar = ft.ProgressBar(visible=False)
        self.lines = ft.ListView(spacing=2, auto_scroll=True, height=height)
        self.view = ft.Column([self.bar, self.lines], spacing=6)

    def _call(self, fn, *args):
        try:
            self.app.page.loop.call_soon_threadsafe(fn, *args)
        except (RuntimeError, AttributeError):
            pass

    def add(self, text):
        for line in str(text).splitlines() or [""]:
            self.lines.controls.append(ft.Text(line, size=12, selectable=True))
        del self.lines.controls[:-400]
        refresh(self.lines)

    def set_progress(self, done, total):
        if total:
            self.bar.value = min(1.0, done / total)
            refresh(self.bar)

    # from the worker thread
    def tlog(self, text):
        self._call(self.add, text)

    def tprogress(self, done, total):
        self._call(self.set_progress, done, total)

    def start(self, clear=True):
        if clear:
            self.lines.controls.clear()
        self.bar.value = None
        self.bar.visible = True
        refresh(self.view)

    def stop(self):
        self.bar.visible = False
        refresh(self.view)

    def clear(self):
        self.lines.controls.clear()
        refresh(self.lines)


# ====================================================================== the app

class App:
    def __init__(self, page):
        self.page = page
        self.settings = None
        self.busy = False
        self.pages = []

    # ------------------------------------------------------------ dialogs (awaitable)

    def _dialog(self, head, body, actions):
        fut = asyncio.get_running_loop().create_future()

        def close(value):
            def handler(e):
                self.page.pop_dialog()
                if not fut.done():
                    fut.set_result(value() if callable(value) else value)
            return handler
        buttons = [ft.TextButton(text, on_click=close(v)) if not primary else ft.FilledButton(text, on_click=close(v))
                   for text, v, primary in actions]
        dlg = ft.AlertDialog(modal=True, title=ft.Text(head),
                             content=ft.Column(body, tight=True, scroll=ft.ScrollMode.AUTO, width=520),
                             actions=buttons, actions_alignment=ft.MainAxisAlignment.END)
        self.page.show_dialog(dlg)
        return fut

    async def info(self, head, text):
        await self._dialog(head, [ft.Text(text, selectable=True)], [("باشه", True, True)])

    async def ask(self, head, text, yes="بله", no="خیر"):
        return await self._dialog(head, [ft.Text(text, selectable=True)], [(no, False, False), (yes, True, True)])

    async def choose(self, head, text, options):
        """options: [(key, label)]; None when cancelled."""
        return await self._dialog(head, [ft.Text(text)] if text else [],
                                  [("انصراف", None, False)] + [(label, key, True) for key, label in options])

    async def form(self, head, fields, note=None, ok="ذخیره"):
        """fields: [(key, label, value, kind)], kind: text|ltr|password|int|multiline|check|select:[(k,t)].
        Returns {key: value} or None."""
        widgets = {}
        body = [hint(note)] if note else []
        for key, label, value, kind in fields:
            if kind == "check":
                w = ft.Checkbox(label=label, value=bool(value))
            elif isinstance(kind, list):
                w = dropdown(label, kind, value)
            elif kind == "multiline":
                w = ft.TextField(label=label, value=value or "", multiline=True, min_lines=3, max_lines=8)
            elif kind == "text":
                w = ft.TextField(label=label, value=str(value or ""))
            else:
                w = ltr_field(label, value, password=(kind == "password"),
                              keyboard_type=ft.KeyboardType.NUMBER if kind == "int" else ft.KeyboardType.TEXT)
            widgets[key] = (w, kind)
            body.append(w)

        def values():
            out = {}
            for key, (w, kind) in widgets.items():
                v = w.value
                if kind == "int":
                    try:
                        v = int(str(v).strip())
                    except ValueError:
                        v = 0
                elif isinstance(v, str) and kind != "multiline":
                    v = v.strip()
                out[key] = v
            return out
        return await self._dialog(head, body, [("انصراف", None, False), (ok, values, True)])

    async def prompt(self, head, label, value="", password=False):
        res = await self.form(head, [("v", label, value, "password" if password else "ltr")], ok="تأیید")
        return None if res is None else res["v"]

    def toast(self, text):
        self.page.show_dialog(ft.SnackBar(content=ft.Text(text)))

    async def pick_file(self, extensions=None):
        """(name, bytes, path or None) of a picked file, or None."""
        files = await ft.FilePicker().pick_files(
            allow_multiple=False, with_data=True,
            file_type=ft.FilePickerFileType.CUSTOM if extensions else ft.FilePickerFileType.ANY,
            allowed_extensions=extensions)
        if not files:
            return None
        f = files[0]
        data = f.bytes
        if data is None and f.path:
            with open(f.path, "rb") as fh:
                data = fh.read()
        return f.name, data, f.path

    async def save_file(self, name, data):
        return await ft.FilePicker().save_file(file_name=name, src_bytes=data)

    # ------------------------------------------------------------ background work

    async def run(self, panel, job, clear=True):
        """job(log, progress) in a thread; errors are shown and raise Cancel."""
        if self.busy:
            await self.info("صبر کنید", "یک کار دیگر در حال اجراست.")
            raise Cancel()
        self.busy = True
        panel.start(clear)
        try:
            return await asyncio.to_thread(job, panel.tlog, panel.tprogress)
        except Cancel:
            raise
        except Exception as e:
            msg = str(e) or e.__class__.__name__
            if not isinstance(e, (pb.ReleaseError, OSError)) and e.__class__.__name__ not in ("RouterOSError", "LinuxError"):
                msg += "\n\n" + traceback.format_exc()[-1500:]
            panel.add("✗ " + msg)
            await self.info("خطا", msg)
            raise Cancel()
        finally:
            self.busy = False
            panel.stop()

    def guard(self, fn):
        """An async click handler that ends quietly on Cancel."""
        async def handler(e=None):
            try:
                await fn()
            except Cancel:
                pass
            self.page.update()
        return handler

    def button(self, text, fn, primary=False, icon=None):
        cls = ft.FilledButton if primary else ft.OutlinedButton
        return cls(text, icon=icon, on_click=self.guard(fn))

    # ------------------------------------------------------------ start

    def start(self):
        p = self.page
        p.title = "Persian Admin"
        p.rtl = True
        p.theme_mode = ft.ThemeMode.LIGHT
        p.theme = ft.Theme(color_scheme_seed=ft.Colors.INDIGO)
        p.padding = 0
        if st.has_app_password():
            self.show_lock()
        else:
            self.show_welcome()

    def _screen(self, *controls):
        p = self.page
        p.appbar = None
        p.navigation_bar = None
        p.controls.clear()
        p.add(ft.SafeArea(expand=True, content=ft.Container(
            padding=ft.Padding.all(20),
            content=ft.Column(list(controls), spacing=16, scroll=ft.ScrollMode.AUTO,
                              horizontal_alignment=ft.CrossAxisAlignment.STRETCH))))
        p.update()

    def show_lock(self):
        pw = ltr_field("رمز برنامه", password=True, autofocus=True)
        msg = ft.Text("", color=ft.Colors.RED)

        async def go(e=None):
            msg.value = "در حال باز کردن…"
            msg.color = ft.Colors.GREY_700
            self.page.update()
            ok = await asyncio.to_thread(st.unlock, pw.value or "")
            if not ok:
                msg.value = "رمز اشتباه است."
                msg.color = ft.Colors.RED
                self.page.update()
                return
            self.settings = st.Settings.load()
            self.show_main()
        pw.on_submit = go
        self._screen(ft.Icon(ft.Icons.LOCK, size=56), ft.Text("Persian Admin", size=24, weight=ft.FontWeight.BOLD,
                                                              text_align=ft.TextAlign.CENTER),
                     pw, ft.FilledButton("باز کردن", on_click=go), msg)

    def show_welcome(self):
        msg = ft.Text("")

        async def new_password():
            res = await self.form("رمز برنامه", [("a", "رمز برنامه (حداقل ۶ حرف)", "", "password"),
                                                 ("b", "تکرار رمز", "", "password")],
                                  note="هر بار که برنامه باز می‌شود این رمز را می‌خواهد. همه‌ی رمزها و کلیدها با آن "
                                       "قفل می‌شوند.", ok="ادامه")
            if res is None:
                raise Cancel()
            if len(res["a"]) < 6 or res["a"] != res["b"]:
                await self.info("رمز برنامه", "رمز حداقل ۶ حرف باشد و با تکرارش یکی باشد.")
                raise Cancel()
            return res["a"]

        async def from_file():
            picked = await self.pick_file()
            if not picked:
                return
            name, data, _ = picked
            pw = await self.prompt("فایل انتقال", "رمز فایل (همان که برنامه‌ی ویندوز نشان داد)", password=True)
            if not pw:
                return
            msg.value = "در حال باز کردن فایل…"
            self.page.update()
            try:
                content = await asyncio.to_thread(tb.read, data, pw)
            except pb.ReleaseError as e:
                msg.value = ""
                await self.info("خطا", str(e))
                return
            app_pw = await new_password()
            msg.value = "در حال ذخیره…"
            self.page.update()

            def apply():
                st.set_app_password(app_pw)
                s = st.Settings()
                return s, tb.apply(content, s, workspace_dir())
            self.settings, written = await asyncio.to_thread(apply)
            n = len(self.settings.routers)
            await self.info("انجام شد", "تنظیمات وارد شد: %s سرور و %s.\n\nحالا فایل انتقال را از تلگرام و کامپیوتر "
                                        "پاک کنید." % (fa(n), "، ".join(written) or "بدون فایل پوشه‌ی کاری"))
            self.show_main()

        async def empty():
            app_pw = await new_password()
            await asyncio.to_thread(st.set_app_password, app_pw)
            self.settings = st.Settings()
            self.settings.workspace = workspace_dir()
            os.makedirs(self.settings.workspace, exist_ok=True)
            self.settings.save()
            self.show_main()

        self._screen(
            ft.Icon(ft.Icons.PHONE_ANDROID, size=56),
            ft.Text("Persian Admin", size=24, weight=ft.FontWeight.BOLD, text_align=ft.TextAlign.CENTER),
            ft.Text("ابزار انتشار و مدیریت سرورها روی گوشی.\n\n"
                    "در برنامه‌ی ویندوز دکمه‌ی «📱 انتقال به گوشی» را بزنید، فایل ساخته‌شده را به گوشی بفرستید "
                    "(مثلاً تلگرام) و این‌جا واردش کنید. رمز فایل را همان برنامه نشان می‌دهد."),
            self.button("وارد کردن فایل انتقال از ویندوز", from_file, primary=True, icon=ft.Icons.FILE_OPEN),
            self.button("شروع بدون فایل (تنظیم دستی)", empty),
            msg)

    def show_main(self):
        p = self.page
        p.controls.clear()
        self.pages = [PublishPage(self), ServersPage(self), ServicesPage(self), NewServerPage(self),
                      MonitorPage(self)]
        self.body = ft.Container(expand=True, padding=ft.Padding.symmetric(horizontal=12, vertical=8))
        self.features_btn = ft.IconButton(ft.Icons.SYSTEM_UPDATE, tooltip="امکانات جدید",
                                          on_click=self.guard(lambda: self.features(False)))
        p.appbar = ft.AppBar(title=ft.Text("Persian Admin"), actions=[
            self.features_btn,
            ft.IconButton(ft.Icons.SETTINGS, tooltip="تنظیمات", on_click=self.guard(self.open_settings))])
        p.navigation_bar = ft.NavigationBar(
            selected_index=0, on_change=lambda e: self.select(e.control.selected_index),
            destinations=[ft.NavigationBarDestination(icon=ft.Icons.ROCKET_LAUNCH, label="انتشار"),
                          ft.NavigationBarDestination(icon=ft.Icons.BACKUP, label="سرورها"),
                          ft.NavigationBarDestination(icon=ft.Icons.HUB, label="سرویس‌ها"),
                          ft.NavigationBarDestination(icon=ft.Icons.ADD, label="سرور جدید"),
                          ft.NavigationBarDestination(icon=ft.Icons.MONITOR_HEART, label="وضعیت")])
        p.add(ft.SafeArea(expand=True, content=self.body))
        self.select(0)
        p.run_task(self._quiet_features)

    def select(self, i):
        self.current = self.pages[i]
        self.current.reload()
        self.body.content = ft.Column([self.current.view], scroll=ft.ScrollMode.AUTO, expand=True)
        self.page.update()

    def refresh_all(self):
        for pg in self.pages:
            pg.reload()
        self.page.update()

    # ------------------------------------------------------------ settings

    async def open_settings(self):
        s = self.settings
        res = await self.form("تنظیمات", [
            ("repo", "مخزن GitHub", s.repo, "ltr"),
            ("public_repo", "مخزن عمومی پشتیبان (خالی = بدون پشتیبان)", s.public_repo, "ltr"),
            ("testers", "یوزرهای تست (با کاما)", "، ".join(s.testers), "ltr"),
            ("token", "توکن GitHub", s.token, "password"),
            ("backup_repo", "مخزن خصوصی بکاپ روترها", s.backup_repo, "ltr"),
            ("bpass", "رمز بکاپ", s.backup_password, "password"),
            ("bpass2", "تکرار رمز بکاپ", s.backup_password, "password")])
        if res is None:
            return
        if res["bpass"] != res["bpass2"]:
            return await self.info("خطا", "رمز بکاپ و تکرارش یکی نیستند.")
        if res["bpass"] and len(res["bpass"]) < 10:
            return await self.info("خطا", "رمز بکاپ حداقل ۱۰ حرف باشد.")
        if s.backup_password and res["bpass"] != s.backup_password and not await self.ask(
                "تأیید", "رمز بکاپ عوض می‌شود. بکاپ‌های قبلی فقط با رمز قبلی باز می‌شوند. ادامه؟"):
            return
        s.repo, s.public_repo, s.token = res["repo"], res["public_repo"], res["token"]
        s.backup_repo, s.backup_password = res["backup_repo"], res["bpass"]
        s.testers = [t.strip() for t in re.split(r"[,،\s]+", res["testers"]) if t.strip()]
        s.save()
        self.refresh_all()
        self.toast("ذخیره شد")

    # ------------------------------------------------------------ new features (only the changed code)

    async def _quiet_features(self):
        await asyncio.sleep(3)
        try:
            await self.features(True)
        except Exception:
            pass

    async def features(self, silent):
        s = self.settings
        if not (s.token and s.repo):
            if not silent:
                await self.info("امکانات جدید", "اول توکن GitHub را در تنظیمات وارد کنید.")
            return

        def check():
            up = su.Updater(s.token, s.repo)
            return up, up.check()
        try:
            up, plan = await asyncio.to_thread(check)
        except su.UpdateError as e:
            if not silent:
                await self.info("امکانات جدید", str(e))
            return
        if silent:
            if not plan.up_to_date and not plan.needs_new_exe:
                self.features_btn.icon_color = ft.Colors.GREEN
                self.features_btn.tooltip = "امکانات جدید آماده است"
                refresh(self.features_btn)
                self.toast("امکانات جدید آماده است (دکمه‌ی سبز بالا)")
            return
        if plan.needs_new_exe:
            return await self.info("امکانات جدید", "نسخه‌ی جدید به نصب دوباره‌ی برنامه نیاز دارد: فایل "
                                   "Persian-Admin را از GitHub (Actions ← Admin app (Android)) بگیرید و نصب کنید.")
        if plan.up_to_date:
            return await self.info("امکانات جدید", "برنامه به‌روز است (%s)." % su.version_text())
        what = "%s فایل، حدود %s کیلوبایت" % (fa(len(plan.changes)), fa(max(1, plan.size // 1024)))
        if not await self.ask("امکانات جدید", "نسخه‌ی جدید آماده است%s: %s.\nدریافت شود؟"
                              % (" (#%s)" % fa(plan.run) if plan.run else "", what)):
            return
        try:
            await asyncio.to_thread(up.apply, plan, lambda *_: None)
        except (su.UpdateError, OSError) as e:
            return await self.info("امکانات جدید", "دریافت ناموفق بود: %s" % e)
        await self.info("امکانات جدید", "دریافت شد. برنامه بسته می‌شود؛ دوباره بازش کنید.")
        os._exit(0)

    # ------------------------------------------------------------ shared choices

    def routers(self, roles=None):
        return [r for r in self.settings.routers if roles is None or r.get("role") in roles]

    def router_items(self, roles=None):
        return [(r["id"], router_label(r)) for r in self.routers(roles)]

    def github_clients(self, use_github=True):
        s = self.settings
        if not use_github or not s.token:
            return None, None
        gh = pb.GitHubClient(s.token, s.repo)
        public = pb.GitHubClient(s.token, s.public_repo) if s.public_repo else None
        return gh, public

    def workspace(self):
        return pb.Workspace(self.settings.workspace or workspace_dir())


# ====================================================================== publish

class PublishPage:
    def __init__(self, app):
        self.app = app
        self.build = None
        self.panel = Panel(app)
        self.status = hint("")
        self.build_text = ft.Text("فایلی انتخاب نشده")
        self.code = ltr_field("شماره‌ی نسخه", keyboard_type=ft.KeyboardType.NUMBER, expand=True,
                              on_change=self._code_changed)
        self.name = ltr_field("نام نسخه", expand=True)
        self.notes = ft.TextField(label="توضیحات نسخه (به کاربرها نمایش داده می‌شود)", multiline=True,
                                  min_lines=2, max_lines=5)
        self.chk_router = ft.Checkbox(label="ارسال به روتر", value=True)
        self.chk_github = ft.Checkbox(label="به‌روزرسانی GitHub", value=True)
        self.chk_beta = ft.Checkbox(label="🧪 آزمایشی: اول فقط برای یوزرهای تست", value=True)
        self.beta_info = ft.Text("")
        self.btn_promote = app.button("✅ انتشار عمومی آزمایشی اندروید", lambda: self.promote(False))
        self.btn_promote_win = app.button("✅ انتشار عمومی آزمایشی ویندوز", lambda: self.promote(True))
        self.beta_box = ft.Column([self.beta_info, self.btn_promote, self.btn_promote_win], visible=False)
        self.btn_go = app.button("امضا و انتشار", self.publish, primary=True, icon=ft.Icons.PUBLISH)
        self.view = ft.Column([
            self.status,
            card("۱. فایل برنامه", self.build_text,
                 ft.Row([app.button("دریافت آخرین بیلد از GitHub", self.fetch_latest, icon=ft.Icons.CLOUD_DOWNLOAD),
                         app.button("انتخاب فایل", self.pick_build, icon=ft.Icons.UPLOAD_FILE)], wrap=True),
                 ft.Row([self.code, self.name])),
            card("۲. توضیحات", self.notes),
            card("۳. انتشار", ft.Row([self.chk_router, self.chk_github], wrap=True), self.chk_beta, self.beta_box,
                 self.btn_go,
                 app.button("⇄ انتشار فقط تنظیمات سرور", self.publish_config_only),
                 app.button("🖥 انتشار نسخه‌ی ویندوز", self.publish_windows),
                 self.panel.view)], spacing=10)

    def _code_changed(self, e):
        v = (self.code.value or "").strip()
        if v.isdigit():
            self.name.value = "1.0.%s" % v
            refresh(self.name)

    def reload(self):
        ws = self.app.workspace()
        try:
            ws.check()
            last = ws.published_version_code()
            self.status.value = "آخرین نسخه‌ی منتشرشده: %s" % (fa(last) if last else "—")
            if not self.build and (not self.code.value or int(self.code.value or 0) <= last):
                self.code.value = str(last + 1)
                self.name.value = "1.0.%d" % (last + 1)
        except (pb.ReleaseError, ValueError) as e:
            self.status.value = "⚠ " + str(e)
        has_token = bool(self.app.settings.token)
        self.chk_github.disabled = not has_token
        if not has_token:
            self.chk_github.value = False
        try:
            beta, wbeta = pb.beta_status(ws)
        except (pb.ReleaseError, OSError, ValueError):
            beta = wbeta = None
        parts = []
        if beta:
            parts.append("اندروید %s" % fa(beta.get("version_name") or beta["version_code"]))
        if wbeta:
            parts.append("ویندوز %s" % fa(wbeta["version_code"]))
        self.beta_box.visible = bool(parts)
        self.beta_info.value = "🧪 در حال تست (فقط یوزرهای تست): %s" % "، ".join(parts)
        self.btn_promote.visible = bool(beta)
        self.btn_promote_win.visible = bool(wbeta)
        self.btn_go.disabled = self.build is None

    def set_build(self, build):
        self.build = build
        self.build_text.value = "✓ %s  (%s)" % (build.source, human_size(len(build.apk)))
        if build.version_code:
            self.code.value = str(build.version_code)
            self.name.value = "1.0.%d" % build.version_code
        self.panel.add("فایل بارگذاری شد: %s" % build.source)
        self.reload()

    async def fetch_latest(self):
        s = self.app.settings
        if not s.token:
            return await self.app.info("GitHub", "اول توکن GitHub را در تنظیمات وارد کنید.")
        gh = pb.GitHubClient(s.token, s.repo)
        tmp = tmp_dir()

        def job(log, progress):
            found = gh.latest_build()
            if not found:
                raise pb.ReleaseError("هیچ بیلد قابل‌دانلودی در GitHub پیدا نشد.")
            n, art = found
            log("دانلود بیلد %s…" % fa(n))
            return pb.read_build(gh.download_artifact(art, tmp, progress))
        self.set_build(await self.app.run(self.panel, job))

    async def pick_build(self):
        picked = await self.app.pick_file(["zip", "apk"])
        if not picked:
            return
        name, data, path = picked
        if not path or not os.path.isfile(path):
            path = os.path.join(tmp_dir(), name)
            with open(path, "wb") as f:
                f.write(data)
        try:
            self.set_build(pb.read_build(path))
        except (pb.ReleaseError, OSError) as e:
            await self.app.info("خطا", str(e))

    async def testers_or_none(self):
        if not self.chk_beta.value:
            if not await self.app.ask("انتشار عمومی", "تیک «آزمایشی» برداشته شده: این نسخه همین الان برای همه‌ی "
                                                      "کاربران منتشر می‌شود.\nادامه؟"):
                raise Cancel()
            return None
        if not self.app.settings.testers:
            await self.app.info("یوزرهای تست", "اول یوزرهای تست (مثلاً یوزر خودتان) را در ⚙ تنظیمات وارد کنید.")
            raise Cancel()
        return list(self.app.settings.testers)

    def _sync(self, ws, log, progress):
        """Patches are made from the published APKs: fetch them from the router if this phone lacks them."""
        try:
            pb.sync_workspace(ws, log, progress)
        except (pb.ReleaseError, OSError) as e:
            log("⚠ دریافت فایل‌های قبلی از روتر نشد (وصله‌ی کوچک ساخته نمی‌شود): %s" % e)

    async def publish(self):
        if not self.build:
            return
        try:
            code = int(self.code.value)
        except (TypeError, ValueError):
            return await self.app.info("خطا", "شماره‌ی نسخه عدد باشد.")
        name = (self.name.value or "").strip()
        if self.build.version_code and code != self.build.version_code and not await self.app.ask(
                "تأیید", "شماره‌ی نسخه (%s) با شماره‌ی فایل بیلد (%s) یکی نیست.\nاگر یکی نباشند، گوشی‌ها فایل را "
                         "رد می‌کنند. ادامه؟" % (fa(code), fa(self.build.version_code))):
            return
        testers = await self.testers_or_none()
        github, public = self.app.github_clients(self.chk_github.value)
        ws, build, notes, send_router = self.app.workspace(), self.build, self.notes.value or "", self.chk_router.value

        def job(log, progress):
            self._sync(ws, log, progress)
            return pb.release(ws, build, code, name, notes, send_router=send_router, github=github,
                              public_github=public, log=log, progress=progress, testers=testers)
        cfg = await self.app.run(self.panel, job)
        self.build = None
        self.build_text.value = "فایلی انتخاب نشده"
        self.notes.value = ""
        self.reload()
        if testers is not None:
            v = fa(cfg["app_update_beta"]["version_name"])
            self.panel.add("✓ نسخه‌ی آزمایشی %s منتشر شد (فقط برای: %s)." % (v, "، ".join(testers)))
            return await self.app.info("نسخه‌ی آزمایشی", "نسخه‌ی %s فقط برای یوزرهای تست منتشر شد.\nروی گوشی "
                                       "برنامه‌ی VPN را باز کنید و به‌روزرسانی «آزمایشی» را نصب کنید.\nاگر سالم بود، "
                                       "«✅ انتشار عمومی آزمایشی اندروید» را بزنید." % v)
        self.panel.add("✓ انتشار نسخه‌ی %s کامل شد." % fa(cfg["app_update"]["version_name"]))
        if cfg.get("_public_failed"):
            await self.app.info("هشدار", "نسخه منتشر شد، ولی مخزن عمومی پشتیبان به‌روز نشد:\n%s"
                                % cfg["_public_failed"])
        await self.app.info("انجام شد", "نسخه‌ی %s منتشر شد." % fa(cfg["app_update"]["version_name"]))

    async def publish_windows(self):
        ws = self.app.workspace()
        try:
            ws.check()
        except (pb.ReleaseError, OSError) as e:
            return await self.app.info("خطا", str(e))
        how = await self.app.choose("انتشار نسخه‌ی ویندوز", "آخرین نسخه‌ی اپ ویندوز از کجا گرفته شود؟",
                                    [("file", "انتخاب فایل zip"), ("gh", "دریافت از GitHub")])
        if how is None:
            return
        if how == "file":
            picked = await self.app.pick_file(["zip"])
            if not picked:
                return
            name, data, path = picked
            if not path or not os.path.isfile(path):
                path = os.path.join(tmp_dir(), name)
                with open(path, "wb") as f:
                    f.write(data)
            try:
                win = pb.read_windows_build(path)
            except pb.ReleaseError as e:
                return await self.app.info("خطا", str(e))
        else:
            s = self.app.settings
            if not (s.token and s.repo):
                return await self.app.info("خطا", "برای دریافت از GitHub، توکن و نام مخزن را در تنظیمات وارد کنید.")
            gh, tmp = pb.GitHubClient(s.token, s.repo), tmp_dir()

            def fetch(log, progress):
                art = gh.latest_windows()
                if not art:
                    raise pb.ReleaseError("نسخه‌ی ویندوزی در GitHub پیدا نشد (یا قدیمی و پاک شده است).")
                log("دانلود اپ ویندوز از GitHub…")
                return pb.read_windows_build(gh.download_artifact(art, tmp, progress))
            win = await self.app.run(self.panel, fetch)
        try:
            now = int((ws.load_config().get("windows_update") or {}).get("version_code", 0))
        except (pb.ReleaseError, OSError, ValueError):
            now = 0
        if now and win.version_code <= now and not await self.app.ask(
                "نسخه‌ی ویندوز", "نسخه‌ی %s همین الان منتشر شده است (آخرین روی GitHub: %s).\nدوباره منتشر شود؟"
                % (fa(now), fa(win.version_code))):
            return
        res = await self.app.form("نسخه‌ی ویندوز %s" % fa(win.version_code),
                                  [("notes", "توضیح تغییرات (اختیاری)", "", "multiline")],
                                  note="نسخه‌ی منتشرشده‌ی فعلی: %s" % (fa(now) if now else "—"), ok="انتشار")
        if res is None:
            return
        testers = await self.testers_or_none()
        github, public = self.app.github_clients(self.chk_github.value)
        send_router = self.chk_router.value

        def job(log, progress):
            self._sync(ws, log, progress)
            return pb.release_config_only(ws, send_router=send_router, github=github, public_github=public,
                                          log=log, progress=progress, win=win, win_notes=res["notes"],
                                          win_testers=testers)
        cfg = await self.app.run(self.panel, job, clear=False)
        self.reload()
        if testers is not None:
            return await self.app.info("نسخه‌ی آزمایشی", "نسخه‌ی ویندوز %s فقط برای یوزرهای تست منتشر شد.\nاگر سالم "
                                       "بود، «✅ انتشار عمومی آزمایشی ویندوز» را بزنید." % fa(win.version_code))
        await self.app.info("انجام شد", "نسخه‌ی ویندوز منتشر شد (تنظیمات %s)." % fa(cfg["version"]))

    async def promote(self, windows):
        what = "ویندوز" if windows else "اندروید"
        if not await self.app.ask("انتشار عمومی", "نسخه‌ی آزمایشی %s، همان فایلی که تست کردید، برای همه‌ی کاربران "
                                                  "منتشر شود؟" % what):
            return
        github, public = self.app.github_clients(self.chk_github.value)
        ws, send_router = self.app.workspace(), self.chk_router.value
        fn = pb.promote_win_beta if windows else pb.promote_beta

        def job(log, progress):
            self._sync(ws, log, progress)
            return fn(ws, send_router=send_router, github=github, public_github=public, log=log, progress=progress)
        await self.app.run(self.panel, job)
        self.reload()
        await self.app.info("انجام شد", "نسخه‌ی %s برای همه‌ی کاربران منتشر شد." % what)

    async def publish_config_only(self):
        ws = self.app.workspace()
        try:
            ws.check()
            cfg = ws.load_config()
        except (pb.ReleaseError, OSError, ValueError) as e:
            return await self.app.info("خطا", str(e))
        servers = "\n".join("• %s  (%s:%s)" % (s.get("name", ""), s.get("host", ""), s.get("port", 443))
                            for s in cfg.get("servers", []))
        send_router = self.chk_router.value
        github, public = self.app.github_clients(self.chk_github.value)
        if not send_router and github is None:
            return await self.app.info("خطا", "حداقل یکی از «ارسال به روتر» یا «به‌روزرسانی GitHub» را انتخاب کنید.")
        if not await self.app.ask("تأیید", "این سرورها از config.json برای همه‌ی کاربران منتشر می‌شوند:\n\n%s\n\n"
                                           "ادامه؟" % (servers or "(خالی!)")):
            return

        def job(log, progress):
            self._sync(ws, log, progress)
            return pb.release_config_only(ws, send_router=send_router, github=github, public_github=public,
                                          log=log, progress=progress)
        cfg = await self.app.run(self.panel, job)
        self.reload()
        await self.app.info("انجام شد", "تنظیمات جدید (نسخه‌ی %s) منتشر شد." % fa(cfg["version"]))


# ====================================================================== servers and backups

class ServersPage:
    def __init__(self, app):
        self.app = app
        self.panel = Panel(app, height=180)
        self.list = ft.Column(spacing=4)
        self.selected = None
        self.backups = ft.Column(spacing=2)
        self.view = ft.Column([
            card("سرورها و روترها", hint("روی هر مورد بزنید تا انتخاب شود."), self.list,
                 ft.Row([app.button("＋ افزودن", self.add), app.button("ویرایش", self.edit),
                         app.button("حذف", self.delete), app.button("بررسی اتصال", self.test)], wrap=True)),
            card("بکاپ", ft.Row([app.button("بکاپ از همه", lambda: self.backup(False), primary=True),
                                 app.button("بکاپ از همین مورد", lambda: self.backup(True))], wrap=True),
                 self.backups, app.button("بررسی آخرین بکاپ این مورد", self.verify)),
            card("تنظیمات برنامه",
                 ft.Row([app.button("خروجی تنظیمات", self.export_tool), app.button("وارد کردن دوباره", self.import_tool),
                         app.button("تغییر رمز برنامه", self.change_password)], wrap=True)),
            self.panel.view], spacing=10)

    def current(self):
        return self.app.settings.router(self.selected) if self.selected else None

    def reload(self):
        s = self.app.settings
        status = st.load_status()
        if not self.current() and s.routers:
            self.selected = s.routers[0]["id"]
        self.list.controls.clear()
        for r in s.routers:
            stt = status.get(r["id"], {})
            mark = "✓" if stt.get("ok") else ("✗" if stt else "•")
            sel = r["id"] == self.selected
            self.list.controls.append(ft.ListTile(
                selected=sel, leading=ft.Icon(ft.Icons.ROUTER if r.get("role") != "linux" else ft.Icons.DNS),
                title=ft.Text("%s %s" % (mark, r.get("name") or r["id"])),
                subtitle=ft.Text("%s:%s — %s — بکاپ: %s" % (r["host"], fa(r.get("port", 22)),
                                                           dict(ROLES).get(r.get("role"), ""), ago(stt.get("last_ok")))),
                on_click=self._select(r["id"])))
        if not s.routers:
            self.list.controls.append(hint("هنوز سروری تعریف نشده است."))
        self.backups.controls.clear()
        r = self.current()
        if r:
            names = bk.LocalStore(s.backup_dir()).list(r["id"])
            for name in names[:6]:
                self.backups.controls.append(ft.Text(name, size=12, selectable=True))
            if not names:
                self.backups.controls.append(hint("بکاپی روی این گوشی نیست."))

    def _select(self, rid):
        def handler(e):
            self.selected = rid
            self.reload()
            self.app.page.update()
        return handler

    async def router_form(self, r):
        res = await self.app.form("مشخصات", [
            ("name", "نام (برای خودتان)", r.get("name", ""), "text"),
            ("role", "نقش", r.get("role") or "main", ROLES),
            ("host", "آدرس (IP یا دامنه)", r.get("host", ""), "ltr"),
            ("port", "پورت SSH", r.get("port") or 22, "int"),
            ("user", "نام کاربری", r.get("user") or "pvtool", "ltr"),
            ("password", "رمز", r.get("password", ""), "password")],
            note="روتر: /user add name=pvtool group=full password=…   سرور لینوکس: کاربر root و رمز آن.")
        if res is None:
            return None
        if not res["host"] or not res["password"]:
            await self.app.info("خطا", "آدرس و رمز لازم است.")
            return None
        out = dict(r)
        if r.get("host") and r["host"] != res["host"]:
            out["hostkey"] = ""
        out.update(res, port=res["port"] or 22)
        return out

    async def add(self):
        s = self.app.settings
        r = await self.router_form({"id": s.new_router_id(), "role": "secondary" if s.routers else "main"})
        if r:
            s.routers.append(r)
            s.save()
            self.selected = r["id"]
            self.reload()

    async def edit(self):
        r = self.current()
        if not r:
            return
        new = await self.router_form(r)
        if new:
            r.update(new)
            self.app.settings.save()
            self.reload()

    async def delete(self):
        r = self.current()
        if r and await self.app.ask("تأیید", "«%s» از لیست حذف شود؟ (بکاپ‌هایش پاک نمی‌شوند)" % router_label(r)):
            self.app.settings.routers.remove(r)
            self.app.settings.save()
            self.selected = None
            self.reload()

    async def test(self):
        r = self.current()
        if not r:
            return
        cfg = dict(r)

        def job(log, progress):
            log("اتصال به %s:%s…" % (cfg["host"], cfg["port"]))
            if cfg.get("role") == "linux":
                with linux.LinuxHost(cfg["host"], cfg["port"], cfg["user"], cfg["password"], cfg.get("hostkey", "")) as c:
                    return c.seen_hostkey, c.run(". /etc/os-release; echo $PRETTY_NAME").strip(), c.run("hostname").strip()
            with SSHRouter(cfg["host"], cfg["port"], cfg["user"], cfg["password"], cfg.get("hostkey", "")) as c:
                res = c.run("/system resource print")
                ident = c.run("/system identity print")
                return c.seen_hostkey, "RouterOS " + bk.parse_version(res), ident.split(":", 1)[-1].strip()
        key, ver, ident = await self.app.run(self.panel, job)
        if not r.get("hostkey"):
            if not await self.app.ask("کلید SSH", "اولین اتصال به این سرور.\nاثر انگشت کلید SSH:\n%s\n\nاگر مطمئن "
                                                  "هستید همان سرور شماست، تأیید کنید." % key):
                return
            r["hostkey"] = key
            self.app.settings.save()
        self.panel.add("✓ %s: %s (%s)" % (r.get("name") or r["host"], ver, ident))

    async def backup(self, only_selected):
        s = self.app.settings
        if not s.backup_password:
            return await self.app.info("خطا", "اول رمز بکاپ را در ⚙ تنظیمات بگذارید.")
        only = None
        if only_selected:
            r = self.current()
            if not r:
                return
            only = {r["id"]}
        results = await self.app.run(self.panel, lambda log, progress: bk.backup_all(s, log, progress, only=only))
        self.reload()
        bad = [x for x in results.values() if not x["ok"]]
        if bad:
            return await self.app.info("خطا", "\n\n".join(x["error"] for x in bad))
        no_gh = [x for x in results.values() if x["ok"] and not x.get("github")]
        await self.app.info("انجام شد", "بکاپ کامل شد." + ("\nبه GitHub فرستاده نشد (توکن یا مخزن بکاپ)." if no_gh else ""))

    async def verify(self):
        r = self.current()
        if not r:
            return
        store = bk.LocalStore(self.app.settings.backup_dir())
        names = store.list(r["id"])
        if not names:
            return await self.app.info("بکاپ", "بکاپی از این مورد روی گوشی نیست.")
        path, password = os.path.join(store.dir(r["id"]), names[0]), self.app.settings.backup_password
        m, parts = await self.app.run(self.panel, lambda log, progress: bk.open_backup(path, password))
        files = [p for p in parts if p.startswith("files/")]
        self.panel.add("\n".join([
            "✓ بکاپ %s سالم است و با رمز فعلی باز می‌شود." % names[0],
            "روتر: %s (%s) — RouterOS %s" % (m.get("router_name", ""), m.get("host", ""), m.get("routeros", "")),
            "تنظیمات کامل: %s   یوزر منیجر: %s   فایل‌ها: %s" % (
                "✓" if "export.rsc" in parts else "✗", "✓" if any(p.startswith("um/") for p in parts) else "—",
                fa(len(files)))]))

    async def export_tool(self):
        pw = await self.app.prompt("خروجی تنظیمات", "رمز فایل (حداقل ۱۰ حرف)", password=True)
        if not pw:
            return
        if len(pw) < 10:
            return await self.app.info("خطا", "رمز حداقل ۱۰ حرف باشد.")
        blob = await asyncio.to_thread(tb.export_bytes, self.app.settings, pw)
        where = await self.app.save_file("persian-vpn-tool-%s%s" % (bk.stamp(), bk.EXT), blob)
        if where:
            await self.app.info("انجام شد", "خروجی ذخیره شد. این فایل کلید امضا و همه‌ی رمزها را دارد.")

    async def import_tool(self):
        picked = await self.app.pick_file()
        if not picked:
            return
        pw = await self.app.prompt("وارد کردن تنظیمات", "رمز فایل", password=True)
        if not pw:
            return
        try:
            data = await asyncio.to_thread(tb.read, picked[1], pw)
        except pb.ReleaseError as e:
            return await self.app.info("خطا", str(e))
        if not await self.app.ask("تأیید", "تنظیمات فعلی با محتوای فایل (ساخته‌شده در %s، %s سرور) جایگزین می‌شود. "
                                           "ادامه؟" % (data.get("created", "?"), fa(len(data["settings"].get("routers", []))))):
            return
        written = await asyncio.to_thread(tb.apply, data, self.app.settings, workspace_dir())
        self.app.refresh_all()
        await self.app.info("انجام شد", "تنظیمات وارد شد (%s)." % ("، ".join(written) or "بدون فایل پوشه‌ی کاری"))

    async def change_password(self):
        res = await self.app.form("تغییر رمز برنامه", [("a", "رمز جدید (حداقل ۶ حرف)", "", "password"),
                                                       ("b", "تکرار", "", "password")])
        if res is None:
            return
        if len(res["a"]) < 6 or res["a"] != res["b"]:
            return await self.app.info("خطا", "رمز حداقل ۶ حرف باشد و با تکرارش یکی باشد.")
        s = self.app.settings

        def change():
            blobs = [st.decrypt_blob(r.get("params")) if r.get("params") else None for r in s.routers]
            st.set_app_password(res["a"])
            for r, p in zip(s.routers, blobs):
                if p is not None:
                    r["params"] = st.encrypt_blob(p)
            s.save()
        await asyncio.to_thread(change)
        self.app.toast("رمز برنامه عوض شد")


# ====================================================================== services

class ServicesPage:
    def __init__(self, app):
        self.app = app
        self.panel = Panel(app)
        self.target = dropdown("روتر اصلی", [])
        self.um2 = dropdown("روتر دوم", [])
        self.bt = dropdown("سرور لینوکس", [])
        self.bot_state = ft.Text("")
        self.bt_state = ft.Text("")
        b = app.button
        self.view = ft.Column([
            card("روتر", ft.Row([self.target])),
            card("سرویس وضعیت (umstatus)",
                 hint("نسخه‌ی همراه برنامه و کلید عمومی امضا را روی روتر می‌گذارد و سرویس را دوباره راه می‌اندازد."),
                 b("به‌روزرسانی umstatus", self.update_umstatus)),
            card("بات تلگرام", self.bot_state,
                 ft.Row([b("وضعیت و گزارش", self.bot_refresh), b("راه‌اندازی دوباره", self.bot_restart),
                         b("تنظیمات بات", self.bot_settings), b("به‌روزرسانی کد از GitHub", self.bot_update)], wrap=True),
                 b("نصب بات روی روتر / انتقال دیتابیس", self.bot_install, primary=True)),
            card("یوزر منیجر دوم (پشتیبان)", ft.Row([self.um2]),
                 hint("دیتابیس یوزر منیجر روتر اصلی هر ۵ دقیقه روی این روتر کپی می‌شود."),
                 b("راه‌اندازی / تازه کردن همگام‌سازی", self.setup_um2)),
            card("تانل پشتیبان SSTP (AmneziaWG)", ft.Row([self.bt]),
                 hint("ترافیک SSTP از GRE می‌رود؛ اگر GRE قطع شد خودکار از AmneziaWG به سرور لینوکس می‌رود."),
                 self.bt_state,
                 ft.Row([b("بررسی و راه‌اندازی", self.backup_setup, primary=True), b("وضعیت", self.backup_status),
                         b("برداشتن", self.backup_remove)], wrap=True)),
            self.panel.view], spacing=10)

    def _fill(self, d, roles):
        items = self.app.router_items(roles)
        d.options = [ft.DropdownOption(key=k, text=t) for k, t in items]
        if d.value not in [k for k, _ in items]:
            d.value = items[0][0] if items else None

    def reload(self):
        self._fill(self.target, None)
        main = next((r for r in self.app.routers(("main",))), None)
        if main and not self.target.value:
            self.target.value = main["id"]
        self._fill(self.um2, ("um2",))
        self._fill(self.bt, ("linux",))

    async def chosen(self, d, what):
        r = self.app.settings.router(d.value) if d.value else None
        if not r:
            await self.app.info("انتخاب", "اول در «سرورها» %s را تعریف کنید." % what)
            raise Cancel()
        return r

    async def update_umstatus(self):
        r = await self.chosen(self.target, "روتر اصلی")
        key = None
        try:
            with open(self.app.workspace().path("config_key.public.txt"), "rb") as f:
                key = f.read()
        except OSError:
            pass

        def job(log, progress):
            with router_connector(r)() as c:
                sv.update_umstatus(c, key, log)
        await self.app.run(self.panel, job)
        await self.app.info("انجام شد", "umstatus به‌روز شد.")

    async def bot_refresh(self):
        r = await self.chosen(self.target, "روتر اصلی")

        def job(log, progress):
            with router_connector(r)() as c:
                return sv.bot_status(c)
        stt, lines = await self.app.run(self.panel, job)
        names = {"running": "در حال اجرا ✓", "stopped": "متوقف", "none": "نصب نشده"}
        self.bot_state.value = "وضعیت بات: " + names.get(stt, stt)
        self.panel.add("\n".join(lines[-40:]) or "(گزارشی نیست)")

    async def bot_restart(self):
        r = await self.chosen(self.target, "روتر اصلی")

        def job(log, progress):
            with router_connector(r)() as c:
                sv.restart(c, sv.UMBOT, log)
        await self.app.run(self.panel, job)
        await self.bot_refresh()

    async def bot_form(self, values, head="تنظیمات بات"):
        res = await self.app.form(head, [(k, label, values.get(k, dict(sv.BOT_DEFAULTS).get(k, "")),
                                          "password" if k == "BOT_TOKEN" else "ltr") for k, label in BOT_FIELDS])
        if res is None:
            raise Cancel()
        merged = dict(values, **res)
        try:
            sv.check_bot_values(merged)
        except pb.ReleaseError as e:
            await self.app.info("خطا", str(e))
            raise Cancel()
        return merged

    async def bot_settings(self):
        r = await self.chosen(self.target, "روتر اصلی")

        def get(log, progress):
            with router_connector(r)() as c:
                return sv.bot_values(c)
        values = await self.bot_form(await self.app.run(self.panel, get))

        def save(log, progress):
            with router_connector(r)() as c:
                port = sv.ensure_rest(c, log)
                env = sv.parse_env(sv.file_text(c, "umbot/.env") or "")
                c.put("umbot/.env", sv.render_env(values, port, env.get("MT_PASSWORD", "")))
                sv.restart(c, sv.UMBOT, log)
        await self.app.run(self.panel, save, clear=False)
        await self.app.info("انجام شد", "تنظیمات بات ذخیره شد.")

    async def bot_update(self):
        r = await self.chosen(self.target, "روتر اصلی")
        token = self.app.settings.token
        status = linux.bot_linux_status(self.app.settings.routers)

        def job(log, progress):
            log("دریافت کد بات از GitHub…")
            code = sv.download_bot_code(token)
            with router_connector(r)() as c:
                sv.install_bot(c, code, {"LINUX_STATUS": status}, log=log)
        await self.app.run(self.panel, job)
        await self.app.info("انجام شد", "کد بات به‌روز شد.")

    async def bot_install(self):
        r = await self.chosen(self.target, "روتر اصلی")
        values = {}
        if await self.app.ask("فایل .env", "فایل .env بات قبلی (از سرور ویندوز) را دارید؟", yes="انتخاب فایل",
                              no="ندارم"):
            picked = await self.app.pick_file()
            if picked:
                values = sv.parse_env(picked[1].decode("utf-8-sig", "replace"))
        values = await self.bot_form(values, "تنظیمات بات روی روتر")
        db = None
        if await self.app.ask("دیتابیس بات", "دیتابیس بات قبلی (umbot.sqlite3) را منتقل می‌کنید؟\n(برای بات تازه "
                                              "«خیر» بزنید)"):
            picked = await self.app.pick_file()
            if not picked:
                return
            if not picked[1].startswith(b"SQLite format 3"):
                return await self.app.info("خطا", "این فایل دیتابیس SQLite نیست.")
            path = os.path.join(tmp_dir(), "umbot.sqlite3")
            with open(path, "wb") as f:
                f.write(picked[1])
            try:
                db, resellers = sv.merged_sqlite(path)
            except pb.ReleaseError as e:
                return await self.app.info("خطا", str(e))
            if not await self.app.ask("دیتابیس بات", "در این دیتابیس %s ریسلر هست. همین منتقل شود؟" % fa(resellers)):
                return
        if not await self.app.ask("تأیید", "قبل از ادامه، بات قبلی (اگر جایی اجرا می‌شود) را متوقف کنید؛ دو بات "
                                           "با یک توکن هم‌زمان کار نمی‌کنند.\nمتوقف کرده‌اید؟"):
            return
        token = self.app.settings.token
        values = dict(values, LINUX_STATUS=linux.bot_linux_status(self.app.settings.routers))

        def job(log, progress):
            log("دریافت کد بات از GitHub…")
            code = sv.download_bot_code(token)
            with router_connector(r)() as c:
                sv.install_bot(c, code, values, db=db, overwrite_db=True, log=log)
                time.sleep(8)
                return sv.bot_status(c)
        stt, lines = await self.app.run(self.panel, job)
        self.panel.add("\n".join(lines[-15:]))
        await self.app.info("انجام شد", "بات روی روتر نصب شد (وضعیت: %s).\nیک پیام به بات بدهید." % stt)

    async def setup_um2(self):
        import um2
        main = await self.chosen(self.target, "روتر اصلی")
        sec = await self.chosen(self.um2, "روتر دوم (نقش «یوزر منیجر دوم»)")
        if not await self.app.ask("یوزر منیجر دوم", "دیتابیس یوزر منیجر %s هر ۵ دقیقه روی %s کپی می‌شود و هرچه روی "
                                                    "%s هست جایگزین می‌شود.\nادامه؟"
                                  % (main["host"], sec["host"], sec["host"])):
            return
        res = await self.app.run(self.panel, lambda log, progress: um2.setup_um2(
            router_connector(main), router_connector(sec), main["host"], log=log))
        await self.app.info("انجام شد", "یوزر منیجر دوم همگام شد (%s یوزر)." % fa(res["users"]))

    async def backup_setup(self):
        import backuptunnel as bt
        r = await self.chosen(self.target, "روتر اصلی")
        tgt = await self.chosen(self.bt, "سرور لینوکس")
        params = st.decrypt_blob(tgt.get("params")) or {}
        if not (params.get("awg") or {}).get("priv"):
            return await self.app.info("خطا", "روی این سرور لینوکس AmneziaWG نصب نشده است.")

        def look(log, progress):
            with router_connector(r)() as c:
                return bt.inspect(c)
        plan = await self.app.run(self.panel, look)
        if not plan.ok:
            return await self.app.info("ممکن نیست", "راه‌اندازی خودکار ممکن نیست:\n" + "\n".join(plan.problems))
        if not await self.app.ask("تانل پشتیبان", bt.describe(plan, tgt["host"]) + "\n\nادامه؟"):
            return

        def job(log, progress):
            with router_connector(r)() as c:
                return bt.setup(c, linux_connector(tgt), params, tgt["host"], log=log)
        p = await self.app.run(self.panel, job, clear=False)
        tgt["params"] = st.encrypt_blob(p)
        self.app.settings.save()
        await self.app.info("انجام شد", "تانل پشتیبان آماده است.")
        await self.backup_status()

    async def backup_status(self):
        import backuptunnel as bt
        r = await self.chosen(self.target, "روتر اصلی")
        tgt = self.app.settings.router(self.bt.value) if self.bt.value else None

        def job(log, progress):
            with router_connector(r)() as c:
                s = bt.status(c)
            if s.get("installed") and tgt:
                static = ((st.decrypt_blob(tgt.get("params")) or {}).get("awg") or {}).get("static") or {}
                if static:
                    with linux_connector(tgt)() as h:
                        s["linux"] = linux.static_peer_status(h, next(iter(static)))
            return s
        s = await self.app.run(self.panel, job)
        if not s.get("installed"):
            self.bt_state.value = "تانل پشتیبان راه‌اندازی نشده است."
            return
        hs = s.get("handshake")
        lines = ["اتصال به سرور لینوکس: %s" % ("✓ آخرین handshake %s پیش" % hs if hs else "✗ هنوز وصل نشده"),
                 "حجم از تانل پشتیبان: دریافت %s، ارسال %s" % (human_size(s.get("rx", 0)), human_size(s.get("tx", 0)))]
        for table, via in sorted((s.get("using") or {}).items()):
            if table != "main":
                lines.append("جدول %s الان از: %s" % (table, "AmneziaWG (پشتیبان)" if via == "AmneziaWG"
                                                       else "GRE (%s)" % via))
        lines.append("کانتینر رله: %s" % s.get("relay"))
        self.bt_state.value = "\n".join(lines)

    async def backup_remove(self):
        import backuptunnel as bt
        r = await self.chosen(self.target, "روتر اصلی")
        if not await self.app.ask("برداشتن تانل پشتیبان", "همه‌ی چیزهایی که تانل پشتیبان ساخته از روتر برداشته "
                                                          "می‌شود و GRE مثل قبل می‌شود. ادامه؟"):
            return

        def job(log, progress):
            with router_connector(r)() as c:
                bt.remove(c, log)
        await self.app.run(self.panel, job)
        self.bt_state.value = "تانل پشتیبان برداشته شد."


# ====================================================================== new server

class NewServerPage:
    def __init__(self, app):
        self.app = app
        self.result = None
        self.panel = Panel(app)
        self.mode = ft.RadioGroup(value="main", on_change=lambda e: self.update_mode(), content=ft.Column([
            ft.Radio(value="main", label="سرور اصلی جدید (از روی بکاپ)"),
            ft.Radio(value="sec", label="سرور فرعی (احراز هویت از سرور اصلی)"),
            ft.Radio(value="linux", label="سرور لینوکس (Xray و AmneziaWG)")]))
        self.target = dropdown("روتر / سرور جدید", [], on_select=lambda e: self.fill_ip())
        self.source = dropdown("سرور اصلی فعلی/قدیم", [], on_select=lambda e: self.fill_backups())
        self.backup = dropdown("بکاپ", [])
        self.ip = ltr_field("IP عمومی سرور جدید")
        self.domain = ltr_field("دامنه (Cloudflare؛ خالی = بدون CDN)")
        self.cf_token = ltr_field("توکن Cloudflare", password=True)
        self.chk_bot = ft.Checkbox(label="بات روی سرور قدیم متوقف شود (اگر در دسترس است)", value=True)
        self.btn_cfg = app.button("به‌روزرسانی سرورهای اپ و انتشار", self.publish_servers)
        self.btn_cfg.disabled = True
        self.fresh = app.button("بکاپ تازه از سرور اصلی", self.fresh_backup)
        self.view = ft.Column([
            card("۱. نوع سرور", self.mode, hint("سرور جدید را اول در «سرورها» اضافه کنید.")),
            card("۲. مشخصات", ft.Row([self.target]), ft.Row([self.source]), ft.Row([self.backup]), self.ip,
                 self.domain, self.cf_token, self.chk_bot, self.fresh),
            card("۳. اجرا", app.button("شروع / ادامه", self.go, primary=True), self.btn_cfg, self.panel.view)],
            spacing=10)

    def _fill(self, d, items):
        d.options = [ft.DropdownOption(key=k, text=t) for k, t in items]
        if d.value not in [k for k, _ in items]:
            d.value = items[0][0] if items else None

    def reload(self):
        self._fill(self.target, self.app.router_items())
        self._fill(self.source, self.app.router_items(("main",)))
        self.fill_backups(update=False)
        self.fill_ip(update=False)
        self.update_mode(update=False)

    def update_mode(self, update=True):
        m = self.mode.value
        self.chk_bot.visible = m == "main"
        self.backup.visible = self.source.visible = self.fresh.visible = m != "linux"
        self.domain.visible = self.cf_token.visible = m == "linux"
        self.btn_cfg.content = "به‌روزرسانی سرورهای اپ و انتشار" if m == "main" else "اضافه کردن به سرورهای اپ و انتشار"
        if update:
            self.app.page.update()

    def fill_ip(self, update=True):
        r = self.app.settings.router(self.target.value) if self.target.value else None
        if r:
            self.ip.value = r["host"]
            p = st.decrypt_blob(r.get("params")) if r.get("role") == "linux" and r.get("params") else {}
            if (p or {}).get("domain"):
                self.domain.value = p["domain"]
            if (p or {}).get("cf_token"):
                self.cf_token.value = p["cf_token"]
        if update:
            self.app.page.update()

    def fill_backups(self, update=True):
        r = self.app.settings.router(self.source.value) if self.source.value else None
        names = bk.LocalStore(self.app.settings.backup_dir()).list(r["id"]) if r else []
        self._fill(self.backup, [(n, n) for n in names])
        if update:
            self.app.page.update()

    async def fresh_backup(self):
        r = self.app.settings.router(self.source.value) if self.source.value else None
        if not r:
            return await self.app.info("خطا", "سرور اصلی را انتخاب کنید.")
        s = self.app.settings
        if not s.backup_password:
            return await self.app.info("خطا", "اول رمز بکاپ را در ⚙ بگذارید.")
        res = await self.app.run(self.panel, lambda log, progress: bk.backup_all(s, log, progress, only={r["id"]}))
        self.fill_backups()
        if not res[r["id"]]["ok"]:
            await self.app.info("خطا", res[r["id"]]["error"])

    async def go_linux(self, tgt, new_ip):
        s = self.app.settings
        ums = sorted(self.app.routers(UM_ROLES), key=lambda r: r.get("role") != "main")
        if not ums:
            return await self.app.info("خطا", "اول روتر یوزر منیجر (اصلی) را در «سرورها» تعریف کنید.")
        if tgt.get("role") != "linux":
            return await self.app.info("خطا", "نقش این سرور در «سرورها» باید «سرور لینوکس» باشد.")
        if not await self.app.ask("تأیید", "روی «%s» Xray، AmneziaWG و سرویس هماهنگی با یوزر منیجر نصب می‌شود.\n"
                                           "روی %s هم دسترسی این سرور ثبت می‌شود.\nادامه؟"
                                  % (router_label(tgt), "، ".join(router_label(r) for r in ums))):
            return
        name = re.sub(r"[^A-Za-z0-9_-]", "-", tgt.get("name") or tgt["id"])
        params = st.decrypt_blob(tgt.get("params")) or {}
        domain = (self.domain.value or "").strip().lower().rstrip(".")
        if domain and not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", domain):
            return await self.app.info("خطا", "دامنه درست نیست: %s" % domain)
        if domain != params.get("domain"):
            params.pop("domain_info", None)
        if domain:
            params["domain"] = domain
        else:
            params.pop("domain", None)
        params["cf_token"] = (self.cf_token.value or "").strip()
        if domain and not params["cf_token"] and not await self.app.ask(
                "توکن Cloudflare", "توکن Cloudflare خالی است؛ رکوردهای دامنه را باید خودتان بسازید.\nادامه؟"):
            return
        others = [r for r in s.routers if r.get("id") != tgt.get("id")]

        def job(log, progress):
            res = linux.setup_linux(linux_connector(tgt), [(router_connector(r), r["host"]) for r in ums],
                                    name, new_ip, params=params, log=log)
            value = linux.bot_linux_status(others + [dict(tgt, params=st.encrypt_blob(res[0]))])
            for r in ums:
                try:
                    with router_connector(r)() as c:
                        if sv.set_bot_env(c, {"LINUX_STATUS": value}, log):
                            log("✓ بات تلگرام از این سرور خبر دارد (آنلاین‌ها).")
                except Exception as e:
                    log("⚠ تنظیم بات روی %s نشد: %s" % (r["host"], str(e).splitlines()[0]))
            return res
        p, entry = await self.app.run(self.panel, job)
        tgt["params"] = st.encrypt_blob(p)
        s.save()
        self.result = {"linux": True, "entry": entry, "target": tgt["id"], "new_ip": new_ip, "main": False}
        self.panel.add("✓ سرور لینوکس آماده است: %s" % "، ".join(x["type"] for x in entry["protocols"]))
        self.btn_cfg.disabled = False
        msg = "سرور لینوکس آماده است.\nحالا «%s» را بزنید تا اپ‌ها آن را بشناسند." % self.btn_cfg.content
        if not any(x["type"] == "amneziawg" for x in entry["protocols"]):
            msg += "\n\n⚠ AmneziaWG نصب نشد (بقیه‌ی پروتکل‌ها کار می‌کنند). دلیلش در گزارش با ⚠ آمده است."
        await self.app.info("انجام شد", msg)

    async def go(self):
        s = self.app.settings
        tgt = s.router(self.target.value) if self.target.value else None
        if self.mode.value == "linux":
            if not tgt:
                return await self.app.info("خطا", "سرور لینوکس را انتخاب کنید.")
            return await self.go_linux(tgt, (self.ip.value or "").strip() or tgt["host"])
        src = s.router(self.source.value) if self.source.value else None
        if not tgt or not src:
            return await self.app.info("خطا", "روتر جدید و سرور اصلی را انتخاب کنید.")
        if tgt["id"] == src["id"]:
            return await self.app.info("خطا", "روتر جدید و سرور اصلی نمی‌توانند یکی باشند.")
        if not self.backup.value:
            return await self.app.info("خطا", "بکاپی از سرور اصلی انتخاب نشده است (اول بکاپ بگیرید).")
        path = os.path.join(bk.LocalStore(s.backup_dir()).dir(src["id"]), self.backup.value)
        new_ip = (self.ip.value or "").strip()
        if not new_ip:
            return await self.app.info("خطا", "IP عمومی روتر جدید را وارد کنید.")
        password, main_mode = s.backup_password, self.mode.value == "main"
        if not await self.app.ask("تأیید", "«%s» به عنوان %s راه‌اندازی می‌شود.\nتنظیمات فعلی آن روتر تغییر می‌کند. "
                                           "ادامه؟" % (router_label(tgt), "سرور اصلی جدید" if main_mode else "سرور فرعی")):
            return
        key = None
        try:
            with open(self.app.workspace().path("config_key.public.txt"), "rb") as f:
                key = f.read()
        except OSError:
            pass
        stop_old = self.chk_bot.value

        def job(log, progress):
            manifest, parts = bk.open_backup(path, password)
            if main_mode:
                res = pv.restore_main(router_connector(tgt), manifest, parts, new_ip, log=log, progress=progress,
                                      public_key=key, package_source=pc_package)
                if res["status"] == pv.DONE and stop_old:
                    try:
                        with router_connector(src)() as c:
                            if sv.stop_bot_autostart(c, log):
                                log("✓ بات روی سرور قدیم متوقف شد")
                    except Exception as e:
                        log("⚠ سرور قدیم در دسترس نیست (بات آن متوقف نشد): %s" % e)
            else:
                main_ip = pv.old_public_ip(manifest, parts)
                res = pv.setup_secondary(router_connector(tgt), router_connector(src), manifest, parts, new_ip,
                                         main_ip, tgt.get("name") or tgt["id"], log=log)
            res["old_ip"] = res.get("old_ip") or pv.old_public_ip(manifest, parts)
            return res
        res = await self.app.run(self.panel, job)
        self.result = dict(res, new_ip=new_ip, main=main_mode, target=tgt["id"])
        if res["status"] == pv.NEED_POWER_CYCLE:
            self.panel.add("⏸ منتظر خاموش و روشن کردن سرور")
            return await self.app.info("یک کار دستی", "برای فعال شدن کانتینر، روتر جدید باید یک بار خاموش و روشن شود:"
                                       "\nظرف ۵ دقیقه از پنل VPS، سرور را Power Off و بعد Power On کنید (Reboot کافی "
                                       "نیست).\nبعد دوباره «شروع / ادامه» را بزنید.")
        lines = ["نتیجه:"] + ["  " + c for c in res.get("checks", [])]
        if res.get("failed"):
            lines.append("دستورهایی که اجرا نشدند (معمولاً تکراری‌اند):")
            lines += ["  %s → %s" % (l[:150], e[:150]) for l, e in res["failed"]]
        self.panel.add("\n".join(lines))
        bad = [c for c in res.get("checks", []) if c.startswith("✗")]
        self.btn_cfg.disabled = bool(bad)
        if bad:
            return await self.app.info("ناقص", "بعضی بررسی‌ها ناموفق بودند:\n" + "\n".join(bad))
        await self.app.info("انجام شد", "سرور آماده است.\nحالا «%s» را بزنید." % self.btn_cfg.content)

    async def publish_servers(self):
        import json
        import shutil
        res = self.result
        if not res:
            return
        s = self.app.settings
        ws = self.app.workspace()
        try:
            ws.check()
            cfg = ws.load_config()
        except (pb.ReleaseError, OSError, ValueError) as e:
            return await self.app.info("خطا", str(e))
        tgt = s.router(res["target"])
        if res.get("linux"):
            new_cfg = pv.add_linux_server(cfg, res["entry"])
            text = "سرور لینوکس %s به تنظیمات اپ اضافه می‌شود." % res["new_ip"]
        elif res["main"]:
            new_cfg = pv.move_server_in_config(cfg, res["old_ip"], res["new_ip"])
            text = "آدرس سرور اصلی در تنظیمات اپ از %s به %s عوض می‌شود." % (res["old_ip"], res["new_ip"])
        else:
            new_cfg = pv.add_server_to_config(cfg, tgt.get("name") or tgt["id"], res["new_ip"])
            text = "سرور %s به لیست سرورهای اپ اضافه می‌شود." % res["new_ip"]
        if not await self.app.ask("تأیید", text + "\nبعد تنظیمات امضا و منتشر می‌شود. ادامه؟"):
            return
        shutil.copy(ws.path("config.json"), ws.path("config.before-%s.json" % bk.stamp()))
        with open(ws.path("config.json"), "w", encoding="utf-8") as f:
            json.dump(new_cfg, f, ensure_ascii=False, indent=2)
        if res["main"]:
            tgt["role"] = "main"
            s.save()
        github, public = self.app.github_clients()

        def job(log, progress):
            return pb.release_config_only(ws, send_router=True, github=github, public_github=public, log=log,
                                          progress=progress)
        cfg = await self.app.run(self.panel, job, clear=False)
        self.btn_cfg.disabled = True
        await self.app.info("انجام شد", "تنظیمات جدید (نسخه‌ی %s) منتشر شد." % fa(cfg["version"]))


# ====================================================================== monitoring

class MonitorPage:
    def __init__(self, app):
        self.app = app
        self.status = {}
        self.panel = Panel(app, height=60)
        self.total = hint("")
        self.cards = ft.Column(spacing=6)
        self.auto = ft.Switch(label="خودکار هر ۶۰ ثانیه", value=False, on_change=self.toggle_auto)
        self._task = None
        self.view = ft.Column([
            ft.Row([app.button("🔄 به‌روزرسانی", self.refresh, primary=True), self.auto], wrap=True),
            self.total, self.cards, self.panel.view], spacing=10)

    def reload(self):
        self.fill()

    def toggle_auto(self, e):
        if self.auto.value and self._task is None:
            self._task = self.app.page.run_task(self._loop)

    async def _loop(self):
        try:
            while self.auto.value:
                if not self.app.busy and self.app.current is self:
                    try:
                        await self.refresh()
                    except Cancel:
                        pass
                    self.app.page.update()
                await asyncio.sleep(60)
        finally:
            self._task = None

    async def refresh(self):
        routers = list(self.app.settings.routers)
        if not routers:
            return await self.app.info("وضعیت", "اول در «سرورها» سرورها را تعریف کنید.")
        self.status = await self.app.run(self.panel, lambda log, progress: monitor.poll(routers, connector_for))
        self.fill()

    def fill(self):
        self.cards.controls.clear()
        total = 0
        for r in self.app.settings.routers:
            s = self.status.get(r["id"], {})
            ok = s.get("ok")
            head = "%s  %s — %s" % ("🟢" if ok else ("🔴" if s else "⚪"), r.get("name") or r["host"],
                                   ROLE_SHORT.get(r.get("role"), r.get("role", "")))
            lines = []
            if ok:
                total += s.get("users_online", 0)
                lines.append("CPU %s٪   حافظه %s   روشن از %s" % (
                    fa(s.get("cpu", 0)), ("%s٪" % fa(s["mem"])) if s.get("mem") is not None else "—", s.get("uptime", "")))
                by = "  ".join("%s: %s" % (monitor.proto_name(k), fa(v))
                               for k, v in sorted(s.get("by_protocol", {}).items(), key=lambda kv: -kv[1]))
                lines.append("آنلاین: %s   %s" % (fa(s.get("users_online", 0)), by))
                svc = "  ".join("%s %s" % (k, STATE_FA.get(v, v)) for k, v in s.get("services", {}).items())
                if svc:
                    lines.append("سرویس‌ها: " + svc)
            elif s:
                lines.append(s.get("error", "در دسترس نیست"))
            self.cards.controls.append(ft.Card(content=ft.Container(
                padding=ft.Padding.all(12), on_click=self._users(r), ink=True,
                content=ft.Column([ft.Text(head, weight=ft.FontWeight.BOLD)] + [ft.Text(x, size=12) for x in lines],
                                  spacing=4))))
        if self.status:
            self.total.value = "مجموع آنلاین: %s — به‌روزرسانی: %s" % (
                fa(total), fa(_dt.datetime.now().strftime("%H:%M:%S")))

    def _users(self, r):
        async def handler(e):
            rows = self.status.get(r["id"], {}).get("online", [])
            text = "\n".join("%s — %s — %s — %s" % (o["user"], monitor.proto_name(o["protocol"]), o.get("address", ""),
                                                    o.get("since", "")) for o in rows) or "کسی آنلاین نیست."
            await self.app.info("آنلاین‌های %s" % (r.get("name") or r["host"]), text)
        return handler


# ====================================================================== entry

def main():
    def start(page: ft.Page):
        app = App(page)
        page.data = app
        app.start()
    ft.run(start)
    return 0


def smoke():
    """CI: build every screen and dialog with a stand-in page (no device), so
    wrong arguments to the controls show up before a build reaches the phone."""
    class FakePage:
        def __init__(self):
            self.controls, self.loop, self.data, self.dialogs = [], None, None, []

        def update(self, *a):
            pass

        def add(self, *c):
            self.controls.extend(c)

        def show_dialog(self, d):
            self.dialogs.append(d)

        def pop_dialog(self):
            pass

        def run_task(self, fn, *a):
            return None
    page = FakePage()
    app = App(page)
    app.start()                                      # welcome (no app password here)
    app.show_lock()
    app.settings = st.Settings()
    app.settings.routers = [{"id": "r1", "name": "main", "role": "main", "host": "1.2.3.4", "port": 22,
                             "user": "pvtool", "password": "x", "hostkey": "", "params": ""},
                            {"id": "r2", "name": "lin", "role": "linux", "host": "5.6.7.8", "port": 22,
                             "user": "root", "password": "x", "hostkey": "", "params": ""}]
    app.show_main()
    for i in range(len(app.pages)):
        app.select(i)
    app.pages[4].status = {"r1": {"ok": True, "cpu": 3, "mem": 40, "uptime": "1d", "users_online": 2,
                                  "by_protocol": {"sstp": 2}, "services": {"umstatus": "running"}, "online": []},
                           "r2": {"ok": False, "error": "timeout"}}
    app.pages[4].fill()

    async def dialogs():
        async def answer(coro, pick=-1):
            task = asyncio.ensure_future(coro)
            await asyncio.sleep(0)
            page.dialogs[-1].actions[pick].on_click(None)
            return await task
        assert await answer(app.ask("t", "x")) is True
        await answer(app.info("t", "x"))
        assert await answer(app.choose("t", "x", [("a", "A"), ("b", "B")])) == "b"
        res = await answer(app.form("t", [("a", "A", "1", "text"), ("b", "B", "x", "password"),
                                          ("c", "C", 5, "int"), ("d", "D", "", "multiline"),
                                          ("e", "E", True, "check"), ("f", "F", "k2", [("k1", "1"), ("k2", "2")])]))
        assert res == {"a": "1", "b": "x", "c": 5, "d": "", "e": True, "f": "k2"}, res
        values = {k: "" for k, _ in BOT_FIELDS}
        task = asyncio.ensure_future(app.pages[2].bot_form(values))
        await asyncio.sleep(0)
        page.dialogs[-1].actions[0].on_click(None)          # cancel
        try:
            await task
        except Cancel:
            pass
        task = asyncio.ensure_future(app.pages[1].router_form(app.settings.routers[0]))
        await asyncio.sleep(0)
        page.dialogs[-1].actions[-1].on_click(None)
        assert (await task)["host"] == "1.2.3.4"
    asyncio.run(dialogs())
    print("admin smoke OK")
    return 0


if __name__ == "__main__":
    sys.exit(smoke() if "--smoke" in sys.argv else main())
