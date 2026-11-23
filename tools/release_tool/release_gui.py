"""Persian VPN release tool (Windows GUI).

Drop the build file (or fetch the newest one from GitHub), write the
release notes, press one button: the tool signs the new config, uploads
config + APK to the router and updates the repository on GitHub.
"""

import datetime as _dt
import re
import os
import subprocess
import sys
import time
import tempfile
import traceback

from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QFont, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QFileDialog, QFrame, QGraphicsDropShadowEffect,
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMessageBox,
    QHeaderView, QPlainTextEdit, QProgressBar, QPushButton, QRadioButton, QScrollArea, QSpinBox, QTableWidget,
    QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import backup as bk          # noqa: E402
import linux                # noqa: E402
import monitor              # noqa: E402
import provision as pv      # noqa: E402
import publisher as pb       # noqa: E402
import selfupdate as su      # noqa: E402
import services as sv        # noqa: E402
import settings as st        # noqa: E402
from routeros import SSHRouter  # noqa: E402
from settings import Settings  # noqa: E402

FA_DIGITS = str.maketrans("0123456789.", "۰۱۲۳۴۵۶۷۸۹٫")


def fa(x):
    return str(x).translate(FA_DIGITS)


def resource(name):
    base = getattr(sys, "_MEIPASS", None)   # inside the PyInstaller .exe
    for d in ([base] if base else []) + [HERE, os.path.join(HERE, "..", "icon")]:
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p
    return None


STYLE = """
QWidget { color: #FFFFFF; font-size: 10.5pt; }
#Root {
    background: qlineargradient(x1:0, y1:0, x2:0.6, y2:1, stop:0 #0A2540, stop:1 #0B5563);
}
#Card {
    background: rgba(255,255,255,0.07);
    border: 1px solid rgba(255,255,255,0.16);
    border-radius: 18px;
}
#CardTitle { font-size: 12pt; font-weight: bold; }
#Title { font-size: 19pt; font-weight: bold; }
#Subtitle, #Hint { color: rgba(255,255,255,0.65); }
#Hint { font-size: 9.5pt; }
#Drop {
    background: rgba(255,255,255,0.04);
    border: 2px dashed rgba(46,230,197,0.55);
    border-radius: 14px;
    min-height: 92px;
}
#Drop[hover="true"] { background: rgba(46,230,197,0.12); border-color: #2EE6C5; }
#Drop[loaded="true"] { border-style: solid; border-color: #2EE6C5; }
#DropText { font-size: 11pt; }
QPushButton {
    background: rgba(255,255,255,0.08);
    border: 1px solid rgba(255,255,255,0.22);
    border-radius: 18px;
    padding: 8px 18px;
}
QPushButton:hover { background: rgba(255,255,255,0.14); }
QPushButton:disabled { color: rgba(255,255,255,0.35); }
#Primary {
    background: #2EE6C5; color: #04211C; border: none;
    font-size: 12.5pt; font-weight: bold; border-radius: 24px; padding: 12px;
}
#Primary:hover { background: #5CF2D6; }
#Primary:disabled { background: rgba(46,230,197,0.35); color: rgba(4,33,28,0.6); }
#Gear { border-radius: 18px; padding: 6px 12px; font-size: 13pt; }
QLineEdit, QSpinBox, QPlainTextEdit {
    background: rgba(255,255,255,0.07);
    border: 1px solid rgba(255,255,255,0.22);
    border-radius: 10px; padding: 6px 10px;
    selection-background-color: #00A58E;
}
QLineEdit:focus, QSpinBox:focus, QPlainTextEdit:focus { border-color: #2EE6C5; }
QCheckBox::indicator { width: 18px; height: 18px; }
QProgressBar {
    background: rgba(255,255,255,0.12); border: none; border-radius: 4px; height: 8px;
}
QProgressBar::chunk { background: #2EE6C5; border-radius: 4px; }
#Log { background: rgba(0,0,0,0.18); border-radius: 12px; font-size: 10pt; }
QDialog { background: #12324A; }
QTableWidget {
    background: rgba(0,0,0,0.15); border: 1px solid rgba(255,255,255,0.16); border-radius: 12px;
    gridline-color: rgba(255,255,255,0.08); selection-background-color: rgba(46,230,197,0.25);
}
QHeaderView::section {
    background: rgba(255,255,255,0.08); color: rgba(255,255,255,0.85); border: none; padding: 6px;
}
QTabWidget::pane { border: none; }
QTabBar::tab {
    background: rgba(255,255,255,0.06); color: rgba(255,255,255,0.75);
    border: 1px solid rgba(255,255,255,0.16); border-radius: 14px;
    padding: 7px 20px; margin: 0 4px 10px 4px;
}
QTabBar::tab:selected { background: #2EE6C5; color: #04211C; font-weight: bold; border: none; }
QListWidget {
    background: rgba(0,0,0,0.15); border: 1px solid rgba(255,255,255,0.16);
    border-radius: 12px; padding: 4px;
}
QListWidget::item { padding: 8px; border-radius: 8px; }
QListWidget::item:selected { background: rgba(46,230,197,0.25); color: #FFFFFF; }
QComboBox {
    background: rgba(255,255,255,0.07); border: 1px solid rgba(255,255,255,0.22);
    border-radius: 10px; padding: 6px 10px;
}
QComboBox QAbstractItemView { background: #12324A; selection-background-color: #00A58E; }
#Warn { background: rgba(255,170,60,0.18); border: 1px solid rgba(255,170,60,0.6);
        border-radius: 12px; padding: 8px 12px; }
QMessageBox { background: #12324A; }
"""


# ------------------------------------------------------------------ background work

class Worker(QObject):
    log = Signal(str)
    progress = Signal(int, int)
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            self.done.emit(self.fn(self.log.emit, lambda a, b: self.progress.emit(a, b)))
        except pb.ReleaseError as e:
            self.failed.emit(str(e))
        except Exception as e:  # unexpected: keep details for a bug report
            self.failed.emit("خطای پیش‌بینی‌نشده: %s\n\n%s" % (e, traceback.format_exc(limit=3)))


class Relay(QObject):
    """Lives in the GUI thread, so the worker's signals reach the callbacks
    there (queued). Connecting a signal straight to a plain function runs it
    in the worker thread, and a message box opened there freezes the window."""

    def __init__(self, parent, on_done, on_failed, on_log, on_progress):
        super().__init__(parent)
        self.f = (on_done, on_failed, on_log, on_progress)

    def done(self, result):
        self.f[0](result)

    def failed(self, text):
        self.f[1](text)

    def log(self, text):
        if self.f[2]:
            self.f[2](text)

    def progress(self, a, b):
        if self.f[3]:
            self.f[3](a, b)


def run_in_thread(owner, fn, on_done, on_failed, on_log=None, on_progress=None):
    thread = QThread(owner)
    worker = Worker(fn)
    worker.moveToThread(thread)
    relay = Relay(owner, on_done, on_failed, on_log, on_progress)
    thread.started.connect(worker.run)
    worker.done.connect(relay.done, Qt.QueuedConnection)
    worker.failed.connect(relay.failed, Qt.QueuedConnection)
    worker.log.connect(relay.log, Qt.QueuedConnection)
    worker.progress.connect(relay.progress, Qt.QueuedConnection)
    thread.finished.connect(relay.deleteLater)
    for sig in (worker.done, worker.failed):
        sig.connect(thread.quit)
    thread.finished.connect(worker.deleteLater)
    thread.finished.connect(thread.deleteLater)
    owner._jobs = getattr(owner, "_jobs", []) + [(thread, worker)]
    thread.start()


# ------------------------------------------------------------------ widgets

def card(title):
    frame = QFrame()
    frame.setObjectName("Card")
    shadow = QGraphicsDropShadowEffect(blurRadius=24, xOffset=0, yOffset=4)
    shadow.setColor(Qt.black)
    frame.setGraphicsEffect(shadow)
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(18, 14, 18, 16)
    lay.setSpacing(10)
    t = QLabel(title)
    t.setObjectName("CardTitle")
    lay.addWidget(t)
    return frame, lay


class DropArea(QFrame):
    fileDropped = Signal(str)

    def __init__(self):
        super().__init__()
        self.setObjectName("Drop")
        self.setAcceptDrops(True)
        self.setCursor(Qt.PointingHandCursor)
        lay = QVBoxLayout(self)
        self.text = QLabel("فایل بیلد را اینجا بکشید یا کلیک کنید")
        self.text.setObjectName("DropText")
        self.text.setAlignment(Qt.AlignCenter)
        self.sub = QLabel("فایل zip دانلودشده از GitHub (مثل persian-vpn-16.zip) یا فایل APK")
        self.sub.setObjectName("Hint")
        self.sub.setAlignment(Qt.AlignCenter)
        lay.addStretch()
        lay.addWidget(self.text)
        lay.addWidget(self.sub)
        lay.addStretch()

    def _restyle(self, **props):
        for k, v in props.items():
            self.setProperty(k, v)
        self.style().unpolish(self)
        self.style().polish(self)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self._restyle(hover="true")

    def dragLeaveEvent(self, e):
        self._restyle(hover="false")

    def dropEvent(self, e):
        self._restyle(hover="false")
        urls = e.mimeData().urls()
        if urls:
            self.fileDropped.emit(urls[0].toLocalFile())

    def mousePressEvent(self, e):
        path, _ = QFileDialog.getOpenFileName(self, "انتخاب فایل بیلد", "",
                                              "بیلد (*.zip *.apk)")
        if path:
            self.fileDropped.emit(path)

    def show_build(self, build):
        self.text.setText("✓  " + build.source)
        self.sub.setText("%s مگابایت" % fa("%.1f" % (len(build.apk) / 1048576)))
        self._restyle(loaded="true")


# ------------------------------------------------------------------ settings dialog

class SettingsDialog(QDialog):
    def __init__(self, parent, settings):
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle("تنظیمات")
        self.setLayoutDirection(Qt.RightToLeft)
        self.setMinimumWidth(560)
        lay = QVBoxLayout(self)
        lay.setSpacing(8)

        lay.addWidget(QLabel("پوشه‌ی کاری (همان پوشه‌ی tools که config.json و کلید خصوصی در آن است):"))
        row = QHBoxLayout()
        self.ws = QLineEdit(settings.workspace)
        self.ws.setLayoutDirection(Qt.LeftToRight)
        browse = QPushButton("انتخاب…")
        browse.clicked.connect(self.pick_folder)
        row.addWidget(self.ws, 1)
        row.addWidget(browse)
        lay.addLayout(row)

        lay.addWidget(QLabel("مخزن GitHub:"))
        self.repo = QLineEdit(settings.repo)
        self.repo.setLayoutDirection(Qt.LeftToRight)
        lay.addWidget(self.repo)

        lay.addWidget(QLabel("مخزن عمومی پشتیبان (وقتی روتر در دسترس نیست، اپ تنظیمات را از اینجا می‌خواند):"))
        self.public_repo = QLineEdit(settings.public_repo)
        self.public_repo.setLayoutDirection(Qt.LeftToRight)
        self.public_repo.setPlaceholderText("خالی = بدون پشتیبان")
        lay.addWidget(self.public_repo)

        lay.addWidget(QLabel("یوزرهای تست (نسخه‌ی آزمایشی فقط به این‌ها پیشنهاد می‌شود؛ با کاما جدا کنید):"))
        self.testers = QLineEdit("، ".join(settings.testers))
        self.testers.setLayoutDirection(Qt.LeftToRight)
        self.testers.setPlaceholderText("mohammad, ali")
        lay.addWidget(self.testers)

        lay.addWidget(QLabel("توکن GitHub (رمزنگاری‌شده روی همین ویندوز ذخیره می‌شود):"))
        self.token = QLineEdit(settings.token)
        self.token.setEchoMode(QLineEdit.Password)
        self.token.setLayoutDirection(Qt.LeftToRight)
        self.token.setPlaceholderText("github_pat_…")
        lay.addWidget(self.token)

        lay.addWidget(QLabel("مخزن خصوصی بکاپ روترها:"))
        self.backup_repo = QLineEdit(settings.backup_repo)
        self.backup_repo.setLayoutDirection(Qt.LeftToRight)
        lay.addWidget(self.backup_repo)

        lay.addWidget(QLabel("رمز بکاپ (بدون این رمز، بکاپ‌ها باز نمی‌شوند؛ جای امنی بیرون از این کامپیوتر یادداشتش کنید):"))
        prow = QHBoxLayout()
        self.bpass = QLineEdit(settings.backup_password)
        self.bpass.setEchoMode(QLineEdit.Password)
        self.bpass.setLayoutDirection(Qt.LeftToRight)
        self.bpass.setPlaceholderText("رمز بکاپ")
        self.bpass2 = QLineEdit(settings.backup_password)
        self.bpass2.setEchoMode(QLineEdit.Password)
        self.bpass2.setLayoutDirection(Qt.LeftToRight)
        self.bpass2.setPlaceholderText("تکرار رمز")
        prow.addWidget(self.bpass)
        prow.addWidget(self.bpass2)
        lay.addLayout(prow)

        arow = QHBoxLayout()
        self.auto = QCheckBox("بکاپ خودکار هر")
        self.auto.setChecked(settings.auto_backup)
        self.hours = QSpinBox()
        self.hours.setRange(1, 24)
        self.hours.setValue(settings.backup_hours)
        arow.addWidget(self.auto)
        arow.addWidget(self.hours)
        arow.addWidget(QLabel("ساعت (وقتی این کامپیوتر روشن است)"))
        arow.addStretch()
        lay.addLayout(arow)

        tests = QHBoxLayout()
        self.btn_router = QPushButton("بررسی اتصال روتر")
        self.btn_router.clicked.connect(self.test_router)
        self.btn_gh = QPushButton("بررسی GitHub")
        self.btn_gh.clicked.connect(self.test_github)
        tests.addWidget(self.btn_router)
        tests.addWidget(self.btn_gh)
        lay.addLayout(tests)
        self.result = QLabel("")
        self.result.setWordWrap(True)
        self.result.setObjectName("Hint")
        lay.addWidget(self.result)

        buttons = QHBoxLayout()
        save = QPushButton("ذخیره")
        save.setObjectName("Primary")
        save.clicked.connect(self.save)
        cancel = QPushButton("انصراف")
        cancel.clicked.connect(self.reject)
        buttons.addWidget(save, 1)
        buttons.addWidget(cancel)
        lay.addLayout(buttons)

    def pick_folder(self):
        d = QFileDialog.getExistingDirectory(self, "پوشه‌ی کاری", self.ws.text())
        if d:
            self.ws.setText(d)

    def _say(self, text, ok):
        self.result.setText(("✓ " if ok else "✗ ") + text)

    def test_router(self):
        def job(log, progress):
            ws = pb.Workspace(self.ws.text().strip())
            ws.check()
            client = pb.RouterClient(ws.load_config())
            if not client.health():
                raise pb.ReleaseError("روتر جواب داد ولی سرویس سالم نیست.")
            return "%s:%s" % (client.host, client.port)
        self.result.setText("در حال بررسی روتر…")
        run_in_thread(self, job, lambda r: self._say("روتر در دسترس است و گواهی‌اش درست است (%s)." % r, True),
                      lambda e: self._say(e, False))

    def test_github(self):
        def job(log, progress):
            names = [pb.GitHubClient(self.token.text(), self.repo.text()).check()]
            if self.public_repo.text().strip():
                names.append(pb.GitHubClient(self.token.text(), self.public_repo.text()).check())
            if self.backup_repo.text().strip():
                names.append(pb.GitHubClient(self.token.text(), self.backup_repo.text()).check())
            return " و ".join(names)
        self.result.setText("در حال بررسی GitHub…")
        run_in_thread(self, job, lambda r: self._say("دسترسی به مخزن %s برقرار است." % r, True),
                      lambda e: self._say(e, False))

    def save(self):
        if self.bpass.text() != self.bpass2.text():
            return QMessageBox.warning(self, "خطا", "رمز بکاپ و تکرارش یکی نیستند.")
        if self.bpass.text() and len(self.bpass.text()) < 10:
            return QMessageBox.warning(self, "خطا", "رمز بکاپ حداقل ۱۰ حرف باشد.")
        if self.settings.backup_password and self.bpass.text() != self.settings.backup_password:
            ok = QMessageBox.question(self, "تأیید",
                "رمز بکاپ عوض می‌شود. بکاپ‌های قبلی فقط با رمز قبلی باز می‌شوند. ادامه می‌دهید؟")
            if ok != QMessageBox.Yes:
                return
        auto, hours = self.auto.isChecked(), self.hours.value()
        if auto and not self.bpass.text():
            return QMessageBox.warning(self, "خطا", "برای بکاپ خودکار اول رمز بکاپ را بگذارید.")
        if sys.platform == "win32" and (auto != self.settings.auto_backup or hours != self.settings.backup_hours):
            try:
                bk.set_schedule(auto, hours)
            except pb.ReleaseError as e:
                return QMessageBox.warning(self, "خطا", str(e))
        self.settings.auto_backup, self.settings.backup_hours = auto, hours
        self.settings.backup_repo = self.backup_repo.text().strip()
        self.settings.backup_password = self.bpass.text()
        self.settings.workspace = self.ws.text().strip()
        self.settings.repo = self.repo.text().strip()
        self.settings.public_repo = self.public_repo.text().strip()
        self.settings.token = self.token.text().strip()
        self.settings.testers = [t.strip() for t in re.split(r"[,،\s]+", self.testers.text()) if t.strip()]
        self.settings.save()
        self.accept()


# ------------------------------------------------------------------ routers

ROLES = [("main", "اصلی (یوزر منیجر)"), ("um2", "یوزر منیجر دوم (پشتیبان)"),
         ("secondary", "فرعی (SSTP)"), ("linux", "سرور لینوکس (Xray و AmneziaWG)")]
UM_ROLES = ("main", "um2")


class RouterDialog(QDialog):
    def __init__(self, parent, router):
        super().__init__(parent)
        self.router = dict(router)
        self.setWindowTitle("مشخصات روتر")
        self.setLayoutDirection(Qt.RightToLeft)
        self.setMinimumWidth(480)
        lay = QVBoxLayout(self)

        def field(label, widget):
            lay.addWidget(QLabel(label))
            lay.addWidget(widget)
            return widget

        self.name = field("نام (برای خودتان):", QLineEdit(router.get("name", "")))
        self.role = QComboBox()
        for key, label in ROLES:
            self.role.addItem(label, key)
        self.role.setCurrentIndex(max(0, [k for k, _ in ROLES].index(router.get("role") or "main")))
        field("نقش:", self.role)
        row = QHBoxLayout()
        self.host = QLineEdit(router.get("host", ""))
        self.host.setLayoutDirection(Qt.LeftToRight)
        self.host.setPlaceholderText("IP یا دامنه")
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(int(router.get("port") or 22))
        row.addWidget(self.host, 1)
        row.addWidget(QLabel("پورت SSH:"))
        row.addWidget(self.port)
        lay.addWidget(QLabel("آدرس:"))
        lay.addLayout(row)
        self.user = field("نام کاربری روتر:", QLineEdit(router.get("user") or "pvtool"))
        self.user.setLayoutDirection(Qt.LeftToRight)
        self.password = field("رمز (رمزنگاری‌شده روی همین ویندوز ذخیره می‌شود):", QLineEdit(router.get("password", "")))
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setLayoutDirection(Qt.LeftToRight)

        krow = QHBoxLayout()
        self.key = QLabel(router.get("hostkey") or "کلید SSH: بعد از اولین اتصال ثبت می‌شود")
        self.key.setObjectName("Hint")
        self.key.setWordWrap(True)
        forget = QPushButton("فراموش کردن کلید")
        forget.setToolTip("فقط وقتی روتر را از نو نصب کرده‌اید")
        forget.clicked.connect(self.forget_key)
        krow.addWidget(self.key, 1)
        krow.addWidget(forget)
        lay.addLayout(krow)

        hint = QLabel("روتر: کاربر را بسازید:  /user add name=pvtool group=full password=…\n"
                      "سرور لینوکس: کاربر root و رمز آن.")
        hint.setObjectName("Hint")
        hint.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(hint)

        buttons = QHBoxLayout()
        save = QPushButton("ذخیره")
        save.setObjectName("Primary")
        save.clicked.connect(self.save)
        cancel = QPushButton("انصراف")
        cancel.clicked.connect(self.reject)
        buttons.addWidget(save, 1)
        buttons.addWidget(cancel)
        lay.addLayout(buttons)

    def forget_key(self):
        self.router["hostkey"] = ""
        self.key.setText("کلید SSH: در اتصال بعدی دوباره ثبت می‌شود")

    def save(self):
        if not self.host.text().strip() or not self.password.text():
            return QMessageBox.warning(self, "خطا", "آدرس و رمز لازم است.")
        old_host = self.router.get("host")
        self.router.update(name=self.name.text().strip(), role=self.role.currentData(),
                           host=self.host.text().strip(), port=self.port.value(),
                           user=self.user.text().strip(), password=self.password.text())
        if old_host and old_host != self.router["host"]:
            self.router["hostkey"] = ""      # another machine, another key
        self.accept()


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


class ServersPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        self.busy = False
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(14)

        c1, l1 = card("روترها")
        self.list = QListWidget()
        self.list.setMinimumHeight(140)
        self.list.currentRowChanged.connect(lambda _: self.show_backups())
        self.list.itemDoubleClicked.connect(lambda _: self.edit())
        l1.addWidget(self.list)
        row = QHBoxLayout()
        self.btn_add = QPushButton("＋ افزودن")
        self.btn_add.clicked.connect(self.add)
        self.btn_edit = QPushButton("ویرایش")
        self.btn_edit.clicked.connect(self.edit)
        self.btn_del = QPushButton("حذف")
        self.btn_del.clicked.connect(self.delete)
        self.btn_test = QPushButton("بررسی اتصال")
        self.btn_test.clicked.connect(self.test)
        for b in (self.btn_add, self.btn_edit, self.btn_del, self.btn_test):
            row.addWidget(b)
        row.addStretch()
        l1.addLayout(row)
        lay.addWidget(c1)

        c2, l2 = card("بکاپ")
        brow = QHBoxLayout()
        self.btn_one = QPushButton("بکاپ از همین روتر")
        self.btn_one.clicked.connect(lambda: self.backup(only_selected=True))
        self.btn_all = QPushButton("بکاپ از همه")
        self.btn_all.setObjectName("Primary")
        self.btn_all.setCursor(Qt.PointingHandCursor)
        self.btn_all.clicked.connect(lambda: self.backup(only_selected=False))
        brow.addWidget(self.btn_all, 1)
        brow.addWidget(self.btn_one)
        l2.addLayout(brow)
        self.backups = QListWidget()
        self.backups.setMinimumHeight(110)
        l2.addWidget(self.backups)
        frow = QHBoxLayout()
        self.btn_folder = QPushButton("باز کردن پوشه")
        self.btn_folder.clicked.connect(self.open_folder)
        self.btn_verify = QPushButton("بررسی بکاپ انتخاب‌شده")
        self.btn_verify.clicked.connect(self.verify)
        frow.addWidget(self.btn_folder)
        frow.addWidget(self.btn_verify)
        frow.addStretch()
        self.btn_export = QPushButton("خروجی تنظیمات برنامه…")
        self.btn_export.setToolTip("همه‌ی تنظیمات، رمزها، کلیدهای سرور لینوکس، config.json و کلید امضا در یک فایل رمزدار؛\n"
                                   "برای اجرای برنامه روی کامپیوتر دیگر.")
        self.btn_export.clicked.connect(self.export_tool)
        self.btn_import = QPushButton("وارد کردن تنظیمات…")
        self.btn_import.clicked.connect(self.import_tool)
        frow.addWidget(self.btn_export)
        frow.addWidget(self.btn_import)
        l2.addLayout(frow)
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setMaximumHeight(8)
        self.bar.hide()
        l2.addWidget(self.bar)
        self.log = QPlainTextEdit()
        self.log.setObjectName("Log")
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(110)
        l2.addWidget(self.log)
        lay.addWidget(c2, 1)
        self.reload()

    @property
    def settings(self):
        return self.main.settings

    def ask_password(self, title, text, twice=False):
        from PySide6.QtWidgets import QInputDialog
        pw, ok = QInputDialog.getText(self, title, text, QLineEdit.Password, self.settings.backup_password)
        if not ok or not pw:
            return None
        if twice and pw != self.settings.backup_password:
            again, ok = QInputDialog.getText(self, title, "تکرار رمز:", QLineEdit.Password)
            if not ok or again != pw:
                self.fail("دو رمز یکی نیستند.")
                return None
        return pw

    def export_tool(self):
        import toolbackup
        pw = self.ask_password("خروجی تنظیمات برنامه",
                               "رمز فایل (پیش‌فرض: همان رمز بکاپ). بدون این رمز فایل باز نمی‌شود:", twice=True)
        if not pw:
            return
        path, _ = QFileDialog.getSaveFileName(self, "ذخیره‌ی خروجی تنظیمات",
                                              "persian-vpn-tool-%s%s" % (bk.stamp(), bk.EXT),
                                              "Persian VPN (*%s)" % bk.EXT)
        if not path:
            return
        try:
            blob = toolbackup.export_bytes(self.settings, pw)
            with open(path, "wb") as f:
                f.write(blob)
        except (pb.ReleaseError, OSError) as e:
            return self.fail(str(e))
        QMessageBox.information(self, "انجام شد",
            "خروجی ذخیره شد:\n%s\n\nاین فایل کلید امضا و همه‌ی رمزها را دارد؛ فقط با فلش یا انتقال مستقیم "
            "جابه‌جایش کنید و رمزش را جایی جدا نگه دارید." % path)

    def import_tool(self):
        import toolbackup
        path, _ = QFileDialog.getOpenFileName(self, "فایل خروجی تنظیمات برنامه", "",
                                              "Persian VPN (*%s);;All files (*)" % bk.EXT)
        if not path:
            return
        pw = self.ask_password("وارد کردن تنظیمات", "رمز این فایل:")
        if not pw:
            return
        try:
            with open(path, "rb") as f:
                data = toolbackup.read(f.read(), pw)
        except (pb.ReleaseError, OSError) as e:
            return self.fail(str(e))
        default = self.settings.workspace or data["settings"].get("workspace") or st.DEFAULT_WORKSPACES[0]
        ws = QFileDialog.getExistingDirectory(self, "پوشه‌ی کاری (جای config.json و کلید امضا)", default)
        if not ws:
            return
        n = len(data["settings"].get("routers", []))
        if QMessageBox.question(self, "تأیید",
                "تنظیمات فعلی این برنامه با محتوای فایل (ساخته‌شده در %s، %d سرور) جایگزین می‌شود و "
                "config.json و کلید امضا در «%s» نوشته می‌شوند (نسخه‌ی قبلی با پسوند .bak می‌ماند).\nادامه؟"
                % (data.get("created", "?"), n, ws)) != QMessageBox.Yes:
            return
        try:
            written = toolbackup.apply(data, self.settings, ws)
        except (pb.ReleaseError, OSError) as e:
            return self.fail(str(e))
        if self.settings.auto_backup:
            try:
                bk.set_schedule(True, self.settings.backup_hours)
            except Exception:
                pass
        self.reload()
        QMessageBox.information(self, "انجام شد",
            "تنظیمات وارد شد (%s).\nبرنامه را یک بار ببندید و دوباره باز کنید.%s"
            % ("، ".join(written) or "بدون فایل پوشه‌ی کاری",
               "\n\nبکاپ خودکار روی این کامپیوتر روشن شد؛ روی کامپیوتر قبلی خاموشش کنید."
               if self.settings.auto_backup else ""))

    def current(self):
        i = self.list.currentRow()
        return self.settings.routers[i] if 0 <= i < len(self.settings.routers) else None

    def reload(self):
        status = st.load_status()
        row = max(0, self.list.currentRow())
        self.list.clear()
        for r in self.settings.routers:
            s = status.get(r["id"], {})
            mark = "✓" if s.get("ok") else ("✗" if s else "•")
            role = dict(ROLES).get(r.get("role"), "")
            text = "%s  %s   —   %s:%s   —   %s   —   آخرین بکاپ: %s" % (
                mark, r.get("name") or r["id"], r["host"], fa(r.get("port", 22)), role, ago(s.get("last_ok")))
            item = QListWidgetItem(text)
            if s and not s.get("ok"):
                item.setToolTip(s.get("error", ""))
            self.list.addItem(item)
        if self.settings.routers:
            self.list.setCurrentRow(min(row, len(self.settings.routers) - 1))
        self.show_backups()
        self.update_buttons()

    def update_buttons(self):
        has, sel = bool(self.settings.routers), self.current() is not None
        for b in (self.btn_edit, self.btn_del, self.btn_test, self.btn_one, self.btn_verify, self.btn_folder):
            b.setEnabled(sel and not self.busy)
        self.btn_all.setEnabled(has and not self.busy)
        self.btn_add.setEnabled(not self.busy)

    def show_backups(self):
        self.backups.clear()
        r = self.current()
        if not r:
            return
        for name in bk.LocalStore(self.settings.backup_dir()).list(r["id"]):
            m = bk.STAMP_RE.search(name)
            label = name
            if m:
                t = _dt.datetime.strptime(m.group(1), "%Y%m%d-%H%M%S")
                label = "%s   (%s)" % (fa(t.strftime("%Y-%m-%d %H:%M")), name)
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, name)
            self.backups.addItem(item)
        self.update_buttons()

    def set_busy(self, busy):
        self.busy = busy
        self.bar.setVisible(busy)
        self.bar.setRange(0, 0)
        self.update_buttons()

    def on_progress(self, done, total):
        if total:
            self.bar.setRange(0, total)
            self.bar.setValue(done)

    def fail(self, text):
        self.set_busy(False)
        self.log.appendPlainText("✗ " + text)
        QMessageBox.warning(self, "خطا", text)

    # ---------------------------------------------------------------- actions

    def add(self):
        d = RouterDialog(self, {"id": self.settings.new_router_id(),
                                "role": "secondary" if self.settings.routers else "main"})
        if d.exec():
            self.settings.routers.append(d.router)
            self.settings.save()
            self.reload()
            self.list.setCurrentRow(len(self.settings.routers) - 1)

    def edit(self):
        r = self.current()
        if not r:
            return
        d = RouterDialog(self, r)
        if d.exec():
            r.update(d.router)
            self.settings.save()
            self.reload()

    def delete(self):
        r = self.current()
        if not r:
            return
        if r.get("role") == "linux":
            return self.delete_linux(r)
        if QMessageBox.question(self, "تأیید", "روتر «%s» از لیست حذف شود؟\n(بکاپ‌هایش پاک نمی‌شوند)"
                                % (r.get("name") or r["host"])) == QMessageBox.Yes:
            self.settings.routers.remove(r)
            self.settings.save()
            self.reload()

    def delete_linux(self, r):
        """A Linux server leaves the apps first (signed config), then the bot's
        list, then this tool; the server itself is left as it is."""
        ws = pb.Workspace(self.settings.workspace)
        try:
            ws.check()
            new_cfg, listed = pv.remove_linux_server(ws.load_config(), r["host"])
        except (pb.ReleaseError, OSError, ValueError) as e:
            return self.fail(str(e))
        label = r.get("name") or r["host"]
        if QMessageBox.question(self, "حذف سرور لینوکس",
                ("سرور «%s»:\n" % label) +
                ("• از تنظیمات اپ برداشته می‌شود و تنظیمات امضا و منتشر می‌شود (گوشی‌ها با باز کردن برنامه دیگر "
                 "سراغش نمی‌روند)\n" if listed else "• در تنظیمات اپ نیست\n") +
                "• از لیست «آنلاین‌ها»ی بات برداشته می‌شود\n• از لیست این ابزار حذف می‌شود\n\n"
                "خود سرور دست نمی‌خورد. اگر تانل پشتیبان SSTP روی این سرور است، اول آن را «برداشتن» "
                "و بعد با سرور جدید «بررسی و راه‌اندازی» کنید.\nادامه؟") != QMessageBox.Yes:
            return
        others = [x for x in self.settings.routers if x is not r]
        ums = [x for x in others if x.get("role") in UM_ROLES]
        github = public = None
        if self.settings.token:
            github = pb.GitHubClient(self.settings.token, self.settings.repo)
            if self.settings.public_repo:
                public = pb.GitHubClient(self.settings.token, self.settings.public_repo)
        if listed:
            import json
            import shutil
            before = ws.path("config.before-%s.json" % bk.stamp())
            shutil.copy(ws.path("config.json"), before)
            with open(ws.path("config.json"), "w", encoding="utf-8") as f:
                json.dump(new_cfg, f, ensure_ascii=False, indent=2)

        def job(log, progress):
            cfg = None
            if listed:
                try:
                    cfg = pb.release_config_only(ws, send_router=True, github=github, public_github=public,
                                                 log=log, progress=progress)
                except Exception:
                    shutil.copy(before, ws.path("config.json"))   # not published: nothing changed
                    raise
            value = linux.bot_linux_status(others)
            for u in ums:
                try:
                    with router_connector(u)() as c:
                        if sv.set_bot_env(c, {"LINUX_STATUS": value}, log):
                            log("✓ بات دیگر سراغ این سرور نمی‌رود.")
                except Exception as e:   # noqa: BLE001
                    log("⚠ تنظیم بات روی %s نشد: %s" % (u["host"], str(e).splitlines()[0]))
            return cfg

        def done(cfg):
            self.set_busy(False)
            self.settings.routers.remove(r)
            self.settings.save()
            self.reload()
            QMessageBox.information(self, "انجام شد", "سرور «%s» حذف شد.%s" % (
                label, "\nتنظیمات جدید اپ: نسخه‌ی %s" % fa(cfg["version"]) if cfg else ""))
        self.set_busy(True)
        run_in_thread(self, job, done, self.fail, self.log.appendPlainText, self.on_progress)

    def test(self):
        r = self.current()
        if not r:
            return
        cfg = dict(r)

        def job(log, progress):
            if cfg.get("role") == "linux":
                with linux.LinuxHost(cfg["host"], cfg["port"], cfg["user"], cfg["password"],
                                     cfg.get("hostkey", "")) as c:
                    os_name = c.run(". /etc/os-release; echo $PRETTY_NAME").strip()
                    return c.seen_hostkey, os_name, c.run("hostname").strip()
            with SSHRouter(cfg["host"], cfg["port"], cfg["user"], cfg["password"], cfg.get("hostkey", "")) as c:
                res = c.run("/system resource print")
                ident = c.run("/system identity print")
                return c.seen_hostkey, "RouterOS " + bk.parse_version(res), ident.split(":", 1)[-1].strip()

        def done(out):
            key, ver, ident = out
            self.set_busy(False)
            new = not r.get("hostkey")
            if new:
                if QMessageBox.question(self, "کلید SSH روتر",
                        "اولین اتصال به این روتر.\nاثر انگشت کلید SSH:\n%s\n\n"
                        "اگر مطمئن هستید این همان روتر شماست، تأیید کنید." % key) != QMessageBox.Yes:
                    return
                r["hostkey"] = key
                self.settings.save()
            self.log.appendPlainText("✓ %s: %s (%s)" % (r.get("name") or r["host"], ver, ident))
            QMessageBox.information(self, "انجام شد", "اتصال برقرار است.\n%s — %s" % (ver, ident))

        self.log.clear()
        self.log.appendPlainText("اتصال به %s:%s…" % (r["host"], r["port"]))
        self.set_busy(True)
        run_in_thread(self, job, done, self.fail, self.log.appendPlainText, self.on_progress)

    def backup(self, only_selected):
        if not self.settings.backup_password:
            return self.fail("اول رمز بکاپ را در ⚙ تنظیمات بگذارید.")
        only = None
        if only_selected:
            r = self.current()
            if not r:
                return
            only = {r["id"]}
        settings = self.settings

        def job(log, progress):
            return bk.backup_all(settings, log, progress, only=only)

        def done(results):
            self.set_busy(False)
            self.reload()
            self.main.check_backups()
            bad = [r for r in results.values() if not r["ok"]]
            warns = sum(len(r.get("warnings", [])) for r in results.values())
            no_gh = [r for r in results.values() if r["ok"] and not r.get("github")]
            if bad:
                QMessageBox.warning(self, "خطا", "\n\n".join(r["error"] for r in bad))
            else:
                msg = "بکاپ کامل شد."
                if warns:
                    msg += "\n%s هشدار (در گزارش پایین)." % fa(warns)
                if no_gh:
                    msg += "\nبه GitHub فرستاده نشد (توکن یا مخزن بکاپ تنظیم نیست)."
                QMessageBox.information(self, "انجام شد", msg)

        self.log.clear()
        self.set_busy(True)
        run_in_thread(self, job, done, self.fail, self.log.appendPlainText, self.on_progress)

    def open_folder(self):
        r = self.current()
        if not r:
            return
        d = bk.LocalStore(self.settings.backup_dir()).dir(r["id"])
        os.makedirs(d, exist_ok=True)
        if sys.platform == "win32":
            os.startfile(d)
        else:
            subprocess.Popen(["xdg-open", d])

    def verify(self):
        item, r = self.backups.currentItem(), self.current()
        if not item or not r:
            return self.fail("یک بکاپ را از لیست انتخاب کنید.")
        path = os.path.join(bk.LocalStore(self.settings.backup_dir()).dir(r["id"]), item.data(Qt.UserRole))
        password = self.settings.backup_password

        def job(log, progress):
            return bk.open_backup(path, password)

        def done(res):
            m, parts = res
            self.set_busy(False)
            files = [p for p in parts if p.startswith("files/")]
            lines = ["✓ بکاپ سالم است و با رمز فعلی باز می‌شود.",
                     "روتر: %s (%s) — RouterOS %s" % (m.get("router_name", ""), m.get("host", ""), m.get("routeros", "")),
                     "زمان: %s" % fa(m.get("created", "")[:16].replace("T", " ")),
                     "تنظیمات کامل: %s" % ("✓" if "export.rsc" in parts else "✗"),
                     "یوزر منیجر: %s" % ("✓" if any(p.startswith("um/") for p in parts) else "—"),
                     "گواهی‌ها: %s" % fa(len(m.get("certificates", []))),
                     "فایل‌ها: %s" % fa(len(files)),
                     "بکاپ باینری: %s" % ("✓" if "system.backup" in parts else "—")]
            if m.get("warnings"):
                lines.append("هشدارها:\n  " + "\n  ".join(m["warnings"]))
            self.log.setPlainText("\n".join(lines))

        self.log.clear()
        self.set_busy(True)
        run_in_thread(self, job, done, self.fail, self.log.appendPlainText, self.on_progress)


# ------------------------------------------------------------------ shared bits of the router pages

def linux_connector(r):
    def connect():
        return linux.LinuxHost(r["host"], r["port"], r["user"], r["password"], r.get("hostkey", "")).connect()
    return connect


def router_connector(r):
    def connect():
        return SSHRouter(r["host"], r["port"], r["user"], r["password"], r.get("hostkey", "")).connect()
    return connect


def scrolled(page):
    """A tab page inside a frameless scroll area."""
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setFrameShape(QFrame.NoFrame)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    area.setStyleSheet("QScrollArea { background: transparent; } QScrollArea > QWidget > QWidget { background: transparent; }")
    area.setWidget(page)
    return area


def human_size(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d %s" if unit == "B" else "%.1f %s") % (n, unit)
        n /= 1024


def router_label(r):
    return "%s  (%s)" % (r.get("name") or r["id"], r["host"])


def pc_package(name, version):
    """Package from mikrotik.com via this PC (when the router cannot download it)."""
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


class RouterPage(QWidget):
    """Base of the pages that work on one router: log, progress, busy state."""

    def __init__(self, main):
        super().__init__()
        self.main = main
        self.busy = False
        self.buttons = []
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setMaximumHeight(8)
        self.bar.hide()
        self.log = QPlainTextEdit()
        self.log.setObjectName("Log")
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(140)

    @property
    def settings(self):
        return self.main.settings

    def button(self, text, slot, primary=False):
        b = QPushButton(text)
        if primary:
            b.setObjectName("Primary")
        b.setCursor(Qt.PointingHandCursor)
        b.clicked.connect(slot)
        self.buttons.append(b)
        return b

    def router_combo(self, roles=None):
        c = QComboBox()
        c.setLayoutDirection(Qt.LeftToRight)
        c.roles = roles
        return c

    def fill_routers(self, combo):
        cur = combo.currentData()
        combo.clear()
        for r in self.settings.routers:
            if combo.roles is None or r.get("role") in combo.roles:
                combo.addItem(router_label(r), r["id"])
        i = combo.findData(cur)
        if i >= 0:
            combo.setCurrentIndex(i)

    def chosen(self, combo):
        return self.settings.router(combo.currentData()) if combo.currentData() else None

    def set_busy(self, busy):
        self.busy = busy
        self.bar.setVisible(busy)
        self.bar.setRange(0, 0)
        for b in self.buttons:
            b.setEnabled(not busy and getattr(b, "allowed", True))

    def on_progress(self, done, total):
        if total:
            self.bar.setRange(0, total)
            self.bar.setValue(done)

    def fail(self, text):
        self.set_busy(False)
        self.log.appendPlainText("✗ " + text)
        QMessageBox.warning(self, "خطا", text)

    def run(self, job, done, clear=True):
        if clear:
            self.log.clear()
        self.set_busy(True)

        def finished(res):
            self.set_busy(False)
            done(res)
        run_in_thread(self, job, finished, self.fail, self.log.appendPlainText, self.on_progress)


# ------------------------------------------------------------------ services & bot

class BotSettingsDialog(QDialog):
    FIELDS = [("BOT_TOKEN", "توکن بات (از BotFather)"), ("ADMIN_IDS", "شناسه‌ی عددی ادمین‌ها (با کاما)"),
              ("USERNAME_PREFIX", "پیشوند نام یوزر جدید"), ("USERNAME_DIGITS", "تعداد رقم نام یوزر"),
              ("PASSWORD_LENGTH", "طول رمز یوزر"), ("STOCK_PREFIX", "فروش یوزرهای آماده با این پیشوند (خالی = همه)"),
              ("INVITE_TTL_HOURS", "اعتبار لینک دعوت (ساعت)"),
              ("REPORT_HOUR", "ساعت گزارش شبانه‌ی فروش (۰ تا ۲۳ به وقت تهران، یا off)")]

    def __init__(self, parent, values, title="تنظیمات بات"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setLayoutDirection(Qt.RightToLeft)
        self.setMinimumWidth(520)
        self.values = dict(values)
        lay = QVBoxLayout(self)
        self.edits = {}
        for key, label in self.FIELDS:
            lay.addWidget(QLabel(label + ":"))
            e = QLineEdit(self.values.get(key, dict(sv.BOT_DEFAULTS).get(key, "")))
            e.setLayoutDirection(Qt.LeftToRight)
            if key == "BOT_TOKEN":
                e.setEchoMode(QLineEdit.Password)
            self.edits[key] = e
            lay.addWidget(e)
        buttons = QHBoxLayout()
        save = QPushButton("ذخیره")
        save.setObjectName("Primary")
        save.clicked.connect(self.save)
        cancel = QPushButton("انصراف")
        cancel.clicked.connect(self.reject)
        buttons.addWidget(save, 1)
        buttons.addWidget(cancel)
        lay.addLayout(buttons)

    def save(self):
        for key, e in self.edits.items():
            self.values[key] = e.text().strip()
        try:
            sv.check_bot_values(self.values)
        except pb.ReleaseError as e:
            return QMessageBox.warning(self, "خطا", str(e))
        self.accept()


class ServicesPage(RouterPage):
    def __init__(self, main):
        super().__init__(main)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(14)

        row = QHBoxLayout()
        row.addWidget(QLabel("روتر اصلی:"))
        self.combo = self.router_combo(("main",))
        row.addWidget(self.combo, 1)
        lay.addLayout(row)

        c1, l1 = card("سرویس وضعیت (umstatus)")
        hint = QLabel("نسخه‌ی همراه این برنامه و کلید عمومی امضا را روی روتر می‌گذارد و سرویس را دوباره راه می‌اندازد.")
        hint.setObjectName("Hint")
        hint.setWordWrap(True)
        l1.addWidget(hint)
        l1.addWidget(self.button("به‌روزرسانی umstatus", self.update_umstatus))
        lay.addWidget(c1)

        c2, l2 = card("بات تلگرام")
        self.bot_state = QLabel("")
        l2.addWidget(self.bot_state)
        r1 = QHBoxLayout()
        r1.addWidget(self.button("وضعیت و گزارش", self.bot_refresh))
        r1.addWidget(self.button("راه‌اندازی دوباره", self.bot_restart))
        r1.addWidget(self.button("تنظیمات بات", self.bot_settings))
        r1.addWidget(self.button("به‌روزرسانی کد از GitHub", self.bot_update))
        l2.addLayout(r1)
        l2.addWidget(self.button("نصب بات روی روتر / انتقال از سرور ویندوز", self.bot_install, primary=True))
        lay.addWidget(c2)

        c6, l6 = card("سرورهای لینوکس (pv-agent)")
        hint6 = QLabel("pv-agent: فقط کد عوض می‌شود؛ یوزرها و تنظیمات دست نمی‌خورند. Xray: سرورها یکی‌یکی؛ "
                       "یوزرهای پروتکل‌های Xray چند ثانیه قطع و خودکار وصل می‌شوند.")
        hint6.setObjectName("Hint")
        hint6.setWordWrap(True)
        l6.addWidget(hint6)
        r6 = QHBoxLayout()
        r6.addWidget(self.button("به‌روزرسانی pv-agent همه‌ی سرورها", self.update_agents))
        r6.addWidget(self.button("به‌روزرسانی Xray همه‌ی سرورها", self.update_xrays))
        l6.addLayout(r6)
        lay.addWidget(c6)

        c4, l4 = card("یوزر منیجر دوم (پشتیبان)")
        r4 = QHBoxLayout()
        r4.addWidget(QLabel("روتر دوم:"))
        self.um2_combo = self.router_combo(("um2",))
        r4.addWidget(self.um2_combo, 1)
        l4.addLayout(r4)
        hint4 = QLabel("دیتابیس یوزر منیجر روتر اصلی هر ۵ دقیقه روی این روتر کپی می‌شود (یوزرها، شارژها، حجم مصرفی). "
                       "اگر پکیج user-manager رویش نیست نصب می‌شود (یک ریستارت). نقش «یوزر منیجر دوم» را در تب "
                       "«سرورها و بکاپ» برایش انتخاب کنید.")
        hint4.setObjectName("Hint")
        hint4.setWordWrap(True)
        l4.addWidget(hint4)
        l4.addWidget(self.button("راه‌اندازی / تازه کردن همگام‌سازی", self.setup_um2))
        lay.addWidget(c4)

        c5, l5 = card("تانل پشتیبان SSTP (AmneziaWG)")
        r5 = QHBoxLayout()
        r5.addWidget(QLabel("سرور لینوکس:"))
        self.bt_combo = self.router_combo(("linux",))
        r5.addWidget(self.bt_combo, 1)
        l5.addLayout(r5)
        hint5 = QLabel("ترافیک کاربران SSTP مثل الان از تانل GRE می‌رود؛ اگر GRE قطع شد خودکار از AmneziaWG به این "
                       "سرور لینوکس می‌رود و با برگشتن GRE، برمی‌گردد. چیزی از تنظیمات فعلی پاک نمی‌شود؛ قبل از "
                       "اعمال، تغییرات نشان داده می‌شود.")
        hint5.setObjectName("Hint")
        hint5.setWordWrap(True)
        l5.addWidget(hint5)
        self.bt_state = QLabel("")
        self.bt_state.setWordWrap(True)
        l5.addWidget(self.bt_state)
        r5b = QHBoxLayout()
        r5b.addWidget(self.button("بررسی و راه‌اندازی", self.backup_setup, primary=True))
        r5b.addWidget(self.button("وضعیت", self.backup_status))
        r5b.addWidget(self.button("برداشتن", self.backup_remove))
        l5.addLayout(r5b)
        lay.addWidget(c5)

        c3, l3 = card("گزارش")
        l3.addWidget(self.bar)
        l3.addWidget(self.log)
        lay.addWidget(c3, 1)
        self.reload()

    def reload(self):
        self.fill_routers(self.combo)
        self.fill_routers(self.um2_combo)
        self.fill_routers(self.bt_combo)

    def backup_setup(self):
        import backuptunnel as bt
        r = self.target()
        if not r:
            return
        tgt = self.chosen(self.bt_combo)
        if not tgt:
            return self.fail("در تب «سرورها و بکاپ» سرور لینوکس را تعریف و از تب «سرور جدید» نصب کنید.")
        params = st.decrypt_blob(tgt.get("params")) or {}
        if not (params.get("awg") or {}).get("priv"):
            return self.fail("روی این سرور لینوکس AmneziaWG نصب نشده است (از تب «سرور جدید» نصبش کنید).")

        def look(log, progress):
            with router_connector(r)() as c:
                return bt.inspect(c)

        def confirm(plan):
            if not plan.ok:
                return self.fail("راه‌اندازی خودکار ممکن نیست:\n" + "\n".join(plan.problems))
            if QMessageBox.question(self, "تانل پشتیبان", bt.describe(plan, tgt["host"]) + "\n\nادامه؟") \
                    != QMessageBox.Yes:
                return

            def job(log, progress):
                with router_connector(r)() as c:
                    return bt.setup(c, linux_connector(tgt), params, tgt["host"], log=log)

            def done(p):
                tgt["params"] = st.encrypt_blob(p)
                self.settings.save()
                QMessageBox.information(self, "انجام شد", "تانل پشتیبان آماده است. «وضعیت» را بزنید تا اتصال "
                                        "به سرور لینوکس (handshake) را ببینید.")
                self.backup_status()
            self.run(job, done, clear=False)
        self.run(look, confirm)

    def backup_status(self):
        import backuptunnel as bt
        r = self.target()
        if not r:
            return
        tgt = self.chosen(self.bt_combo)

        def job(log, progress):
            with router_connector(r)() as c:
                s = bt.status(c)
            if s.get("installed") and tgt:
                params = st.decrypt_blob(tgt.get("params")) or {}
                static = (params.get("awg") or {}).get("static") or {}
                if static:
                    with linux_connector(tgt)() as h:
                        s["linux"] = linux.static_peer_status(h, next(iter(static)))
                        s["icmp"] = linux.icmp_status(h)
            return s

        def done(s):
            if not s.get("installed"):
                self.bt_state.setText("تانل پشتیبان راه‌اندازی نشده است.")
                return
            lines = []
            hs = s.get("handshake")
            lines.append("اتصال به سرور لینوکس: %s" % ("✓ آخرین handshake %s پیش" % hs if hs else "✗ هنوز وصل نشده"))
            lines.append("حجم از تانل پشتیبان: دریافت %s، ارسال %s" % (human_size(s.get("rx", 0)),
                                                                  human_size(s.get("tx", 0))))
            for table, via in sorted((s.get("using") or {}).items()):
                if table != "main":
                    lines.append("جدول %s الان از: %s" % (table, "AmneziaWG (پشتیبان)" if via == "AmneziaWG"
                                                           else "GRE (%s)" % via))
            lines.append("کانتینر رله: %s" % s.get("relay"))
            lx = s.get("linux")
            if lx:
                lines.append("سرور لینوکس از روتر: %s، دریافت %s، ارسال %s" % (
                    "✓ handshake %d ثانیه پیش" % lx[0] if lx[0] is not None else "✗ handshake نشده",
                    human_size(lx[1]), human_size(lx[2])))
            for l in s.get("diag") or []:
                lines.append("بررسی: " + l)
            for l in s.get("log") or []:
                lines.append("رله: " + l)
            lines.append("راه رله به سرور لینوکس: %s" % ("پینگ (ICMP) — UDP بسته است" if s.get("carrier") == "ICMP"
                                                          else "UDP (عادی)"))
            if s.get("icmp"):
                lines.append("پشتیبان پینگ روی لینوکس (pv-icmp): %s" % ("✓ فعال" if s["icmp"] == "active" else
                                                                      "نصب نشده — «بررسی و راه‌اندازی» را دوباره بزنید"
                                                                      if s["icmp"] in ("none", "inactive") else s["icmp"]))
            self.bt_state.setText("\n".join(lines))
        self.run(job, done)

    def backup_remove(self):
        import backuptunnel as bt
        r = self.target()
        if not r:
            return
        if QMessageBox.question(self, "برداشتن تانل پشتیبان",
                                "همه‌ی چیزهایی که تانل پشتیبان ساخته از روتر برداشته می‌شود و تنظیمات GRE مثل "
                                "قبل می‌شود. ادامه؟") != QMessageBox.Yes:
            return

        def job(log, progress):
            with router_connector(r)() as c:
                bt.remove(c, log)
        self.run(job, lambda _: self.bt_state.setText("تانل پشتیبان برداشته شد."))

    def setup_um2(self):
        import um2
        main = self.target()
        if not main:
            return
        sec = self.chosen(self.um2_combo)
        if not sec:
            return self.fail("در تب «سرورها و بکاپ» روتر دوم را با نقش «یوزر منیجر دوم» تعریف کنید.")
        if QMessageBox.question(self, "یوزر منیجر دوم",
                "دیتابیس یوزر منیجر %s هر ۵ دقیقه روی %s کپی می‌شود و هرچه روی %s هست جایگزین می‌شود.\n"
                "اگر پکیج user-manager روی آن نیست، نصب می‌شود و روتر یک بار ری‌استارت می‌شود.\nادامه؟"
                % (main["host"], sec["host"], sec["host"])) != QMessageBox.Yes:
            return

        def job(log, progress):
            return um2.setup_um2(router_connector(main), router_connector(sec), main["host"], log=log)

        def done(res):
            QMessageBox.information(self, "انجام شد",
                "یوزر منیجر دوم همگام شد (%d یوزر).\n\nحالا سرور لینوکس را یک بار دیگر از تب «سرور جدید» اجرا "
                "کنید تا اگر روتر اصلی جواب نداد، سراغ این یکی برود." % res["users"])
        self.run(job, done)

    def target(self):
        r = self.chosen(self.combo)
        if not r:
            self.fail("اول در تب «سرورها و بکاپ» روتر اصلی را تعریف کنید.")
        return r

    def update_umstatus(self):
        r = self.target()
        if not r:
            return
        key = None
        try:
            with open(pb.Workspace(self.settings.workspace).path("config_key.public.txt"), "rb") as f:
                key = f.read()
        except OSError:
            pass

        def job(log, progress):
            with router_connector(r)() as c:
                sv.update_umstatus(c, key, log)
        self.run(job, lambda _: QMessageBox.information(self, "انجام شد", "umstatus به‌روز شد."))

    def update_agents(self):
        servers = [r for r in self.settings.routers if r.get("role") == "linux"]
        if not servers:
            return QMessageBox.warning(self, "خطا", "سرور لینوکسی تعریف نشده است.")

        def job(log, progress):
            bad = []
            for r in servers:
                log("— %s" % r["host"])
                try:
                    with linux_connector(r)() as h:
                        linux.update_agent(h, log)
                except Exception as e:   # noqa: BLE001 - the others still get it
                    log("✗ %s" % e)
                    bad.append(r["host"])
            return bad

        def done(bad):
            if bad:
                QMessageBox.warning(self, "ناقص", "این سرورها به‌روز نشدند: %s" % "، ".join(bad))
            else:
                QMessageBox.information(self, "انجام شد", "pv-agent همه‌ی سرورها به‌روز شد.")
        self.run(job, done)

    def update_xrays(self):
        servers = [r for r in self.settings.routers if r.get("role") == "linux"]
        if not servers:
            return QMessageBox.warning(self, "خطا", "سرور لینوکسی تعریف نشده است.")
        if QMessageBox.question(self, "به‌روزرسانی Xray",
                                "آخرین نسخه‌ی Xray روی %d سرور، یکی‌یکی نصب می‌شود. یوزرهای "
                                "Reality/XHTTP/Hysteria2/Shadowsocks/CDN هر سرور چند ثانیه قطع و خودکار وصل "
                                "می‌شوند (SSTP و AmneziaWG نه). اگر نسخه‌ی جدید تنظیمات را قبول نکند، نسخه‌ی قبلی "
                                "می‌ماند. بهتر است ساعت کم‌ترافیک باشد. ادامه؟" % len(servers)) != QMessageBox.Yes:
            return

        def job(log, progress):
            done = []
            for r in servers:
                log("— %s" % r["host"])
                try:
                    with linux_connector(r)() as h:
                        old, new = linux.update_xray(h, log)
                    done.append("%s: %s" % (r["host"], new if old == new else "%s → %s" % (old, new)))
                except Exception as e:   # noqa: BLE001 - the others still get it
                    log("✗ %s" % e)
                    done.append("%s: ✗ نشد" % r["host"])
            return done
        self.run(job, lambda done: QMessageBox.information(self, "Xray", "\n".join(done)))

    def bot_refresh(self):
        r = self.target()
        if not r:
            return

        def job(log, progress):
            with router_connector(r)() as c:
                return sv.bot_status(c)

        def done(res):
            st_, lines = res
            names = {"running": "در حال اجرا ✓", "stopped": "متوقف", "none": "نصب نشده"}
            self.bot_state.setText("وضعیت بات: " + names.get(st_, st_))
            self.log.setPlainText("\n".join(lines) or "(گزارشی نیست)")
        self.run(job, done)

    def bot_restart(self):
        r = self.target()
        if not r:
            return

        def job(log, progress):
            with router_connector(r)() as c:
                sv.restart(c, sv.UMBOT, log)
        self.run(job, lambda _: self.bot_refresh())

    def bot_settings(self):
        r = self.target()
        if not r:
            return

        def job(log, progress):
            with router_connector(r)() as c:
                return sv.bot_values(c)

        def got(values):
            d = BotSettingsDialog(self, values)
            if not d.exec():
                return

            def save(log, progress):
                with router_connector(r)() as c:
                    port = sv.ensure_rest(c, log)
                    env = sv.parse_env(sv.file_text(c, "umbot/.env") or "")
                    c.put("umbot/.env", sv.render_env(d.values, port, env.get("MT_PASSWORD", "")))
                    sv.restart(c, sv.UMBOT, log)
            self.run(save, lambda _: QMessageBox.information(self, "انجام شد", "تنظیمات بات ذخیره شد."), clear=False)
        self.run(job, got)

    def bot_update(self):
        r = self.target()
        if not r:
            return
        token = self.settings.token
        linux_status = linux.bot_linux_status(self.settings.routers)

        def job(log, progress):
            log("دریافت کد بات از GitHub…")
            code = sv.download_bot_code(token)
            with router_connector(r)() as c:
                sv.install_bot(c, code, {"LINUX_STATUS": linux_status}, log=log)
        self.run(job, lambda _: QMessageBox.information(self, "انجام شد", "کد بات به‌روز شد."))

    def bot_install(self):
        r = self.target()
        if not r:
            return
        env_path, _ = QFileDialog.getOpenFileName(
            self, "فایل .env بات (از سرور ویندوز، C:\\umbot\\.env) — اگر ندارید انصراف بزنید", "", "*")
        values = sv.parse_env(open(env_path, encoding="utf-8-sig").read()) if env_path else {}
        d = BotSettingsDialog(self, values, "تنظیمات بات روی روتر")
        if not d.exec():
            return
        db = None
        db_path, _ = QFileDialog.getOpenFileName(
            self, "دیتابیس بات umbot.sqlite3 (کنار آن umbot.sqlite3-wal و -shm هم باشد) — برای بات تازه انصراف بزنید",
            "", "SQLite (*.sqlite3 *.db);;*")
        if db_path:
            with open(db_path, "rb") as f:
                if not f.read(16).startswith(b"SQLite format 3"):
                    return self.fail("این فایل دیتابیس SQLite نیست.")
            try:
                db, resellers = sv.merged_sqlite(db_path)
            except pb.ReleaseError as e:
                return self.fail(str(e))
            if QMessageBox.question(self, "دیتابیس بات",
                    "در این دیتابیس %s ریسلر هست. همین منتقل شود؟" % fa(resellers)) != QMessageBox.Yes:
                return
        if QMessageBox.question(
                self, "تأیید",
                "قبل از ادامه، بات روی سرور ویندوز را متوقف کنید\n"
                "(Task Scheduler › umbot › End و Disable).\n"
                "دو بات با یک توکن هم‌زمان کار نمی‌کنند.\n\nمتوقف کرده‌اید؟") != QMessageBox.Yes:
            return
        token, values = self.settings.token, dict(d.values, LINUX_STATUS=linux.bot_linux_status(self.settings.routers))

        def job(log, progress):
            log("دریافت کد بات از GitHub…")
            code = sv.download_bot_code(token)
            with router_connector(r)() as c:
                sv.install_bot(c, code, values, db=db, overwrite_db=True, log=log)
                time.sleep(8)
                return sv.bot_status(c)

        def done(res):
            st_, lines = res
            self.log.appendPlainText("\n".join(lines[-15:]))
            QMessageBox.information(self, "انجام شد",
                "بات روی روتر نصب شد (وضعیت: %s).\nیک پیام به بات بدهید تا مطمئن شوید جواب می‌دهد." % st_)
        self.run(job, done)


# ------------------------------------------------------------------ new server

class NewServerPage(RouterPage):
    def __init__(self, main):
        super().__init__(main)
        self.result = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)

        c1, l1 = card("۱. نوع سرور")
        mrow = QHBoxLayout()
        self.mode_main = QRadioButton("سرور اصلی جدید (از روی بکاپ)")
        self.mode_sec = QRadioButton("سرور فرعی (احراز هویت از سرور اصلی)")
        self.mode_linux = QRadioButton("سرور لینوکس (Xray و AmneziaWG)")
        self.mode_main.setChecked(True)
        mrow.addWidget(self.mode_main)
        mrow.addWidget(self.mode_sec)
        mrow.addWidget(self.mode_linux)
        mrow.addStretch()
        l1.addLayout(mrow)
        hint = QLabel("روتر جدید را اول در تب «سرورها و بکاپ» اضافه کنید (CHR تازه، با کاربر pvtool).")
        hint.setObjectName("Hint")
        l1.addWidget(hint)
        lay.addWidget(c1)

        c2, l2 = card("۲. مشخصات")
        grid = QVBoxLayout()

        def row(label, w):
            h = QHBoxLayout()
            lb = QLabel(label)
            lb.setMinimumWidth(150)
            h.addWidget(lb)
            h.addWidget(w, 1)
            grid.addLayout(h)
            return lb

        self.target = self.router_combo()
        row("روتر جدید:", self.target)
        self.source = self.router_combo(("main",))
        row("سرور اصلی فعلی/قدیم:", self.source)
        self.backup = QComboBox()
        self.backup.setLayoutDirection(Qt.LeftToRight)
        self.lbl_backup = row("بکاپ:", self.backup)
        self.ip = QLineEdit()
        self.ip.setLayoutDirection(Qt.LeftToRight)
        self.ip.setPlaceholderText("IP عمومی روتر جدید")
        row("IP عمومی روتر جدید:", self.ip)
        self.domain = QLineEdit()
        self.domain.setLayoutDirection(Qt.LeftToRight)
        self.domain.setPlaceholderText("مثلاً example.com (خالی = بدون CDN و تونل DNS)")
        self.lbl_domain = row("دامنه (Cloudflare):", self.domain)
        self.cf_token = QLineEdit()
        self.cf_token.setLayoutDirection(Qt.LeftToRight)
        self.cf_token.setEchoMode(QLineEdit.Password)
        self.cf_token.setPlaceholderText("API Token با اجازه‌ی DNS Edit و Zone Settings Edit")
        self.lbl_cf = row("توکن Cloudflare:", self.cf_token)
        l2.addLayout(grid)
        orow = QHBoxLayout()
        self.chk_bot = QCheckBox("بات روی سرور قدیم متوقف شود (اگر در دسترس است)")
        self.chk_bot.setChecked(True)
        orow.addWidget(self.chk_bot)
        orow.addStretch()
        orow.addWidget(self.button("بکاپ تازه از سرور اصلی", self.fresh_backup))
        l2.addLayout(orow)
        lay.addWidget(c2)

        c3, l3 = card("۳. اجرا")
        self.btn_go = self.button("شروع / ادامه", self.go, primary=True)
        l3.addWidget(self.btn_go)
        self.btn_cfg = self.button("به‌روزرسانی سرورهای اپ و انتشار", self.publish_servers)
        self.btn_cfg.allowed = False
        self.btn_cfg.setEnabled(False)
        l3.addWidget(self.btn_cfg)
        l3.addWidget(self.bar)
        l3.addWidget(self.log)
        lay.addWidget(c3, 1)

        self.mode_main.toggled.connect(self.update_mode)
        self.mode_linux.toggled.connect(self.update_mode)
        self.target.currentIndexChanged.connect(self.fill_ip)
        self.source.currentIndexChanged.connect(self.fill_backups)
        self.reload()

    def reload(self):
        self.fill_routers(self.target)
        self.fill_routers(self.source)
        self.fill_backups()
        self.fill_ip()
        self.update_mode()

    def update_mode(self):
        main = self.mode_main.isChecked()
        lin = self.mode_linux.isChecked()
        self.chk_bot.setVisible(main)
        self.backup.setVisible(not lin)
        self.lbl_backup.setVisible(not lin)
        for w in (self.domain, self.lbl_domain, self.cf_token, self.lbl_cf):
            w.setVisible(lin)
        self.btn_cfg.setText("به‌روزرسانی سرورهای اپ و انتشار" if main else "اضافه کردن به سرورهای اپ و انتشار")

    def fill_ip(self):
        r = self.chosen(self.target)
        if r:
            self.ip.setText(r["host"])
            p = st.decrypt_blob(r.get("params")) if r.get("role") == "linux" and r.get("params") else {}
            # a saved value fills the field; what was typed is kept otherwise
            if (p or {}).get("domain"):
                self.domain.setText(p["domain"])
            if (p or {}).get("cf_token"):
                self.cf_token.setText(p["cf_token"])

    def fill_backups(self):
        self.backup.clear()
        r = self.chosen(self.source)
        if not r:
            return
        for name in bk.LocalStore(self.settings.backup_dir()).list(r["id"]):
            self.backup.addItem(name, name)

    def fresh_backup(self):
        r = self.chosen(self.source)
        if not r:
            return self.fail("سرور اصلی را انتخاب کنید.")
        if not self.settings.backup_password:
            return self.fail("اول رمز بکاپ را در ⚙ بگذارید.")
        settings = self.settings

        def job(log, progress):
            return bk.backup_all(settings, log, progress, only={r["id"]})

        def done(res):
            self.fill_backups()
            if not res[r["id"]]["ok"]:
                self.fail(res[r["id"]]["error"])
        self.run(job, done)

    def selected_backup(self):
        src = self.chosen(self.source)
        name = self.backup.currentData()
        if not src or not name:
            raise pb.ReleaseError("بکاپی از سرور اصلی انتخاب نشده است (اول بکاپ بگیرید).")
        return os.path.join(bk.LocalStore(self.settings.backup_dir()).dir(src["id"]), name)

    def go_linux(self, tgt, new_ip):
        ums = [r for r in self.settings.routers if r.get("role") in UM_ROLES]
        ums.sort(key=lambda r: r.get("role") != "main")
        if not ums:
            return self.fail("اول روتر یوزر منیجر (اصلی) را در تب «سرورها و بکاپ» تعریف کنید.")
        if tgt.get("role") != "linux":
            return self.fail("نقش این سرور در تب «سرورها و بکاپ» باید «سرور لینوکس» باشد.")
        if QMessageBox.question(self, "تأیید",
                "روی «%s» این‌ها نصب و تنظیم می‌شود:\nXray (Reality، XHTTP، Hysteria2، Shadowsocks)، AmneziaWG و "
                "سرویس هماهنگی با یوزر منیجر.\n\nروی %s هم دسترسی این سرور (RADIUS و REST) ثبت می‌شود.\nادامه می‌دهید؟"
                % (router_label(tgt), "، ".join(router_label(r) for r in ums))) != QMessageBox.Yes:
            return
        name = re.sub(r"[^A-Za-z0-9_-]", "-", tgt.get("name") or tgt["id"])
        params = st.decrypt_blob(tgt.get("params")) or {}
        domain = self.domain.text().strip().lower().rstrip(".")
        if domain and not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", domain):
            return self.fail("دامنه درست نیست: %s" % domain)
        if domain != params.get("domain"):
            params.pop("domain_info", None)
        if domain:
            params["domain"] = domain
        else:
            params.pop("domain", None)
        params["cf_token"] = self.cf_token.text().strip()
        if domain and not params["cf_token"] and QMessageBox.question(
                self, "توکن Cloudflare", "توکن Cloudflare خالی است؛ رکوردهای دامنه را باید خودتان بسازید.\n"
                "بدون توکن ادامه می‌دهید؟") != QMessageBox.Yes:
            return

        others = [r for r in self.settings.routers if r.get("id") != tgt.get("id")]

        def job(log, progress):
            res = linux.setup_linux(linux_connector(tgt), [(router_connector(r), r["host"]) for r in ums],
                                    name, new_ip, params=params, log=log)
            # the bot's "online users" learns about this server
            value = linux.bot_linux_status(others + [dict(tgt, params=st.encrypt_blob(res[0]))])
            for r in ums:
                try:
                    with router_connector(r)() as c:
                        if sv.set_bot_env(c, {"LINUX_STATUS": value}, log):
                            log("✓ بات تلگرام از این سرور خبر دارد (آنلاین‌ها).")
                except Exception as e:
                    log("⚠ تنظیم بات روی %s نشد: %s" % (r["host"], str(e).splitlines()[0]))
            return res

        def done(res):
            p, entry = res
            tgt["params"] = st.encrypt_blob(p)
            self.settings.save()
            self.result = {"linux": True, "entry": entry, "target": tgt["id"], "new_ip": new_ip, "main": False}
            self.log.appendPlainText("\n✓ سرور لینوکس آماده است: %s" % "، ".join(x["type"] for x in entry["protocols"]))
            self.btn_cfg.allowed = True
            self.btn_cfg.setEnabled(True)
            msg = "سرور لینوکس آماده است.\nحالا «%s» را بزنید تا اپ‌ها آن را بشناسند." % self.btn_cfg.text()
            if not any(x["type"] == "amneziawg" for x in entry["protocols"]):
                msg += ("\n\n⚠ AmneziaWG نصب نشد (بقیه‌ی پروتکل‌ها کار می‌کنند). دلیلش در گزارش بالا با علامت ⚠ "
                        "آمده است؛ همان چند خط را بفرستید.")
                QMessageBox.warning(self, "انجام شد، بدون AmneziaWG", msg)
            else:
                QMessageBox.information(self, "انجام شد", msg)
        self.run(job, done)

    def go(self):
        if self.mode_linux.isChecked():
            tgt = self.chosen(self.target)
            if not tgt:
                return self.fail("سرور لینوکس را انتخاب کنید.")
            return self.go_linux(tgt, self.ip.text().strip() or tgt["host"])
        tgt, src = self.chosen(self.target), self.chosen(self.source)
        if not tgt or not src:
            return self.fail("روتر جدید و سرور اصلی را انتخاب کنید.")
        if tgt["id"] == src["id"]:
            return self.fail("روتر جدید و سرور اصلی نمی‌توانند یکی باشند.")
        try:
            path = self.selected_backup()
        except pb.ReleaseError as e:
            return self.fail(str(e))
        new_ip = self.ip.text().strip()
        if not new_ip:
            return self.fail("IP عمومی روتر جدید را وارد کنید.")
        password = self.settings.backup_password
        main_mode = self.mode_main.isChecked()
        what = "سرور اصلی جدید" if main_mode else "سرور فرعی"
        if QMessageBox.question(self, "تأیید",
                "«%s» به عنوان %s راه‌اندازی می‌شود.\nتنظیمات فعلی آن روتر تغییر می‌کند. ادامه می‌دهید؟"
                % (router_label(tgt), what)) != QMessageBox.Yes:
            return
        key = None
        try:
            with open(pb.Workspace(self.settings.workspace).path("config_key.public.txt"), "rb") as f:
                key = f.read()
        except OSError:
            pass
        stop_old = self.chk_bot.isChecked()

        def job(log, progress):
            manifest, parts = bk.open_backup(path, password)
            if main_mode:
                res = pv.restore_main(router_connector(tgt), manifest, parts, new_ip, log=log,
                                      progress=progress, public_key=key, package_source=pc_package)
                if res["status"] == pv.DONE and stop_old:
                    try:
                        with router_connector(src)() as c:
                            if sv.stop_bot_autostart(c, log):
                                log("✓ بات روی سرور قدیم متوقف شد")
                    except Exception as e:
                        log("⚠ سرور قدیم در دسترس نیست (بات آن متوقف نشد): %s" % e)
            else:
                main_ip = pv.old_public_ip(manifest, parts)
                res = pv.setup_secondary(router_connector(tgt), router_connector(src), manifest, parts,
                                         new_ip, main_ip, tgt.get("name") or tgt["id"], log=log)
            res["old_ip"] = res.get("old_ip") or pv.old_public_ip(manifest, parts)
            return res

        def done(res):
            self.result = dict(res, new_ip=new_ip, main=main_mode, target=tgt["id"])
            if res["status"] == pv.NEED_POWER_CYCLE:
                self.log.appendPlainText("\n⏸ منتظر خاموش و روشن کردن سرور")
                QMessageBox.information(self, "یک کار دستی",
                    "برای فعال شدن کانتینر، روتر جدید باید یک بار خاموش و روشن شود:\n\n"
                    "ظرف ۵ دقیقه از پنل سرویس‌دهنده‌ی VPS، سرور را Power Off و بعد Power On کنید\n"
                    "(Reboot معمولی کافی نیست).\n\nبعد از بالا آمدن سرور، دوباره «شروع / ادامه» را بزنید.")
                return
            lines = ["", "نتیجه:"] + ["  " + c for c in res.get("checks", [])]
            if res.get("failed"):
                lines.append("دستورهایی که اجرا نشدند (معمولاً تکراری‌اند و مشکلی ندارند):")
                lines += ["  %s\n     → %s" % (l[:150], e[:150]) for l, e in res["failed"]]
            for why, line in res.get("skipped", []):
                lines.append("  رد شد (%s): %s" % (why, line[:120]))
            self.log.appendPlainText("\n".join(lines))
            bad = [c for c in res.get("checks", []) if c.startswith("✗")]
            self.btn_cfg.allowed = not bad
            self.btn_cfg.setEnabled(not bad)
            if bad:
                QMessageBox.warning(self, "ناقص", "بعضی بررسی‌ها ناموفق بودند:\n" + "\n".join(bad))
            else:
                QMessageBox.information(self, "انجام شد",
                    "سرور آماده است.\nحالا «%s» را بزنید تا اپ‌ها سرور جدید را بشناسند." % self.btn_cfg.text())
        self.run(job, done)

    def publish_servers(self):
        res = self.result
        if not res:
            return
        ws = pb.Workspace(self.settings.workspace)
        try:
            ws.check()
            cfg = ws.load_config()
        except (pb.ReleaseError, OSError, ValueError) as e:
            return self.fail(str(e))
        tgt = self.settings.router(res["target"])
        if res.get("linux"):
            new_cfg = pv.add_linux_server(cfg, res["entry"])
            text = "سرور لینوکس %s به تنظیمات اپ اضافه می‌شود." % res["new_ip"]
        elif res["main"]:
            new_cfg = pv.move_server_in_config(cfg, res["old_ip"], res["new_ip"])
            text = "آدرس سرور اصلی در تنظیمات اپ از %s به %s عوض می‌شود." % (res["old_ip"], res["new_ip"])
        else:
            new_cfg = pv.add_server_to_config(cfg, tgt.get("name") or tgt["id"], res["new_ip"])
            text = "سرور %s به لیست سرورهای اپ اضافه می‌شود." % res["new_ip"]
        if QMessageBox.question(self, "تأیید", text + "\nبعد تنظیمات امضا و منتشر می‌شود. ادامه می‌دهید؟") != QMessageBox.Yes:
            return
        import json
        import shutil
        shutil.copy(ws.path("config.json"), ws.path("config.before-%s.json" % bk.stamp()))
        with open(ws.path("config.json"), "w", encoding="utf-8") as f:
            json.dump(new_cfg, f, ensure_ascii=False, indent=2)
        if res["main"]:
            tgt["role"] = "main"
            self.settings.save()
        github = public = None
        if self.settings.token:
            github = pb.GitHubClient(self.settings.token, self.settings.repo)
            if self.settings.public_repo:
                public = pb.GitHubClient(self.settings.token, self.settings.public_repo)

        def job(log, progress):
            return pb.release_config_only(ws, send_router=True, github=github, public_github=public,
                                          log=log, progress=progress)

        def done(cfg):
            self.btn_cfg.allowed = False
            self.btn_cfg.setEnabled(False)
            self.main.refresh_state()
            QMessageBox.information(self, "انجام شد",
                "تنظیمات جدید (نسخه‌ی %s) منتشر شد.\nگوشی‌ها با باز کردن برنامه آن را می‌گیرند." % fa(cfg["version"]))
        self.run(job, done, clear=False)


# ------------------------------------------------------------------ monitoring

ROLE_SHORT = {"main": "میکروتیک اصلی", "um2": "یوزر منیجر دوم", "secondary": "میکروتیک فرعی", "linux": "لینوکس"}
STATE_FA = {"running": "✓", "active": "✓", "stopped": "✗ متوقف", "failed": "✗ خطا", "inactive": "✗"}


def item(text, align=Qt.AlignCenter):
    it = QTableWidgetItem(str(text))
    it.setTextAlignment(align)
    it.setFlags(it.flags() & ~Qt.ItemIsEditable)
    return it


class MonitorPage(RouterPage):
    COLUMNS = ["سرور", "نوع", "وضعیت", "CPU", "حافظه", "روشن از", "آنلاین", "به تفکیک پروتکل", "سرویس‌ها"]

    def __init__(self, main):
        super().__init__(main)
        self.status = {}
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)

        top = QHBoxLayout()
        self.btn_refresh = self.button("🔄 به‌روزرسانی", self.refresh, primary=True)
        top.addWidget(self.btn_refresh)
        self.auto = QCheckBox("خودکار هر ۶۰ ثانیه")
        self.auto.toggled.connect(self.toggle_auto)
        top.addWidget(self.auto)
        top.addStretch()
        self.total = QLabel("")
        self.total.setObjectName("Hint")
        top.addWidget(self.total)
        lay.addLayout(top)

        c1, l1 = card("سرورها")
        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self.show_users)
        l1.addWidget(self.table)
        lay.addWidget(c1, 1)

        c2, l2 = card("کاربران آنلاین سرور انتخاب‌شده")
        self.users = QTableWidget(0, 4)
        self.users.setHorizontalHeaderLabels(["کاربر", "پروتکل", "آدرس", "مدت / آخرین فعالیت"])
        self.users.verticalHeader().setVisible(False)
        self.users.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        l2.addWidget(self.users)
        l2.addWidget(self.bar)
        lay.addWidget(c2, 1)

        self.timer = QTimer(self)
        self.timer.setInterval(60_000)
        self.timer.timeout.connect(self.tick)

    def toggle_auto(self, on):
        if on:
            self.timer.start()
            self.refresh()
        else:
            self.timer.stop()

    def tick(self):
        if not self.busy and self.main.tabs.currentWidget() is self:
            self.refresh()

    def refresh(self):
        routers = list(self.settings.routers)
        if not routers:
            return self.fail("اول در تب «سرورها و بکاپ» سرورها را تعریف کنید.")

        def connector_for(r):
            return linux_connector(r) if r.get("role") == "linux" else router_connector(r)

        def job(log, progress):
            return monitor.poll(routers, connector_for)

        def done(res):
            self.status = res
            self.fill()
        self.set_busy(True)
        run_in_thread(self, job, lambda r: (self.set_busy(False), done(r)), self.fail, None, None)

    def fill(self):
        routers = self.settings.routers
        sel = self.table.currentRow()
        self.table.setRowCount(len(routers))
        total = 0
        for i, r in enumerate(routers):
            st = self.status.get(r["id"], {})
            ok = st.get("ok")
            cells = [r.get("name") or r["host"], ROLE_SHORT.get(r.get("role"), r.get("role", "")),
                     "🟢 روشن" if ok else ("🔴 در دسترس نیست" if st else "—")]
            if ok:
                total += st.get("users_online", 0)
                by = "  ".join("%s: %s" % (monitor.proto_name(k), fa(v))
                               for k, v in sorted(st.get("by_protocol", {}).items(), key=lambda kv: -kv[1]))
                svc = "  ".join("%s %s" % (k, STATE_FA.get(v, v)) for k, v in st.get("services", {}).items())
                cells += ["%s٪" % fa(st.get("cpu", 0)), ("%s٪" % fa(st["mem"])) if st.get("mem") is not None else "—",
                          st.get("uptime", ""), fa(st.get("users_online", 0)), by or "—", svc or "—"]
            else:
                cells += ["", "", "", "", st.get("error", ""), ""]
            for c, text in enumerate(cells):
                self.table.setItem(i, c, item(text, Qt.AlignCenter if c not in (7, 8) else Qt.AlignRight | Qt.AlignVCenter))
        if 0 <= sel < len(routers):
            self.table.selectRow(sel)
        self.total.setText("مجموع کاربران آنلاین: %s   —   به‌روزرسانی: %s"
                           % (fa(total), fa(_dt.datetime.now().strftime("%H:%M:%S"))))
        self.show_users()

    def show_users(self):
        i = self.table.currentRow()
        routers = self.settings.routers
        rows = []
        if 0 <= i < len(routers):
            rows = self.status.get(routers[i]["id"], {}).get("online", [])
        self.users.setRowCount(len(rows))
        for k, o in enumerate(rows):
            for c, text in enumerate([o["user"], monitor.proto_name(o["protocol"]), o.get("address", ""),
                                      o.get("since", "")]):
                self.users.setItem(k, c, item(text))


def _features_job(settings):
    def job(log, progress):
        try:
            up = su.Updater(settings.token, settings.repo)
            return up, up.check()
        except su.UpdateError as e:
            raise pb.ReleaseError(str(e))
    return job


def _restart():
    """Start the tool again (with the new code) and close this one."""
    args = sys.argv[1:] if getattr(sys, "frozen", False) else [os.path.abspath(sys.argv[0])] + sys.argv[1:]
    # a onefile .exe started by itself would otherwise reuse this process's
    # unpacked folder, which is deleted as soon as this one closes
    env = dict(os.environ, PYINSTALLER_RESET_ENVIRONMENT="1")
    flags = 0x00000008 | 0x00000200 if os.name == "nt" else 0   # DETACHED_PROCESS | NEW_PROCESS_GROUP
    subprocess.Popen([sys.executable] + args, env=env, close_fds=True, creationflags=flags)
    QApplication.instance().quit()


class FeaturesMixin:
    """"Get new features": only the changed source files (selfupdate.py)."""

    def check_features(self, silent):
        if getattr(self, "_checking_features", False):
            return
        if silent and not (self.settings.token and self.settings.repo):
            return
        self._checking_features = True
        if not silent:
            self.btn_new.setText("⏳ بررسی…")

        def done(result):
            self._checking_features = False
            up, plan = result
            if silent:
                if not plan.up_to_date and not plan.needs_new_exe:
                    self.btn_new.setText("⬇ امکانات جدید آماده است")
                    self.btn_new.setStyleSheet("background:#16a34a;")
                return
            self.btn_new.setText("⬇ امکانات جدید")
            self.offer_features(up, plan)

        def failed(err):
            self._checking_features = False
            self.btn_new.setText("⬇ امکانات جدید")
            if not silent:
                QMessageBox.warning(self, "امکانات جدید", err)
        run_in_thread(self, _features_job(self.settings), done, failed)

    def offer_features(self, up, plan):
        actions_url = "https://github.com/%s/actions/workflows/%s" % (self.settings.repo, su.WORKFLOW)
        if plan.needs_new_exe:
            QMessageBox.information(
                self, "امکانات جدید",
                "نسخه‌ی جدید به کتابخانه‌های تازه‌ای نیاز دارد که فقط با دانلود کامل برنامه می‌آیند.\n"
                "یک بار فایل PersianVPN-Release را از GitHub دریافت کنید:\n%s" % actions_url)
            return
        if plan.up_to_date:
            QMessageBox.information(self, "امکانات جدید",
                                    "برنامه به‌روز است (%s)." % su.version_text())
            return
        what = "%s فایل، حدود %s کیلوبایت" % (fa(len(plan.changes)), fa(max(1, plan.size // 1024)))
        note = "" if plan.tested else "\n⚠ تست خودکار این نسخه قابل بررسی نبود (توکن به Actions دسترسی ندارد)."
        if QMessageBox.question(
                self, "امکانات جدید",
                "نسخه‌ی جدید آماده است%s: %s.\nدریافت شود و برنامه دوباره باز شود؟%s"
                % (" (#%s)" % fa(plan.run) if plan.run else "", what, note)) != QMessageBox.Yes:
            return
        if self.busy:
            return QMessageBox.warning(self, "امکانات جدید", "اول کار در حال اجرا تمام شود.")

        def job(log, progress):
            try:
                return up.apply(plan, log)
            except (su.UpdateError, OSError) as e:
                raise pb.ReleaseError("دریافت امکانات جدید ناموفق بود: %s" % e)

        def done(_files):
            QMessageBox.information(self, "امکانات جدید", "دریافت شد. برنامه دوباره باز می‌شود.")
            _restart()
        self.btn_new.setText("⏳ دریافت…")
        run_in_thread(self, job, done,
                      lambda e: (self.btn_new.setText("⬇ امکانات جدید"),
                                 QMessageBox.warning(self, "امکانات جدید", e)),
                      lambda line: self.btn_new.setText("⏳ " + line[:30]))


# ------------------------------------------------------------------ main window

class MainWindow(QMainWindow, FeaturesMixin):
    def __init__(self):
        super().__init__()
        self.settings = Settings.load()
        self.build = None
        self.busy = False

        self.setWindowTitle("Persian VPN — مدیریت")
        icon = resource("icon-512.png")
        if icon:
            self.setWindowIcon(QIcon(icon))
        self.setLayoutDirection(Qt.RightToLeft)
        self.resize(760, 860)
        screen = QApplication.primaryScreen()
        if screen is not None:                    # never taller than the screen (taskbar left out)
            free = screen.availableGeometry()
            self.resize(min(760, free.width() - 40), min(860, free.height() - 60))
            self.move(free.x() + (free.width() - self.width()) // 2, free.y() + 10)

        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        lay = QVBoxLayout(root)
        lay.setContentsMargins(26, 20, 26, 22)
        lay.setSpacing(14)

        # header
        head = QHBoxLayout()
        if icon:
            logo = QLabel()
            logo.setPixmap(QPixmap(icon).scaled(56, 56, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            head.addWidget(logo)
        titles = QVBoxLayout()
        t = QLabel("Persian VPN")
        t.setObjectName("Title")
        sub = QLabel("انتشار نسخه، تنظیمات سرور و بکاپ روترها")
        sub.setObjectName("Subtitle")
        titles.addWidget(t)
        titles.addWidget(sub)
        head.addLayout(titles, 1)
        self.btn_new = QPushButton("⬇ امکانات جدید")
        self.btn_new.setToolTip("دریافت فقط کدهای تغییرکرده از GitHub، بدون دانلود دوباره‌ی کل برنامه\n"
                                + su.version_text())
        self.btn_new.clicked.connect(lambda: self.check_features(False))
        head.addWidget(self.btn_new, 0, Qt.AlignTop)
        QTimer.singleShot(2000, lambda: self.check_features(True))
        phone = QPushButton("📱 انتقال به گوشی")
        phone.setToolTip("همه‌ی تنظیمات، رمزها و کلید امضا در یک فایل رمزدار برای برنامه‌ی اندروید «Persian Admin»")
        phone.clicked.connect(self.transfer_to_phone)
        head.addWidget(phone, 0, Qt.AlignTop)
        gear = QPushButton("⚙")
        gear.setObjectName("Gear")
        gear.setToolTip("تنظیمات")
        gear.clicked.connect(self.open_settings)
        head.addWidget(gear, 0, Qt.AlignTop)
        lay.addLayout(head)
        self.warn = QLabel("")
        self.warn.setObjectName("Warn")
        self.warn.setWordWrap(True)
        self.warn.hide()
        lay.addWidget(self.warn)

        self.tabs = QTabWidget()
        lay.addWidget(self.tabs, 1)
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(14)
        # every page scrolls: on a laptop screen the lower buttons stay reachable
        self.tabs.addTab(scrolled(page), "انتشار")
        self.servers = ServersPage(self)
        self.tabs.addTab(scrolled(self.servers), "سرورها و بکاپ")
        self.services = ServicesPage(self)
        self.tabs.addTab(scrolled(self.services), "سرویس‌ها و بات")
        self.newserver = NewServerPage(self)
        self.tabs.addTab(scrolled(self.newserver), "سرور جدید")
        self.monitor = MonitorPage(self)
        self.tabs.addTab(scrolled(self.monitor), "مانیتورینگ")
        self.tabs.currentChanged.connect(lambda _: (self.services.reload(), self.newserver.reload()))

        # 1. build
        c1, l1 = card("۱. فایل برنامه")
        self.drop = DropArea()
        self.drop.fileDropped.connect(self.load_build)
        l1.addWidget(self.drop)
        row = QHBoxLayout()
        self.btn_fetch = QPushButton("⤓  دریافت آخرین بیلد از GitHub")
        self.btn_fetch.clicked.connect(self.fetch_latest)
        row.addWidget(self.btn_fetch)
        row.addStretch()
        row.addWidget(QLabel("شماره‌ی نسخه:"))
        self.code = QSpinBox()
        self.code.setRange(1, 1000000)
        self.code.setLayoutDirection(Qt.LeftToRight)
        self.code.valueChanged.connect(lambda v: self.name.setText("1.0.%d" % v))
        row.addWidget(self.code)
        row.addWidget(QLabel("نام نسخه:"))
        self.name = QLineEdit()
        self.name.setLayoutDirection(Qt.LeftToRight)
        self.name.setFixedWidth(90)
        row.addWidget(self.name)
        l1.addLayout(row)
        self.published = QLabel("")
        self.published.setObjectName("Hint")
        l1.addWidget(self.published)
        lay.addWidget(c1)

        # 2. notes
        c2, l2 = card("۲. توضیحات نسخه (به کاربرها نمایش داده می‌شود)")
        self.notes = QPlainTextEdit()
        self.notes.setPlaceholderText("مثلاً: رفع قطع و وصل شدن اتصال، نمایش حجم در نوتیفیکیشن")
        self.notes.setFixedHeight(84)
        l2.addWidget(self.notes)
        lay.addWidget(c2)

        # 3. publish
        c3, l3 = card("۳. انتشار")
        opts = QHBoxLayout()
        self.chk_router = QCheckBox("ارسال به روتر")
        self.chk_router.setChecked(True)
        self.chk_github = QCheckBox("به‌روزرسانی GitHub")
        self.chk_github.setChecked(True)
        opts.addWidget(self.chk_router)
        opts.addWidget(self.chk_github)
        opts.addStretch()
        l3.addLayout(opts)
        self.chk_beta = QCheckBox("🧪 آزمایشی: اول فقط برای یوزرهای تست (اندروید و ویندوز)")
        self.chk_beta.setChecked(True)
        self.chk_beta.setToolTip("یوزرهای تست در ⚙ تنظیمات. بقیه همان نسخه‌ی فعلی را دارند تا «انتشار عمومی» را بزنید.")
        l3.addWidget(self.chk_beta)
        self.beta_box = QFrame()
        bl = QVBoxLayout(self.beta_box)
        bl.setContentsMargins(0, 0, 0, 0)
        self.beta_info = QLabel("")
        self.beta_info.setWordWrap(True)
        bl.addWidget(self.beta_info)
        brow = QHBoxLayout()
        self.btn_promote = QPushButton("✅ انتشار عمومی نسخه‌ی آزمایشی اندروید")
        self.btn_promote.clicked.connect(lambda: self.promote(False))
        self.btn_promote_win = QPushButton("✅ انتشار عمومی نسخه‌ی آزمایشی ویندوز")
        self.btn_promote_win.clicked.connect(lambda: self.promote(True))
        brow.addWidget(self.btn_promote)
        brow.addWidget(self.btn_promote_win)
        bl.addLayout(brow)
        l3.addWidget(self.beta_box)
        self.btn_go = QPushButton("امضا و انتشار")
        self.btn_go.setObjectName("Primary")
        self.btn_go.setCursor(Qt.PointingHandCursor)
        self.btn_go.clicked.connect(self.publish)
        l3.addWidget(self.btn_go)
        self.btn_cfg = QPushButton("⇄  انتشار فقط تنظیمات سرور (بدون نسخه‌ی جدید)")
        self.btn_cfg.setCursor(Qt.PointingHandCursor)
        self.btn_cfg.setToolTip("بعد از تغییر سرورها در config.json پوشه‌ی کاری")
        self.btn_cfg.clicked.connect(self.publish_config_only)
        l3.addWidget(self.btn_cfg)
        self.btn_win = QPushButton("🖥  انتشار نسخه‌ی ویندوز…")
        self.btn_win.setCursor(Qt.PointingHandCursor)
        self.btn_win.setToolTip("فایل «PersianVPN-Windows» از GitHub (بخش Actions ← Windows client)")
        self.btn_win.clicked.connect(self.publish_windows)
        l3.addWidget(self.btn_win)
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setMaximumHeight(8)
        self.bar.hide()
        l3.addWidget(self.bar)
        self.log = QPlainTextEdit()
        self.log.setObjectName("Log")
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(130)
        l3.addWidget(self.log)
        lay.addWidget(c3, 1)

        self.refresh_state()
        self.check_backups()

    # ---------------------------------------------------------------- state

    def workspace(self):
        return pb.Workspace(self.settings.workspace)

    def refresh_state(self):
        try:
            ws = self.workspace()
            ws.check()
            last = ws.published_version_code()
            self.published.setText("آخرین نسخه‌ی منتشرشده: %s" % (fa(last) if last else "—"))
            if not self.build and self.code.value() <= last:
                self.code.setValue(last + 1)
        except pb.ReleaseError as e:
            self.published.setText("⚠ " + str(e) + " (از ⚙ پوشه‌ی کاری را تنظیم کنید)")
        has_token = bool(self.settings.token)
        self.btn_fetch.setEnabled(has_token and not self.busy)
        self.chk_github.setEnabled(has_token)
        if not has_token:
            self.chk_github.setChecked(False)
            self.chk_github.setToolTip("ابتدا توکن GitHub را در تنظیمات وارد کنید")
        self.btn_go.setEnabled(self.build is not None and not self.busy)
        self.btn_cfg.setEnabled(not self.busy)
        try:
            beta, wbeta = pb.beta_status(self.workspace())
        except (pb.ReleaseError, OSError, ValueError):
            beta = wbeta = None
        parts = []
        if beta:
            parts.append("اندروید %s" % fa(beta.get("version_name") or beta["version_code"]))
        if wbeta:
            parts.append("ویندوز %s" % fa(wbeta["version_code"]))
        self.beta_box.setVisible(bool(parts))
        self.beta_info.setText("🧪 در حال تست (فقط یوزرهای تست): %s" % "، ".join(parts))
        self.btn_promote.setVisible(bool(beta))
        self.btn_promote_win.setVisible(bool(wbeta))
        self.btn_promote.setEnabled(not self.busy)
        self.btn_promote_win.setEnabled(not self.busy)

    def say(self, line):
        self.log.appendPlainText(line)

    def set_busy(self, busy):
        self.busy = busy
        self.drop.setEnabled(not busy)
        self.bar.setVisible(busy)
        self.bar.setRange(0, 0)
        self.refresh_state()

    def on_progress(self, done, total):
        if total:
            self.bar.setRange(0, total)
            self.bar.setValue(done)

    def fail(self, text):
        self.set_busy(False)
        self.say("✗ " + text)
        QMessageBox.warning(self, "خطا", text)

    # ---------------------------------------------------------------- actions

    def open_settings(self):
        if SettingsDialog(self, self.settings).exec():
            self.refresh_state()
            self.servers.reload()
            self.check_backups()

    def transfer_to_phone(self):
        """Everything the phone version needs, in one file locked with a fresh
        password that is shown here (and never stored)."""
        import secrets as _secrets
        import toolbackup
        alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
        pw = "-".join("".join(_secrets.choice(alphabet) for _ in range(4)) for _ in range(4))
        start = os.path.join(os.path.expanduser("~"), "Desktop", "persian-admin%s" % bk.EXT)
        path, _ = QFileDialog.getSaveFileName(self, "فایل انتقال به گوشی", start, "Persian VPN (*%s)" % bk.EXT)
        if not path:
            return
        try:
            blob = toolbackup.export_bytes(self.settings, pw)
            with open(path, "wb") as f:
                f.write(blob)
        except (pb.ReleaseError, OSError) as e:
            return self.fail(str(e))
        box = QMessageBox(self)
        box.setWindowTitle("انتقال به گوشی")
        box.setTextInteractionFlags(Qt.TextSelectableByMouse)
        box.setText(
            "فایل ساخته شد:\n%s\n\n"
            "رمز فایل (فقط همین‌جا نشان داده می‌شود؛ جایی ذخیره نمی‌شود):\n\n    %s\n\n"
            "۱. برنامه‌ی Persian Admin را روی گوشی نصب و باز کنید.\n"
            "۲. این فایل را به گوشی بفرستید (مثلاً تلگرام ← Saved Messages، یا کابل).\n"
            "۳. در برنامه «وارد کردن از فایل» را بزنید، فایل را انتخاب کنید و این رمز را وارد کنید.\n"
            "۴. بعد از وارد کردن، فایل را از تلگرام و این کامپیوتر پاک کنید.\n\n"
            "در فایل: تنظیمات، رمز روترها و سرورها، توکن GitHub، config.json و کلید امضا." % (path, pw))
        box.exec()

    def check_backups(self):
        """Warn when a scheduled backup failed or none is recent."""
        status = st.load_status()
        problems = []
        limit = _dt.timedelta(hours=self.settings.backup_hours * 3)
        now = _dt.datetime.now().astimezone()
        for r in self.settings.routers:
            s = status.get(r["id"], {})
            name = r.get("name") or r["host"]
            if s and not s.get("ok"):
                problems.append("آخرین بکاپ «%s» ناموفق بود: %s" % (name, s.get("error", "")[:160]))
            elif self.settings.auto_backup:
                try:
                    last = _dt.datetime.fromisoformat(s.get("last_ok", ""))
                    if now - last > limit:
                        problems.append("بکاپ «%s» قدیمی است (%s)." % (name, fa(s["last_ok"][:16].replace("T", " "))))
                except ValueError:
                    problems.append("هنوز هیچ بکاپی از «%s» گرفته نشده است." % name)
        if self.settings.routers and not self.settings.backup_password:
            problems.append("رمز بکاپ تنظیم نشده است (⚙).")
        self.warn.setText("⚠ " + "\n⚠ ".join(problems) if problems else "")
        self.warn.setVisible(bool(problems))

    def load_build(self, path):
        try:
            build = pb.read_build(path)
        except (pb.ReleaseError, OSError) as e:
            return self.fail(str(e))
        self.build = build
        self.drop.show_build(build)
        if build.version_code:
            self.code.setValue(build.version_code)
        self.say("فایل بارگذاری شد: %s" % build.source)
        self.refresh_state()

    def fetch_latest(self):
        gh = pb.GitHubClient(self.settings.token, self.settings.repo)
        tmp = tempfile.mkdtemp(prefix="pvpn-")

        def job(log, progress):
            found = gh.latest_build()
            if not found:
                raise pb.ReleaseError("هیچ بیلد قابل‌دانلودی در GitHub پیدا نشد.")
            n, art = found
            log("دانلود بیلد %s…" % fa(n))
            return gh.download_artifact(art, tmp, progress)

        self.set_busy(True)
        run_in_thread(self, job,
                      lambda path: (self.set_busy(False), self.load_build(path)),
                      self.fail, self.say, self.on_progress)

    def publish(self):
        if not self.build:
            return
        code, name = self.code.value(), self.name.text().strip()
        if self.build.version_code and code != self.build.version_code:
            ok = QMessageBox.question(
                self, "تأیید",
                "شماره‌ی نسخه (%s) با شماره‌ی فایل بیلد (%s) یکی نیست.\n"
                "اگر یکی نباشند، گوشی‌ها فایل را رد می‌کنند. ادامه می‌دهید؟"
                % (fa(code), fa(self.build.version_code)))
            if ok != QMessageBox.Yes:
                return
        github = public = None
        if self.chk_github.isChecked():
            github = pb.GitHubClient(self.settings.token, self.settings.repo)
            if self.settings.public_repo:
                public = pb.GitHubClient(self.settings.token, self.settings.public_repo)
        ws, build, notes = self.workspace(), self.build, self.notes.toPlainText()
        send_router = self.chk_router.isChecked()
        testers = self.testers_or_none()
        if testers is False:
            return

        def job(log, progress):
            return pb.release(ws, build, code, name, notes, send_router=send_router,
                              github=github, public_github=public, log=log, progress=progress,
                              testers=testers)

        def done(cfg):
            self.set_busy(False)
            if testers is not None:
                v = fa(cfg["app_update_beta"]["version_name"])
                self.say("✓ نسخه‌ی آزمایشی %s منتشر شد (فقط برای: %s)." % (v, "، ".join(testers)))
                QMessageBox.information(
                    self, "نسخه‌ی آزمایشی",
                    "نسخه‌ی %s فقط برای یوزرهای تست منتشر شد (%s).\n"
                    "روی گوشی خودتان برنامه را باز کنید و به‌روزرسانی «آزمایشی» را نصب کنید.\n"
                    "اگر سالم بود، «✅ انتشار عمومی نسخه‌ی آزمایشی اندروید» را بزنید." % (v, "، ".join(testers)))
                self.build = None
                self.drop.text.setText("فایل بیلد را اینجا بکشید یا کلیک کنید")
                self.drop.sub.setText("فایل zip دانلودشده از GitHub یا فایل APK")
                self.drop._restyle(loaded="false")
                self.notes.clear()
                self.refresh_state()
                return
            self.say("✓ انتشار نسخه‌ی %s کامل شد." % fa(cfg["app_update"]["version_name"]))
            if cfg.get("_public_failed"):
                QMessageBox.warning(self, "هشدار",
                    "نسخه منتشر شد، ولی مخزن عمومی پشتیبان به‌روز نشد:\n%s\n\n"
                    "معمولاً یعنی توکن به مخزن عمومی دسترسی ندارد." % cfg["_public_failed"])
            QMessageBox.information(
                self, "انجام شد",
                "نسخه‌ی %s منتشر شد.\nکاربرها با باز کردن برنامه، پیام به‌روزرسانی را می‌بینند."
                % fa(cfg["app_update"]["version_name"]))
            self.build = None
            self.drop.text.setText("فایل بیلد را اینجا بکشید یا کلیک کنید")
            self.drop.sub.setText("فایل zip دانلودشده از GitHub یا فایل APK")
            self.drop._restyle(loaded="false")
            self.notes.clear()
            self.refresh_state()

        self.log.clear()
        self.set_busy(True)
        run_in_thread(self, job, done, self.fail, self.say, self.on_progress)

    def publish_windows(self):
        from PySide6.QtWidgets import QInputDialog
        ws = self.workspace()
        try:
            ws.check()
        except (pb.ReleaseError, OSError) as e:
            return self.fail(str(e))
        box = QMessageBox(self)
        box.setWindowTitle("انتشار نسخه‌ی ویندوز")
        box.setText("آخرین نسخه‌ی اپ ویندوز از GitHub دریافت و منتشر شود؟")
        b_gh = box.addButton("دریافت از GitHub", QMessageBox.AcceptRole)
        b_file = box.addButton("انتخاب فایل zip…", QMessageBox.ActionRole)
        box.addButton("انصراف", QMessageBox.RejectRole)
        box.exec()
        if box.clickedButton() is b_file:
            path, _ = QFileDialog.getOpenFileName(self, "فایل PersianVPN-Windows از GitHub", "", "zip (*.zip)")
            if not path:
                return
            try:
                win = pb.read_windows_build(path)
            except pb.ReleaseError as e:
                return self.fail(str(e))
            return self._publish_windows(ws, win)
        if box.clickedButton() is not b_gh:
            return
        if not (self.settings.token and self.settings.repo):
            return self.fail("برای دریافت از GitHub، توکن و نام مخزن را در تنظیمات وارد کنید.")
        gh = pb.GitHubClient(self.settings.token, self.settings.repo)
        tmp = tempfile.mkdtemp(prefix="pvwin-")

        def fetch(log, progress):
            art = gh.latest_windows()
            if not art:
                raise pb.ReleaseError("نسخه‌ی ویندوزی در GitHub پیدا نشد (یا قدیمی و پاک شده است).")
            log("دانلود اپ ویندوز از GitHub…")
            return pb.read_windows_build(gh.download_artifact(art, tmp, progress))

        def fetched(win):
            self.set_busy(False)
            self._publish_windows(ws, win)

        self.log.clear()
        self.set_busy(True)
        run_in_thread(self, fetch, fetched, self.fail, self.say, self.on_progress)

    def _publish_windows(self, ws, win):
        from PySide6.QtWidgets import QInputDialog
        try:
            now = int((ws.load_config().get("windows_update") or {}).get("version_code", 0))
        except (pb.ReleaseError, OSError, ValueError):
            now = 0
        if now and win.version_code <= now:
            if QMessageBox.question(
                    self, "نسخه‌ی ویندوز",
                    "نسخه‌ی %s همین الان منتشر شده است (آخرین روی GitHub: %s).\nدوباره منتشر شود؟"
                    % (fa(now), fa(win.version_code))) != QMessageBox.Yes:
                return
        notes, ok = QInputDialog.getMultiLineText(
            self, "نسخه‌ی ویندوز %s" % fa(win.version_code),
            "نسخه‌ی منتشرشده‌ی فعلی: %s\nتوضیح تغییرات (اختیاری؛ به کاربر نشان داده می‌شود):"
            % (fa(now) if now else "—"))
        if not ok:
            return
        github = public = None
        if self.chk_github.isChecked():
            github = pb.GitHubClient(self.settings.token, self.settings.repo)
            if self.settings.public_repo:
                public = pb.GitHubClient(self.settings.token, self.settings.public_repo)
        send_router = self.chk_router.isChecked()
        testers = self.testers_or_none()
        if testers is False:
            return

        def job(log, progress):
            return pb.release_config_only(ws, send_router=send_router, github=github, public_github=public,
                                          log=log, progress=progress, win=win, win_notes=notes,
                                          win_testers=testers)

        def done(cfg):
            self.set_busy(False)
            if testers is not None:
                self.say("✓ نسخه‌ی آزمایشی ویندوز %d فقط برای یوزرهای تست منتشر شد." % win.version_code)
                QMessageBox.information(self, "نسخه‌ی آزمایشی",
                    "نسخه‌ی ویندوز %s فقط برای یوزرهای تست منتشر شد.\n"
                    "اگر سالم بود، «✅ انتشار عمومی نسخه‌ی آزمایشی ویندوز» را بزنید." % fa(win.version_code))
                self.refresh_state()
                return
            self.say("✓ نسخه‌ی ویندوز %d منتشر شد (تنظیمات %s)." % (win.version_code, fa(cfg["version"])))
            QMessageBox.information(self, "انجام شد",
                "نسخه‌ی ویندوز منتشر شد.\nبرنامه‌های ویندوز موقع باز شدن پیشنهاد به‌روزرسانی می‌دهند.\n\n"
                "برای نصب اول، فایل PersianVPN.exe داخل همان zip را به کاربران بدهید.")
            self.refresh_state()

        self.log.clear()
        self.set_busy(True)
        run_in_thread(self, job, done, self.fail, self.say, self.on_progress)

    def testers_or_none(self):
        """Usernames for a test release, None for a public one, False = cancelled."""
        if not self.chk_beta.isChecked():
            if QMessageBox.question(
                    self, "انتشار عمومی",
                    "تیک «آزمایشی» برداشته شده: این نسخه همین الان برای همه‌ی کاربران منتشر می‌شود.\nادامه؟"
                    ) != QMessageBox.Yes:
                return False
            return None
        if not self.settings.testers:
            QMessageBox.warning(self, "یوزرهای تست",
                                "اول یوزرهای تست (مثلاً یوزر خودتان) را در ⚙ تنظیمات وارد کنید.")
            return False
        return list(self.settings.testers)

    def promote(self, windows):
        what = "ویندوز" if windows else "اندروید"
        if QMessageBox.question(
                self, "انتشار عمومی",
                "نسخه‌ی آزمایشی %s، همان فایلی که تست کردید، برای همه‌ی کاربران منتشر شود؟" % what
                ) != QMessageBox.Yes:
            return
        github = public = None
        if self.chk_github.isChecked():
            github = pb.GitHubClient(self.settings.token, self.settings.repo)
            if self.settings.public_repo:
                public = pb.GitHubClient(self.settings.token, self.settings.public_repo)
        ws, send_router = self.workspace(), self.chk_router.isChecked()
        fn = pb.promote_win_beta if windows else pb.promote_beta

        def job(log, progress):
            return fn(ws, send_router=send_router, github=github, public_github=public, log=log, progress=progress)

        def done(cfg):
            self.set_busy(False)
            self.say("✓ نسخه‌ی %s برای همه منتشر شد." % what)
            QMessageBox.information(self, "انجام شد", "نسخه‌ی %s برای همه‌ی کاربران منتشر شد." % what)
            self.refresh_state()

        self.log.clear()
        self.set_busy(True)
        run_in_thread(self, job, done, self.fail, self.say, self.on_progress)

    def publish_config_only(self):
        ws = self.workspace()
        try:
            ws.check()
            cfg = ws.load_config()
        except (pb.ReleaseError, OSError, ValueError) as e:
            return self.fail(str(e))
        servers = "\n".join("  • %s  (%s:%s)" % (s.get("name", ""), s.get("host", ""), s.get("port", 443))
                             for s in cfg.get("servers", []))
        router = (cfg.get("config_urls") or ["—"])[0].split("/v1/")[0]
        send_router = self.chk_router.isChecked()
        github = public = None
        if self.chk_github.isChecked():
            github = pb.GitHubClient(self.settings.token, self.settings.repo)
            if self.settings.public_repo:
                public = pb.GitHubClient(self.settings.token, self.settings.public_repo)
        if not send_router and github is None:
            return self.fail("حداقل یکی از «ارسال به روتر» یا «به‌روزرسانی GitHub» را انتخاب کنید.")
        where = []
        if send_router:
            where.append("روتر: " + router)
        if github is not None:
            where.append("GitHub" + (" + مخزن عمومی" if public else ""))
        ok = QMessageBox.question(
            self, "تأیید",
            "این سرورها از config.json برای همه‌ی کاربران منتشر می‌شوند:\n\n%s\n\nمقصد: %s\n\nادامه می‌دهید؟"
            % (servers or "  (خالی!)", "، ".join(where)))
        if ok != QMessageBox.Yes:
            return

        def job(log, progress):
            return pb.release_config_only(ws, send_router=send_router, github=github,
                                          public_github=public, log=log, progress=progress)

        def done(cfg):
            self.set_busy(False)
            self.say("✓ تنظیمات سرور (نسخه‌ی %s) منتشر شد." % fa(cfg["version"]))
            if cfg.get("_public_failed"):
                QMessageBox.warning(self, "هشدار",
                    "تنظیمات منتشر شد، ولی مخزن عمومی پشتیبان به‌روز نشد:\n%s" % cfg["_public_failed"])
            QMessageBox.information(self, "انجام شد",
                "تنظیمات جدید منتشر شد.\nگوشی‌ها با باز کردن برنامه آن را دریافت می‌کنند.")
            self.refresh_state()

        self.log.clear()
        self.set_busy(True)
        run_in_thread(self, job, done, self.fail, self.say, self.on_progress)


def make_app(argv):
    app = QApplication(argv)
    app.setLayoutDirection(Qt.RightToLeft)
    # Vazirmatn if installed, otherwise Windows fonts with good Persian glyphs
    f = QFont("Segoe UI", 10)
    f.setFamilies(["Vazirmatn", "Segoe UI", "Tahoma"])
    app.setFont(f)
    app.setStyleSheet(STYLE)
    return app


def smoke():
    """CI check: build the whole window offscreen and close it."""
    app = make_app(sys.argv[:1])
    w = MainWindow()
    w.show()
    app.processEvents()
    SettingsDialog(w, w.settings)  # dialogs build too
    RouterDialog(w, {"id": "r1"})
    BotSettingsDialog(w, {})
    for i in range(w.tabs.count()):
        w.tabs.setCurrentIndex(i)
        app.processEvents()
    w.tabs.setCurrentIndex(1)
    app.processEvents()
    # callbacks of background work must run in the GUI thread
    seen = {}
    run_in_thread(w, lambda log, progress: (log("x"), 42)[1],
                  lambda r: seen.update(done=QThread.currentThread() is app.thread(), r=r),
                  lambda e: seen.update(err=e),
                  lambda line: seen.update(log=QThread.currentThread() is app.thread()))
    import time
    end = time.time() + 10
    while "done" not in seen and "err" not in seen and time.time() < end:
        app.processEvents()
        time.sleep(0.01)
    if seen.get("done") is not True or seen.get("r") != 42 or seen.get("log") is not True:
        if sys.stdout:
            print("smoke FAILED: callbacks not in GUI thread: %r" % seen)
        return _quit(app, 3)
    w.close()
    if sys.stdout:            # a windowed .exe has no console
        print("smoke OK")
        sys.stdout.flush()
    return _quit(app, 0)


def _quit(app, code):
    """Exit without Python's late teardown of Qt objects.

    Interpreter shutdown destroys PySide objects in arbitrary order; with
    PySide6 6.12 on Windows this ends the process with code 1 even after a
    clean run (CI, 2026-11-08). Settings are written when saved, so there is
    nothing left to flush here.
    """
    for w in app.topLevelWidgets():
        w.close()
    app.processEvents()
    if sys.stderr:
        sys.stderr.flush()
    os._exit(code)


def main():
    if "--backup-all" in sys.argv:          # Windows scheduled task: no window
        return bk.run_scheduled()
    if "--smoke" in sys.argv:
        return smoke()
    app = make_app(sys.argv)
    w = MainWindow()
    w.show()
    if not os.path.isdir(w.settings.workspace or ""):
        w.open_settings()
    return _quit(app, app.exec())


if __name__ == "__main__":
    sys.exit(main())
