"""Persian VPN release tool (Windows GUI).

Drop the build file (or fetch the newest one from GitHub), write the
release notes, press one button: the tool signs the new config, uploads
config + APK to the router and updates the repository on GitHub.
"""

import os
import sys
import tempfile
import traceback

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtGui import QFont, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QDialog, QFileDialog, QFrame, QGraphicsDropShadowEffect,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit,
    QProgressBar, QPushButton, QSpinBox, QVBoxLayout, QWidget,
)

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import publisher as pb       # noqa: E402
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


def run_in_thread(owner, fn, on_done, on_failed, on_log=None, on_progress=None):
    thread = QThread(owner)
    worker = Worker(fn)
    worker.moveToThread(thread)
    thread.started.connect(worker.run)
    worker.done.connect(on_done)
    worker.failed.connect(on_failed)
    if on_log:
        worker.log.connect(on_log)
    if on_progress:
        worker.progress.connect(on_progress)
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

        lay.addWidget(QLabel("توکن GitHub (رمزنگاری‌شده روی همین ویندوز ذخیره می‌شود):"))
        self.token = QLineEdit(settings.token)
        self.token.setEchoMode(QLineEdit.Password)
        self.token.setLayoutDirection(Qt.LeftToRight)
        self.token.setPlaceholderText("github_pat_…")
        lay.addWidget(self.token)

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
            return " و ".join(names)
        self.result.setText("در حال بررسی GitHub…")
        run_in_thread(self, job, lambda r: self._say("دسترسی به مخزن %s برقرار است." % r, True),
                      lambda e: self._say(e, False))

    def save(self):
        self.settings.workspace = self.ws.text().strip()
        self.settings.repo = self.repo.text().strip()
        self.settings.public_repo = self.public_repo.text().strip()
        self.settings.token = self.token.text().strip()
        self.settings.save()
        self.accept()


# ------------------------------------------------------------------ main window

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = Settings.load()
        self.build = None
        self.busy = False

        self.setWindowTitle("Persian VPN — انتشار نسخه")
        icon = resource("icon-512.png")
        if icon:
            self.setWindowIcon(QIcon(icon))
        self.setLayoutDirection(Qt.RightToLeft)
        self.resize(760, 860)

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
        t = QLabel("انتشار نسخه‌ی جدید")
        t.setObjectName("Title")
        st = QLabel("امضا، ارسال به روتر و به‌روزرسانی GitHub با یک دکمه")
        st.setObjectName("Subtitle")
        titles.addWidget(t)
        titles.addWidget(st)
        head.addLayout(titles, 1)
        gear = QPushButton("⚙")
        gear.setObjectName("Gear")
        gear.setToolTip("تنظیمات")
        gear.clicked.connect(self.open_settings)
        head.addWidget(gear, 0, Qt.AlignTop)
        lay.addLayout(head)

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
        self.btn_go = QPushButton("امضا و انتشار")
        self.btn_go.setObjectName("Primary")
        self.btn_go.setCursor(Qt.PointingHandCursor)
        self.btn_go.clicked.connect(self.publish)
        l3.addWidget(self.btn_go)
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

        def job(log, progress):
            return pb.release(ws, build, code, name, notes, send_router=send_router,
                              github=github, public_github=public, log=log, progress=progress)

        def done(cfg):
            self.set_busy(False)
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
    SettingsDialog(w, w.settings)  # dialog builds too
    w.close()
    if sys.stdout:            # a windowed .exe has no console
        print("smoke OK")
    return 0


def main():
    if "--smoke" in sys.argv:
        return smoke()
    app = make_app(sys.argv)
    w = MainWindow()
    w.show()
    if not os.path.isdir(w.settings.workspace or ""):
        w.open_settings()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
