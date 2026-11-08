"""SSH/SFTP access to a MikroTik RouterOS 7 router.

The release tool uses this for backups and for setting up new routers.
The router's SSH host key is remembered on first contact (SHA-256
fingerprint); a different key later is refused, so a hijacked address
cannot collect the admin password or the backup.
"""

import base64
import hashlib
import posixpath
import socket
import stat

from publisher import ReleaseError

# RouterOS prints these instead of a non-zero exit status
ERROR_MARKERS = (
    "failure:", "syntax error", "expected end of command", "bad command name",
    "input does not match any value", "no such item", "invalid value",
    "expected command name", "missing value", "ambiguous value", "not enough permissions",
)


class RouterOSError(ReleaseError):
    pass


class HostKeyMismatch(RouterOSError):
    pass


def fingerprint(key_bytes):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key_bytes).digest()).decode().rstrip("=")


def check_output(cmd, out):
    low = out.lower()
    for m in ERROR_MARKERS:
        if m in low:
            line = next((l for l in out.splitlines() if m in l.lower()), out.strip())
            raise RouterOSError("روتر این دستور را اجرا نکرد:\n%s\n\n%s" % (cmd[:300], line.strip()[:300]))
    return out


def q(value):
    """RouterOS string literal."""
    s = str(value)
    for a, b in (("\\", "\\\\"), ('"', '\\"'), ("$", "\\$"), ("\n", "\\n"), ("\r", "\\r")):
        s = s.replace(a, b)
    return '"%s"' % s


class SSHRouter:
    def __init__(self, host, port=22, user="", password="", hostkey="", timeout=20):
        self.host, self.port = host, int(port or 22)
        self.user, self.password = user, password
        self.hostkey = hostkey or ""     # expected fingerprint ("" = first contact)
        self.seen_hostkey = ""
        self.timeout = timeout
        self._t = None
        self._sftp = None

    # ---------------------------------------------------------------- connection

    def connect(self):
        try:
            import paramiko
        except ImportError:
            raise RouterOSError("کتابخانه‌ی paramiko نصب نیست.")
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as e:
            raise RouterOSError("اتصال SSH به %s:%d برقرار نشد: %s" % (self.host, self.port, e))
        try:
            t = paramiko.Transport(sock)
            t.banner_timeout = self.timeout
            t.start_client(timeout=self.timeout)
            fp = fingerprint(t.get_remote_server_key().asbytes())
            self.seen_hostkey = fp
            if self.hostkey and fp != self.hostkey:
                t.close()
                raise HostKeyMismatch(
                    "کلید SSH روتر %s عوض شده است!\nقبلی: %s\nفعلی: %s\n\n"
                    "اگر روتر را از نو نصب نکرده‌اید، ممکن است کسی خودش را جای روتر جا زده باشد."
                    % (self.host, self.hostkey, fp))
            try:
                t.auth_password(self.user, self.password)
            except paramiko.AuthenticationException:
                t.close()
                raise RouterOSError("نام کاربری یا رمز روتر %s اشتباه است." % self.host)
            t.set_keepalive(15)
            self._t = t
        except RouterOSError:
            raise
        except Exception as e:
            sock.close()
            raise RouterOSError("ارتباط SSH با %s ناموفق بود: %s" % (self.host, e))
        return self

    def close(self):
        for x in (self._sftp, self._t):
            try:
                if x:
                    x.close()
            except Exception:
                pass
        self._sftp = self._t = None

    def __enter__(self):
        return self.connect() if self._t is None else self

    def __exit__(self, *exc):
        self.close()

    # ---------------------------------------------------------------- commands

    def run(self, cmd, timeout=300, check=True):
        ch = self._t.open_session(timeout=self.timeout)
        try:
            ch.settimeout(timeout)
            ch.exec_command(cmd)
            chunks = []
            while True:
                try:
                    data = ch.recv(65536)
                except socket.timeout:
                    raise RouterOSError("روتر در زمان مقرر جواب نداد:\n%s" % cmd[:200])
                if not data:
                    break
                chunks.append(data)
            err = ch.recv_stderr(65536) if ch.recv_stderr_ready() else b""
        finally:
            ch.close()
        out = (b"".join(chunks) + err).decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "")
        return check_output(cmd, out) if check else out

    # ---------------------------------------------------------------- files

    def sftp(self):
        if self._sftp is None:
            import paramiko
            self._sftp = paramiko.SFTPClient.from_transport(self._t)
        return self._sftp

    def listdir(self, path=""):
        """[(name, is_dir, size)] of one directory ("" = root)."""
        out = []
        for a in self.sftp().listdir_attr(path or "/"):
            out.append((a.filename, stat.S_ISDIR(a.st_mode or 0), a.st_size or 0))
        return out

    def get(self, path, progress=None):
        with self.sftp().open("/" + path.lstrip("/"), "rb") as f:
            f.prefetch()
            return f.read()

    def put(self, path, data, progress=None):
        path = "/" + path.lstrip("/")
        parent = posixpath.dirname(path)
        if parent not in ("", "/"):
            self.makedirs(parent)
        with self.sftp().open(path, "wb") as f:
            f.set_pipelined(True)
            for i in range(0, len(data), 32768):
                f.write(data[i:i + 32768])
                if progress:
                    progress(min(i + 32768, len(data)), len(data))

    def makedirs(self, path):
        cur = ""
        for part in path.strip("/").split("/"):
            cur += "/" + part
            try:
                self.sftp().stat(cur)
            except IOError:
                self.sftp().mkdir(cur)

    def remove(self, path):
        try:
            self.sftp().remove("/" + path.lstrip("/"))
        except IOError:
            pass

    # ---------------------------------------------------------------- helpers

    def walk(self, path="", skip=lambda p: False):
        """Yield (path, size) of every file below path, skipping where skip(path)."""
        for name, is_dir, size in self.listdir(path):
            p = posixpath.join(path, name) if path else name
            if skip(p):
                continue
            if is_dir:
                yield from self.walk(p, skip)
            else:
                yield p, size

    def lines(self, script):
        return [l for l in self.run(script).split("\n") if l.strip()]
