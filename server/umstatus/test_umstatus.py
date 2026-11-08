import base64
import json
import ssl
import threading
import unittest
import urllib.request
from datetime import datetime

import umstatus as u

MiB = 1024 ** 2

# real numbers from user 25g8282 (download, upload) as the CLI shows them
SESS = [
    ("2026-11-05 19:19:16", "135.0KiB", "182.8KiB"),
    ("2026-11-05 19:57:23", "5.6MiB", "1761.5KiB"),
    ("2026-11-05 20:02:09", "385.4KiB", "484.2KiB"),
    ("2026-11-05 21:18:27", "6.4MiB", "3837.1KiB"),
    ("2026-11-05 22:38:55", "37.4MiB", "14.6MiB"),
    ("2026-11-05 23:08:30", "2170.5KiB", "894.8KiB"),
    ("2026-11-06 00:44:31", "112.0MiB", "21.2MiB"),
    ("2026-11-06 02:31:04", "11.6MiB", "1452.6KiB"),
    ("2026-11-06 02:40:49", "59.1MiB", "7.0MiB"),
    ("2026-11-06 05:11:31", "23.1MiB", "2017.4KiB"),
    ("2026-11-06 11:30:51", "988.4KiB", "794.3KiB"),
    ("2026-11-06 11:35:46", "428.9KiB", "686.7KiB"),
    ("2026-11-06 11:38:08", "23.2MiB", "3650.9KiB"),
    ("2026-11-06 12:14:02", "7.2MiB", "1097.4KiB"),
    ("2026-11-06 21:54:06", "18.9MiB", "8.2MiB"),
    ("2026-11-07 08:01:34", "212.1MiB", "23.5MiB"),
    ("2026-11-07 12:10:28", "1031.0KiB", "484.4KiB"),
    ("2026-11-07 12:49:31", "146.8KiB", "113.7KiB"),
    ("2026-11-07 13:02:00", "126.0MiB", "8.8MiB"),
    ("2026-11-07 17:05:00", "74.8MiB", "5.9MiB"),
    ("2026-11-07 17:27:53", "492.8KiB", "394.5KiB"),
    ("2026-11-07 17:30:12", "5.5MiB", "4.9MiB"),
    ("2026-11-07 19:43:40", "70.2MiB", "10.5MiB"),
]


class FakeRouter(u.Router):
    def __init__(self, password_via="get", extra_sessions=(), profiles=None):
        self.password_via = password_via
        self.session_timeout = 30
        self.calls = []
        self.data = {
            "/system/clock": [{"date": "2026-11-07", "time": "20:10:00"}],
            "/user-manager/profile": [{"name": "30d-25G", "validity": "4w2d",
                                       "name-for-users": "30d"}],
            "/user-manager/profile-limitation": [{"profile": "30d-25G",
                                                  "limitation": "25g"}],
            "/user-manager/limitation": [{"name": "25g", "download-limit": "0",
                                          "upload-limit": "0",
                                          "transfer-limit": "26843545600"}],
            "/user-manager/user-profile": profiles if profiles is not None else [
                {"user": "25g8282", "profile": "30d-25G", "state": "running-active",
                 "end-time": "2026-12-05 19:19:16"}],
            "/user-manager/session": [
                {"user": "25g8282", "started": s, "download": d, "upload": up}
                for s, d, up in list(extra_sessions) + SESS],
        }

    def get(self, path, **q):
        self.calls.append(path)
        if path == "/user-manager/user":
            if q.get("name") != "25g8282":
                return []
            rec = {"name": "25g8282", "disabled": "false"}
            if self.password_via == "get":
                rec["password"] = "ab12cd"
            return [rec]
        rows = self.data[path]
        filt = {k: v for k, v in q.items() if not k.startswith(".")}
        return [r for r in rows if all(r.get(k) == v for k, v in filt.items())]

    def post(self, path, body, timeout=None):
        if path == "/user-manager/user/monitor":
            self.calls.append(path)
            if getattr(self, "post_monitor_override", None):
                return [self.post_monitor_override]
            rows = self.data["/user-manager/session"]
            return [{"total-download": "%dB" % sum(u.parse_size(r["download"]) for r in rows),
                     "total-upload": "%dB" % sum(u.parse_size(r["upload"]) for r in rows)}]
        if path == "/user-manager/session/print":
            self.calls.append(path)
            user = body[".query"][0].split("=", 1)[1]
            return [r for r in self.data["/user-manager/session"] if r["user"] == user]
        assert path == "/user-manager/user/print"
        if self.password_via == "print":
            return [{"name": "25g8282", "password": "ab12cd"}]
        return [{"name": "25g8282"}]


CFG = dict(u.DEFAULTS)


class Parsing(unittest.TestCase):
    def test_size(self):
        self.assertEqual(u.parse_size("26843545600B"), 25 * 1024 ** 3)
        self.assertEqual(u.parse_size("26843545600"), 25 * 1024 ** 3)
        self.assertEqual(u.parse_size("1.5KiB"), 1536)
        self.assertEqual(u.parse_size("0B"), 0)
        self.assertEqual(u.parse_size(""), 0)

    def test_duration(self):
        self.assertEqual(u.parse_duration("4w2d"), 30 * 86400)
        self.assertEqual(u.parse_duration("13h54m17s"), 13 * 3600 + 54 * 60 + 17)
        self.assertEqual(u.parse_duration("1d02:00:00"), 86400 + 7200)
        self.assertIsNone(u.parse_duration("0s"))
        self.assertIsNone(u.parse_duration("unlimited"))

    def test_dt(self):
        self.assertEqual(u.parse_dt("2026-12-05 19:19:16"), datetime(2026, 12, 5, 19, 19, 16))
        self.assertEqual(u.parse_dt("dec/05/2026 19:19:16"), datetime(2026, 12, 5, 19, 19, 16))


class Status(unittest.TestCase):
    def test_real_user(self):
        st = u.build_status(FakeRouter(), "25g8282", "*FE")
        c = st["current"]
        self.assertEqual(st["state"], "active")
        self.assertEqual(c["display"], "30d")
        self.assertEqual(c["start"], "2026-11-05 19:19:16")
        self.assertEqual(c["days_left"], 27)
        # monitor said 798.7MiB down / 122.1MiB up
        self.assertAlmostEqual(c["download_bytes"] / MiB, 798.7, delta=0.1)
        self.assertAlmostEqual(c["upload_bytes"] / MiB, 122.1, delta=0.1)
        self.assertEqual(c["remaining_bytes"], 25 * 1024 ** 3 - c["used_bytes"])

    def test_first_profile_needs_no_session_scan(self):
        r = FakeRouter()
        u.build_status(r, "25g8282", "*FE")
        self.assertNotIn("/user-manager/session/print", r.calls)

    def test_renewed_user_counts_sessions_since_start(self):
        old = [("2026-10-01 10:00:00", "20.0GiB", "1.0GiB")]
        prof = [{"user": "25g8282", "profile": "30d-25G", "state": "used",
                 "end-time": "2026-10-31 10:00:00"},
                {"user": "25g8282", "profile": "30d-25G", "state": "running-active",
                 "end-time": "2026-12-05 19:19:16"}]
        r = FakeRouter(extra_sessions=old, profiles=prof)
        st = u.build_status(r, "25g8282", "*FE")
        self.assertAlmostEqual(st["current"]["used_bytes"] / MiB, 920.8, delta=0.2)
        self.assertIn("/user-manager/session/print", r.calls)

    def test_monitor_ignored_for_renewed_user(self):
        # real case: the session table lost old history, so monitor minus
        # old sessions gave 196 GB; only sessions since start count
        prof = [{"user": "25g8282", "profile": "30d-25G", "state": "used",
                 "end-time": "2026-10-31 10:00:00"},
                {"user": "25g8282", "profile": "30d-25G", "state": "running-active",
                 "end-time": "2026-12-05 19:19:16"}]
        r = FakeRouter(profiles=prof)
        r.post_monitor_override = {"total-download": "247888687197",
                                   "total-upload": "12428945326"}
        st = u.build_status(r, "25g8282", "*FE")
        self.assertAlmostEqual(st["current"]["used_bytes"] / MiB, 920.8, delta=0.2)

    def test_waiting_next_profile(self):
        prof = [{"user": "25g8282", "profile": "30d-25G", "state": "running-active",
                 "end-time": "2026-12-05 19:19:16"},
                {"user": "25g8282", "profile": "30d-25G", "state": "waiting"}]
        st = u.build_status(FakeRouter(profiles=prof), "25g8282", "*FE")
        self.assertEqual(len(st["next"]), 1)
        self.assertEqual(st["next"][0]["validity_days"], 30)

    def test_renewed_user_prefers_running_active(self):
        # old profile: volume used up, end-time still in the future
        prof = [{"user": "25g8282", "profile": "30d-25G", "state": "running",
                 "end-time": "2026-11-08 10:15:00"},
                {"user": "25g8282", "profile": "30d-25G", "state": "running-active",
                 "end-time": "2026-12-05 19:19:16"},
                {"user": "25g8282", "profile": "30d-25G", "state": "waiting"}]
        st = u.build_status(FakeRouter(profiles=prof), "25g8282", "*FE")
        self.assertEqual(st["current"]["end"], "2026-12-05 19:19:16")
        self.assertEqual(st["current"]["days_left"], 27)
        self.assertEqual(len(st["next"]), 1)

    def test_only_waiting(self):
        prof = [{"user": "25g8282", "profile": "30d-25G", "state": "waiting"}]
        st = u.build_status(FakeRouter(profiles=prof), "25g8282", "*FE")
        self.assertEqual(st["state"], "waiting")
        self.assertIsNone(st["current"])

    def test_volume_finished(self):
        big = [("2026-11-06 00:00:00", "25.0GiB", "0B")]
        st = u.build_status(FakeRouter(extra_sessions=big), "25g8282", "*FE")
        self.assertEqual(st["state"], "volume_finished")
        self.assertEqual(st["current"]["remaining_bytes"], 0)


class Auth(unittest.TestCase):
    def test_ok(self):
        code, body = u.Service(FakeRouter(), CFG).handle("1.1.1.1", "25g8282", "ab12cd")
        self.assertEqual(code, 200)
        self.assertFalse(body["disabled"])

    def test_password_via_print(self):
        code, _ = u.Service(FakeRouter("print"), CFG).handle("1.1.1.1", "25g8282", "ab12cd")
        self.assertEqual(code, 200)

    def test_password_unreadable(self):
        code, body = u.Service(FakeRouter("none"), CFG).handle("1.1.1.1", "25g8282", "ab12cd")
        self.assertEqual((code, body["error"]), (503, "server_config"))

    def test_wrong_and_unknown_look_same(self):
        s = u.Service(FakeRouter(), CFG)
        self.assertEqual(s.handle("1.1.1.1", "25g8282", "xx")[1],
                         s.handle("1.1.1.1", "nobody", "xx")[1])

    def test_bruteforce_block(self):
        s = u.Service(FakeRouter(), CFG)
        for _ in range(CFG["max_fail_per_ip"]):
            self.assertEqual(s.handle("2.2.2.2", "25g8282", "bad")[0], 401)
        self.assertEqual(s.handle("2.2.2.2", "25g8282", "ab12cd")[0], 429)
        self.assertEqual(s.handle("3.3.3.3", "25g8282", "ab12cd")[0], 200)

    def test_bad_input(self):
        s = u.Service(FakeRouter(), CFG)
        self.assertEqual(s.handle("1.1.1.1", "a b", "x")[0], 400)
        self.assertEqual(s.handle("1.1.1.1", None, "x")[0], 400)


class HttpsEndToEnd(unittest.TestCase):
    def test_https(self):
        import os, subprocess, tempfile
        d = tempfile.mkdtemp()
        crt, key = os.path.join(d, "c.crt"), os.path.join(d, "k.key")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=t"],
                       check=True, capture_output=True)
        cfg = dict(CFG, app_config_file=os.path.join(d, "app.json"),
                   app_apk_file=os.path.join(d, "app.apk"),
                   cert_file=crt, key_file=key, key_passphrase="",
                   listen_host="127.0.0.1", listen_port=0)
        svc = u.Service(FakeRouter(), cfg)
        httpd = u.make_server(svc, cfg)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        port = httpd.server_address[1]
        cctx = ssl.create_default_context(cafile=crt)
        cctx.check_hostname = False
        req = urllib.request.Request(
            "https://127.0.0.1:%d/v1/status" % port,
            data=json.dumps({"username": "25g8282", "password": "ab12cd"}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, context=cctx) as r:
            body = json.loads(r.read())
        self.assertEqual(body["current"]["days_left"], 27)
        cfgurl = "https://127.0.0.1:%d/v1/config" % port
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(cfgurl, context=cctx)
        self.assertEqual(ctx.exception.code, 404)
        envelope = b'{"payload": "e30=", "sig": "MAA="}'
        with open(svc.cfg["app_config_file"], "wb") as f:
            f.write(envelope)
        with urllib.request.urlopen(cfgurl, context=cctx) as r:
            self.assertEqual(r.read(), envelope)
        apkurl = "https://127.0.0.1:%d/v1/app.apk" % port
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(apkurl, context=cctx)
        self.assertEqual(ctx.exception.code, 404)
        blob = os.urandom(300 * 1024 + 17)
        with open(svc.cfg["app_apk_file"], "wb") as f:
            f.write(blob)
        with urllib.request.urlopen(apkurl, context=cctx) as r:
            self.assertEqual(r.headers["Content-Length"], str(len(blob)))
            self.assertEqual(r.read(), blob)
        httpd.shutdown()


class SilentClients(unittest.TestCase):
    """Regression: silent TLS clients froze the whole service (2026-11-08)."""

    def test_service_answers_despite_silent_and_garbage_clients(self):
        import os, socket, subprocess, tempfile, time
        d = tempfile.mkdtemp()
        crt, key = os.path.join(d, "c.crt"), os.path.join(d, "k.key")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=t"],
                       check=True, capture_output=True)
        cfg = dict(CFG, cert_file=crt, key_file=key, key_passphrase="",
                   listen_host="127.0.0.1", listen_port=0)
        httpd = u.make_server(u.Service(FakeRouter(), cfg), cfg)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        port = httpd.server_address[1]
        # more silent clients than the old accept backlog (5)
        idle = [socket.create_connection(("127.0.0.1", port)) for _ in range(40)]
        junk = socket.create_connection(("127.0.0.1", port))
        junk.sendall(b"GET / HTTP/1.0\r\n\r\n")          # plain HTTP to a TLS port
        cctx = ssl.create_default_context(cafile=crt)
        cctx.check_hostname = False
        t0 = time.time()
        with urllib.request.urlopen("https://127.0.0.1:%d/health" % port,
                                    context=cctx, timeout=5) as r:
            self.assertEqual(json.loads(r.read()), {"ok": True})
        self.assertLess(time.time() - t0, 3)
        for c in idle + [junk]:
            c.close()
        httpd.shutdown()


class Publish(unittest.TestCase):
    """POST /v1/publish: only owner-signed, newer configs with a matching APK."""

    def setUp(self):
        import importlib.util, os, tempfile
        tools = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools")
        spec = importlib.util.spec_from_file_location("sign_config", os.path.join(tools, "sign_config.py"))
        self.sc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.sc)
        self.d = tempfile.mkdtemp()
        self.key = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
        self.pubfile = os.path.join(self.d, "pub.txt")
        with open(self.pubfile, "w") as f:
            f.write(base64.b64encode(self.sc.public_der(self.key)).decode())
        self.cfg = dict(CFG, app_config_file=os.path.join(self.d, "app.json"),
                        app_apk_file=os.path.join(self.d, "app.apk"),
                        config_pubkey_file=self.pubfile)
        self.pub = u.Publisher(self.cfg)
        self.apk = b"PK" + os.urandom(200000)

    def envelope(self, version, apk=None, key=None, tamper=False):
        import hashlib
        cfg = {"version": version, "servers": [{"host": "h", "port": 443}]}
        if apk is not None:
            cfg["app_update"] = {"version_code": version, "urls": ["https://h/v1/app.apk"],
                                 "sha256": hashlib.sha256(apk).hexdigest(), "size": len(apk)}
        payload = json.dumps(cfg).encode()
        sig = self.sc.sign(key or self.key, payload)
        if tamper:
            payload = payload.replace(b'"h"', b'"x"')
        env = json.dumps({"payload": base64.b64encode(payload).decode(),
                          "sig": base64.b64encode(sig).decode()})
        return base64.b64encode(env.encode()).decode(), env

    def send(self, env_b64, body):
        import io
        return self.pub.publish(env_b64, len(body), io.BytesIO(body).read)

    def test_not_configured(self):
        import os
        os.remove(self.pubfile)
        self.assertEqual(self.send(self.envelope(1)[0], b"")[0], 503)

    def test_publish_then_replay_rejected(self):
        b64, env = self.envelope(2, self.apk)
        self.assertEqual(self.send(b64, self.apk), (200, {"ok": True, "version": 2}))
        with open(self.cfg["app_apk_file"], "rb") as f:
            self.assertEqual(f.read(), self.apk)
        with open(self.cfg["app_config_file"]) as f:
            self.assertEqual(f.read(), env)
        code, body = self.send(b64, self.apk)
        self.assertEqual((code, body["error"]), (409, "not_newer"))

    def test_tampered_or_foreign_key_rejected(self):
        self.assertEqual(self.send(self.envelope(2, self.apk, tamper=True)[0], self.apk)[0], 403)
        other = 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678
        self.assertEqual(self.send(self.envelope(2, self.apk, key=other)[0], self.apk)[0], 403)

    def test_wrong_apk_keeps_old_files(self):
        import os
        b64, _ = self.envelope(2, self.apk)
        self.assertEqual(self.send(b64, self.apk)[0], 200)
        newer = b"PK" + os.urandom(200000)
        b64, _ = self.envelope(3, newer)
        bad = bytearray(newer); bad[100] ^= 1
        code, body = self.send(b64, bytes(bad))
        self.assertEqual((code, body["error"]), (400, "apk_mismatch"))
        with open(self.cfg["app_apk_file"], "rb") as f:
            self.assertEqual(f.read(), self.apk)           # untouched
        self.assertEqual(self.pub._current()["version"], 2)
        self.assertFalse(os.path.exists(self.cfg["app_apk_file"] + ".part"))

    def test_size_mismatch_and_config_only(self):
        b64, _ = self.envelope(2, self.apk)
        self.assertEqual(self.send(b64, self.apk[:-1])[1]["error"], "apk_size_mismatch")
        self.assertEqual(self.send(b64, self.apk)[0], 200)
        # same APK, newer config (e.g. server address changed): no upload needed
        b64, _ = self.envelope(3, self.apk)
        self.assertEqual(self.send(b64, b"")[0], 200)
        # config-only with an APK the router does not have
        b64, _ = self.envelope(4, b"PK-other")
        self.assertEqual(self.send(b64, b"")[1]["error"], "apk_required")

    def test_https_end_to_end(self):
        import os, subprocess
        crt, key = os.path.join(self.d, "c.crt"), os.path.join(self.d, "k.key")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=t"],
                       check=True, capture_output=True)
        cfg = dict(self.cfg, cert_file=crt, key_file=key, key_passphrase="",
                   listen_host="127.0.0.1", listen_port=0)
        httpd = u.make_server(u.Service(FakeRouter(), cfg), cfg)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        port = httpd.server_address[1]
        cctx = ssl.create_default_context(cafile=crt)
        cctx.check_hostname = False
        b64, env = self.envelope(5, self.apk)
        req = urllib.request.Request("https://127.0.0.1:%d/v1/publish" % port, data=self.apk,
                                     headers={"X-Config": b64,
                                              "Content-Type": "application/octet-stream"})
        with urllib.request.urlopen(req, context=cctx, timeout=10) as r:
            self.assertEqual(json.loads(r.read())["version"], 5)
        with urllib.request.urlopen("https://127.0.0.1:%d/v1/config" % port, context=cctx) as r:
            self.assertEqual(r.read().decode(), env)
        httpd.shutdown()


if __name__ == "__main__":
    unittest.main()
