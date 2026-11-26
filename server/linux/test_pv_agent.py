"""Unit tests of pv-agent (no Xray/AWG/router needed)."""

import hashlib
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pv_agent as pa  # noqa: E402
import pvcreds  # noqa: E402


class FakeRadius:
    """RADIUS server: decodes PAP, checks authenticators, records accounting."""

    def __init__(self, secret=b"s3cret", users=None):
        self.secret, self.users = secret, users or {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.accounting, self.auth_seen, self.ports = [], [], []
        threading.Thread(target=self.serve, daemon=True).start()

    @staticmethod
    def attrs(body):
        out, i = {}, 0
        while i < len(body):
            t, ln = body[i], body[i + 1]
            out.setdefault(t, []).append(body[i + 2:i + ln])
            i += ln
        return out

    def serve(self):
        while True:
            data, addr = self.sock.recvfrom(4096)
            code, ident, length = struct.unpack("!BBH", data[:4])
            auth, a = data[4:20], self.attrs(data[20:length])
            user = a[1][0].decode()
            if code == 1:
                import hmac
                ma = a[80][0]
                zeroed = data[:length].replace(ma, b"\0" * 16)
                assert hmac.new(self.secret, zeroed, hashlib.md5).digest() == ma, "bad Message-Authenticator"
                enc, plain, last = a[2][0], b"", auth
                for k in range(0, len(enc), 16):
                    key = hashlib.md5(self.secret + last).digest()
                    plain += bytes(x ^ y for x, y in zip(enc[k:k + 16], key))
                    last = enc[k:k + 16]
                password = plain.rstrip(b"\0").decode()
                self.auth_seen.append((user, password))
                rcode = 2 if self.users.get(user) == password else 3
            else:
                expect = hashlib.md5(data[:4] + b"\0" * 16 + data[20:length] + self.secret).digest()
                assert expect == auth, "bad accounting authenticator"
                kind = struct.unpack("!I", a[40][0])[0]
                octets_in = struct.unpack("!I", a[42][0])[0] + (struct.unpack("!I", a[52][0])[0] << 32)
                octets_out = struct.unpack("!I", a[43][0])[0] + (struct.unpack("!I", a[53][0])[0] << 32)
                self.accounting.append((user, kind, a[44][0].decode(), octets_in, octets_out))
                self.ports.append(a[87][0].decode() if 87 in a else None)
                rcode = 5
            resp = struct.pack("!BBH", rcode, ident, 20)
            resp += hashlib.md5(resp + auth + self.secret).digest()
            self.sock.sendto(resp, addr)


class RadiusTests(unittest.TestCase):
    def test_auth_and_accounting(self):
        srv = FakeRadius(users={"25g00001": "abc123"})
        dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dead.bind(("127.0.0.1", 0))        # a "first" server that never answers
        r = pa.Radius([{"host": "127.0.0.1", "secret": "x", "auth_port": dead.getsockname()[1],
                        "acct_port": dead.getsockname()[1]},
                       {"host": "127.0.0.1", "secret": "s3cret", "auth_port": srv.port, "acct_port": srv.port}],
                      "10.0.0.5", "linux1", timeout=0.3)
        self.assertTrue(r.authorize("25g00001", "abc123"))
        self.assertFalse(r.authorize("25g00001", "wrong-and-a-long-password-over-16"))
        self.assertEqual(srv.auth_seen[1][1], "wrong-and-a-long-password-over-16")
        r.account(pa.INTERIM, "25g00001", "sid1", 60, 5 * 2 ** 32 + 7, 9)
        self.assertEqual(srv.accounting[-1], ("25g00001", pa.INTERIM, "sid1", 5 * 2 ** 32 + 7, 9))

    def test_nobody_answers(self):
        dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dead.bind(("127.0.0.1", 0))
        r = pa.Radius([{"host": "127.0.0.1", "secret": "x", "auth_port": dead.getsockname()[1]}],
                      "10.0.0.5", "linux1", timeout=0.2)
        with self.assertRaises(OSError):
            r.authorize("a", "b")


class Creds(unittest.TestCase):
    def test_stable_and_distinct(self):
        self.assertEqual(pvcreds.vless_uuid("25G1", "p"), pvcreds.vless_uuid("25g1 ", "p"))
        self.assertNotEqual(pvcreds.vless_uuid("25g1", "p"), pvcreds.vless_uuid("25g1", "q"))
        self.assertEqual(len(pvcreds.hy2_auth("a", "b")), 32)
        import base64
        self.assertEqual(len(base64.b64decode(pvcreds.ss_key("a", "b"))), 16)
        k = base64.b64decode(pvcreds.awg_private("a", "b"))
        self.assertEqual((k[0] & 7, k[31] & 128, k[31] & 64), (0, 0, 64))
        ip = pvcreds.awg_address("25g00001")
        self.assertTrue(ip.startswith(("10.6", "10.7", "10.8", "10.9", "10.1")))
        self.assertEqual(ip, pvcreds.awg_address("25G00001"))
        # golden values: the apps must produce exactly these
        self.assertEqual(pvcreds.vless_uuid("25g00001", "abc123"), GOLDEN["vless"])
        self.assertEqual(pvcreds.hy2_auth("25g00001", "abc123"), GOLDEN["hy2"])
        self.assertEqual(pvcreds.ss_key("25g00001", "abc123"), GOLDEN["ss"])
        self.assertEqual(pvcreds.awg_private("25g00001", "abc123"), GOLDEN["awg"])
        self.assertEqual(pvcreds.awg_address("25g00001"), GOLDEN["awg_ip"])


GOLDEN = {"vless": "f4faf53d-9ec0-58d6-9711-c9cabcc6e4b5", "hy2": "100720b0c2b0f243637b6979f25c35e7",
          "ss": "kIPsqZJOWdJYPjSbZ7zSrQ==", "awg": "iEOjwrLAGYLR3gCJd8hsCtL+1cqeTz1lO1EWQXlQYlw=",
          "awg_ip": "10.122.173.75"}


class FakeRouter(BaseHTTPRequestHandler):
    users = [{"name": "25g00001", "password": "abc123", "disabled": "false"},
             {"name": "25g00002", "password": "x", "disabled": "true"},
             {"name": "25g00003", "password": "y", "disabled": "false"},
             {"name": "25g00004", "disabled": "false"}]
    profiles = [{"user": "25g00001", "state": "running-active"}, {"user": "25g00002", "state": "running-active"},
                {"user": "25g00003", "state": "waiting"}, {"user": "25g00004", "state": "running-active"}]

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        rows = self.users if self.path.endswith("/user/print") else self.profiles
        body = json.dumps(rows).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class RouterTests(unittest.TestCase):
    def test_allowed_users_and_failover(self):
        httpd = HTTPServer(("127.0.0.1", 0), FakeRouter)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        good = {"name": "um2", "url": "http://127.0.0.1:%d" % httpd.server_address[1], "user": "u", "password": "p"}
        bad = {"name": "um1", "url": "http://127.0.0.1:9", "user": "u", "password": "p"}
        users, source = pa.fetch_users([bad, good])
        self.assertEqual(users, {"25g00001": "abc123", "25g00003": "y"})
        self.assertEqual(source, "um2")
        httpd.shutdown()


class FakeXray:
    def __init__(self):
        self.users, self.pending = {}, {}

    def restart(self, users, if_changed=False):
        self.users = dict(users)

    def apply(self, old, new):
        self.users = dict(new)
        return True

    def alive(self):
        return True

    def traffic(self):
        out, self.pending = self.pending, {}
        return out


class XrayRestartTests(unittest.TestCase):
    def test_agent_restart_does_not_restart_unchanged_xray(self):
        from unittest import mock
        tmp = tempfile.mkdtemp()
        tpl = {"inbounds": [{"tag": "vless-vision", "protocol": "vless", "settings": {"clients": []}}]}
        with open(os.path.join(tmp, "t.json"), "w") as f:
            json.dump(tpl, f)
        x = pa.Xray({"template": os.path.join(tmp, "t.json"), "config": os.path.join(tmp, "c.json"),
                    "inbounds": {"vless-vision": "vless-vision"}})
        calls = []

        def run(cmd, **kw):
            calls.append(cmd)
            return mock.Mock(returncode=0)
        with mock.patch.object(pa.subprocess, "run", run):
            x.restart({"25g00001": "a"}, if_changed=True)          # no config yet: restart
            self.assertEqual(sum("restart" in c for c in calls), 1)
            x.restart({"25g00001": "a"}, if_changed=True)          # same: left running
            self.assertEqual(sum("restart" in c for c in calls), 1)
            x.restart({"25g00002": "b"}, if_changed=True)          # users changed: restart
            self.assertEqual(sum("restart" in c for c in calls), 2)


    def test_supervised_xray(self):
        """No systemd (container on a MikroTik): the agent runs Xray itself."""
        tmp = tempfile.mkdtemp()
        tpl = {"inbounds": [{"tag": "vless-vision", "protocol": "vless", "settings": {"clients": []}}]}
        with open(os.path.join(tmp, "t.json"), "w") as f:
            json.dump(tpl, f)
        fake = os.path.join(tmp, "xray")
        with open(fake, "w") as f:
            f.write("#!/bin/sh\nexec sleep 60\n")
        os.chmod(fake, 0o755)
        x = pa.Xray({"template": os.path.join(tmp, "t.json"), "config": os.path.join(tmp, "c.json"),
                    "inbounds": {"vless-vision": "vless-vision"}, "bin": fake, "supervise": True})
        try:
            self.assertFalse(x.alive())
            x.restart({"25g00001": "a"}, if_changed=True)
            first = x.proc
            self.assertTrue(x.alive())
            x.restart({"25g00001": "a"}, if_changed=True)          # same users, running: kept
            self.assertIs(x.proc, first)
            first.kill()
            first.wait()
            self.assertFalse(x.alive())
            x.restart({"25g00001": "a"}, if_changed=True)          # died: started again
            self.assertTrue(x.alive())
            self.assertIsNot(x.proc, first)
        finally:
            if x.proc:
                x.proc.kill()
                x.proc.wait()


class AgentTests(unittest.TestCase):
    def setUp(self):
        self._fetch = pa.fetch_users

    def tearDown(self):
        pa.fetch_users = self._fetch

    def make(self, radius_users):
        srv = FakeRadius(users=radius_users)
        tmp = tempfile.mkdtemp()
        cfg = {"routers": [], "state": os.path.join(tmp, "state.json"), "min_start": 0,
               "radius": {"servers": [{"host": "127.0.0.1", "secret": "s3cret", "auth_port": srv.port,
                                       "acct_port": srv.port}], "nas_ip": "10.0.0.5"}}
        agent = pa.Agent(cfg)
        agent.xray = FakeXray()
        return agent, srv

    def test_maintenance_only_users(self):
        agent, srv = self.make({})
        tmp = tempfile.mkdtemp()
        agent.cfg["only_users_file"] = os.path.join(tmp, "only-users")
        users = {"Mohammad": "a", "25g00001": "b"}
        self.assertEqual(agent.allowed_now(users), users)            # no file: everyone
        with open(agent.cfg["only_users_file"], "w") as f:
            f.write("mohammad\n")
        self.assertEqual(agent.allowed_now(users), {"Mohammad": "a"})
        os.remove(agent.cfg["only_users_file"])
        self.assertEqual(agent.allowed_now(users), users)

    def test_session_lifecycle(self):
        agent, srv = self.make({"25g00001": "abc123"})
        router_users = {"25g00001": "abc123"}
        pa.fetch_users = lambda routers: (router_users, "um1")
        agent.sync_users()
        self.assertEqual(agent.xray.users, router_users)
        agent.xray.pending = {"25g00001": [100, 2000]}
        agent.account(agent.collect(), now=1000)
        kinds = [(k, i, o) for u, k, s, i, o in srv.accounting]
        self.assertEqual(kinds, [(pa.START, 100, 2000), (pa.INTERIM, 100, 2000)])
        agent.xray.pending = {"25g00001": [1, 1]}
        agent.account(agent.collect(), now=1060)
        self.assertEqual(srv.accounting[-1][1:], (pa.INTERIM, srv.accounting[0][2], 101, 2001))
        agent.account({}, now=1060 + pa.IDLE_STOP + 1)
        self.assertEqual(srv.accounting[-1][1], pa.STOP)
        self.assertEqual(agent.state["sessions"], {})

    def test_one_session_per_user(self):
        """The app spreads a connection over several protocols (the pool); User
        Manager ends sessions over the shared-users limit and their traffic is
        lost, so all of a user's protocols go into one session."""
        agent, srv = self.make({"25g00001": "abc123"})
        pa.fetch_users = lambda routers: ({"25g00001": "abc123"}, "um1")
        agent.sync_users()
        agent.xray.pending = {"25g00001@vless-vision": [10, 100], "25g00001@hy2": [5, 50000]}
        agent.account(agent.collect(), now=1000)
        self.assertEqual(len(srv.auth_seen), 1)                    # asked once for the user
        self.assertEqual(set(agent.state["sessions"]), {"25g00001"})
        self.assertEqual({p for p in srv.ports}, {"hy2"})          # the protocol with most traffic
        sids = {s for u, k, s, i, o in srv.accounting}
        self.assertEqual(len(sids), 1)
        self.assertEqual(srv.accounting[-1][3:], (15, 50100))       # both protocols counted
        agent.xray.pending = {"25g00001@vless-xhttp": [1, 2], "25g00001@ss": [3, 4]}
        agent.account(agent.collect(), now=1060)
        self.assertEqual(srv.accounting[-1][3:], (19, 50106))
        self.assertEqual(len({s for u, k, s, i, o in srv.accounting}), 1)
        self.assertEqual(pa.split_email("25G00001@vless-cdn"), ("25g00001", "vless-cdn"))
        self.assertEqual(pa.split_email("plain"), ("plain", "xray"))
        clients = pa.xray_clients("vless", {"25G00001": "abc123"}, "vless-xhttp")
        self.assertEqual(clients[0]["email"], "25g00001@vless-xhttp")

    def test_status_file_counts_online_users_per_protocol(self):
        agent, srv = self.make({})
        log_path = os.path.join(os.path.dirname(agent.state_path), "access.log")
        agent.cfg["access_log"] = log_path
        agent.cfg["status_file"] = os.path.join(os.path.dirname(agent.state_path), "status.json")
        with open(log_path, "w") as f:
            f.write("2026/11/09 20:11:23.6 from tcp:1.2.3.4:5 accepted tcp:a:443 [vless-vision >> direct] email: 25G00001\n"
                    "2026/11/09 20:11:24.6 from tcp:1.2.3.4:6 accepted tcp:b:443 [hy2 -> direct] email: 25g00002@hy2\n"
                    "2026/11/09 20:11:25.6 from tcp:1.2.3.4:7 accepted tcp:c:443 [vless-vision >> direct] email: 25g00003\n"
                    "2026/11/09 20:11:26.6 from tcp:1.2.3.4:8 accepted tcp:d:443 [vless-vision >> direct] email: 25g00001\n")
        st = agent.write_status(1000)
        self.assertEqual(st["by_protocol"], {"vless-vision": 2, "hy2": 1})
        self.assertEqual(st["users_online"], 3)
        self.assertEqual(os.path.getsize(log_path), 0)                    # emptied after reading
        with open(agent.cfg["status_file"]) as f:
            self.assertEqual(json.load(f)["by_protocol"]["hy2"], 1)
        st = agent.write_status(1000 + pa.ONLINE_WINDOW + 1)              # nobody seen since
        self.assertEqual(st["users_online"], 0)

    def test_user_trying_every_protocol_counts_once(self):
        """The app probes all protocols when connecting: only the one it stays on counts."""
        agent, srv = self.make({})
        log_path = os.path.join(os.path.dirname(agent.state_path), "access.log")
        agent.cfg["access_log"] = log_path
        agent.cfg["status_file"] = os.path.join(os.path.dirname(agent.state_path), "status.json")

        def lines(*protos):
            with open(log_path, "a") as f:
                for p in protos:
                    f.write("2026/11/09 20:11:23.6 from tcp:1.2.3.4:5 accepted tcp:a:443 "
                            "[%s >> direct] email: 25g00001@%s\n" % (p, p))

        lines("vless-vision", "vless-xhttp", "ss", "hy2", "vless-xhttp", "vless-xhttp")
        st = agent.write_status(1000)                 # same round: the most used wins
        self.assertEqual(st["users_online"], 1)
        self.assertEqual([o["protocol"] for o in st["online"]], ["vless-xhttp"])
        lines("vless-vision")
        st = agent.write_status(1030)                 # later round: the one still in use wins
        self.assertEqual(st["by_protocol"], {"vless-vision": 1})

    def test_old_seen_state_is_read(self):
        agent, srv = self.make({})
        agent.cfg["access_log"] = os.path.join(os.path.dirname(agent.state_path), "none.log")
        agent.cfg["status_file"] = os.path.join(os.path.dirname(agent.state_path), "status.json")
        agent.state["seen"] = {"25g00001|hy2": 990}
        st = agent.write_status(1000)
        self.assertEqual(st["by_protocol"], {"hy2": 1})

    def test_probe_traffic_opens_no_user_manager_session(self):
        """The app tries every protocol of every server when connecting: a few KB
        each. Those must not take the user's shared-users slot in User Manager."""
        agent, srv = self.make({"25g00001": "abc123"})
        agent.cfg["min_start"] = pa.MIN_START
        pa.fetch_users = lambda routers: ({"25g00001": "abc123"}, "um1")
        agent.sync_users()
        agent.account({"25g00001|hy2": [3000, 5000]}, now=1000)          # a probe
        self.assertEqual(srv.accounting, [])
        self.assertEqual(agent.state["sessions"], {})
        agent.account({}, now=1000 + pa.IDLE_STOP + 1)                   # and nothing after it
        self.assertEqual(agent.state["pending"], {})
        agent.account({"25g00001|ss": [40000, 30000]}, now=2000)         # real use builds up
        agent.account({"25g00001|ss": [20000, 30000]}, now=2060)
        kinds = [(k, i, o) for u, k, s, i, o in srv.accounting]
        self.assertEqual(kinds, [(pa.START, 60000, 60000), (pa.INTERIM, 60000, 60000)])   # nothing lost

    def test_rejected_user_is_removed(self):
        agent, srv = self.make({})                         # User Manager says no (e.g. volume used up)
        router_users = {"25g00001": "abc123"}
        pa.fetch_users = lambda routers: (router_users, "um1")
        agent.sync_users()
        agent.xray.pending = {"25g00001": [1, 1]}
        agent.account(agent.collect())
        self.assertIn("25g00001", agent.state["blocked"])
        agent.sync_users()
        self.assertEqual(agent.xray.users, {})
        self.assertEqual(srv.accounting, [])



class StaticPeerTests(unittest.TestCase):
    """The router's backup-tunnel peer stays when the users change."""

    def test_static_peer_kept_and_address_reserved(self):
        calls = []
        state = {"peers": {"OLDUSER=": "10.70.0.9", "ROUTER=": "10.64.0.2"}}
        awg = pa.Awg({"static": {"ROUTER=": "10.64.0.2"}}, {})

        def run(*args, input=None):
            calls.append(args)
            if args[:3] == ("show", "awg0", "peers"):
                return "\n".join(state["peers"])
            if args[0] == "pubkey":
                return "PUB-" + input.strip()[:6]
            return ""
        awg._run = run
        orig = pvcreds.awg_address
        pvcreds.awg_address = lambda n: "10.64.0.2" if n == "clash" else orig(n)
        try:
            want = awg.apply({"alice": "pw", "clash": "pw"})
        finally:
            pvcreds.awg_address = orig
        self.assertEqual([v[0] for v in want.values()], ["alice"])          # router address is not given away
        removed = [a[3] for a in calls if a[-1:] == ("remove",)]
        self.assertEqual(removed, ["OLDUSER="])
        self.assertFalse(any(a[3] == "ROUTER=" for a in calls if a[0] == "set"))

if __name__ == "__main__":
    unittest.main()
