import ipaddress
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import backuptunnel as bt  # noqa: E402


def gre(nets, keepalive="10s,10"):
    return {"remote": "203.0.113.9", "keepalive": keepalive, "running": True,
            "nets": [ipaddress.ip_network(n) for n in nets]}


def route(gw, table="to-gre", dist=1, check="", rid="*5", comment=""):
    return {"id": rid, "gateway": gw, "table": table, "distance": dist, "check": check, "comment": comment,
            "active": True}


class PlanTests(unittest.TestCase):
    def test_route_by_gateway_ip(self):
        gres = {"gre-out": gre(["10.10.10.0/30"])}
        plan = bt.make_plan(gres, [("gre-out", "10.10.10.1/30")],
                            [route("192.168.1.1", table="main", rid="*1"), route("10.10.10.2", dist=2)],
                            [("sstp", "10.10.10.2"), ("default", "")])
        self.assertTrue(plan.ok, plan.problems)
        self.assertEqual(plan.tables, ["to-gre"])
        self.assertEqual([r["gre"] for r in plan.routes], ["gre-out"])
        self.assertEqual(len(plan.changes), 1)                 # check-gateway goes on
        self.assertIn("check-gateway", plan.changes[0])
        self.assertEqual(len(plan.warnings), 1)                # DNS behind the GRE
        self.assertIn("1.1.1.1", plan.warnings[0])

    def test_route_by_interface(self):
        gres = {"gre1": gre([], keepalive="")}
        plan = bt.make_plan(gres, [], [route("gre1"), route("10.0.0.1%gre1", table="t2", check="ping")], [])
        self.assertTrue(plan.ok)
        self.assertEqual(plan.tables, ["t2", "to-gre"])
        self.assertEqual(len(plan.changes), 1)
        self.assertIn("keepalive", plan.changes[0])

    def test_refuses_what_it_cannot_do(self):
        self.assertFalse(bt.make_plan({}, [], [route("1.2.3.4")], []).ok)
        gres = {"gre1": gre(["10.10.10.0/30"])}
        p = bt.make_plan(gres, [], [route("192.168.1.1", table="main")], [])
        self.assertFalse(p.ok)
        self.assertIn("192.168.1.1", p.problems[0])
        p = bt.make_plan(gres, [], [route("10.10.10.2", table="main")], [])
        self.assertFalse(p.ok)                                 # the router's own default via GRE
        p = bt.make_plan(gres, [("ether2", "172.17.0.4/24")], [route("10.10.10.2")], [])
        self.assertTrue(p.ok)                                  # the relay's usual address is taken:
        self.assertEqual(p.relay_ip, "172.17.0.5")             # it takes another
        p = bt.make_plan(gres, [("ether2", "10.64.0.2/24")], [route("10.10.10.2")], [])
        self.assertFalse(p.ok)                                 # the tunnel address is taken

    def test_own_routes_ignored(self):
        gres = {"gre1": gre(["10.10.10.0/30"])}
        p = bt.make_plan(gres, [(bt.WG, bt.TUN_ADDR + "/32")],
                         [route("10.10.10.2", check="ping"), route(bt.WG, dist=2, comment=bt.TAG)], [])
        self.assertTrue(p.ok)
        self.assertEqual(len(p.routes), 1)
        self.assertEqual(p.changes, [])
        self.assertIn("10.10.10.2", bt.describe(p, "5.6.7.8"))

    def test_parse_router_output(self):
        class R:
            def run(self, cmd, **kw):
                return ("g|gre-out|203.0.113.9|10s,10|true\n"
                        "a|ether1|192.168.1.10/24\na|gre-out|10.10.10.1/30\n"
                        "r|*1|192.168.1.1|main|1||ISP|true\n"
                        "r|*A|10.10.10.2|to-gre|1|ping||true\n"
                        "p|default-encryption|\n")
        plan = bt.inspect(R())
        self.assertTrue(plan.ok, plan.problems)
        self.assertEqual(plan.routes[0]["id"], "*A")
        self.assertEqual(plan.routes[0]["check"], "ping")

    def test_relay_config(self):
        awg = {"priv": "x", "public": "PUB", "port": 4444, "jc": 4, "jmin": 40, "jmax": 70, "s1": 20, "s2": 30,
               "h1": 5, "h2": 6, "h3": 7, "h4": 8}
        cfg = bt.relay_config("5.6.7.8", awg, "RPUB")
        self.assertNotIn("priv", cfg)                          # no secret ever goes to the router
        self.assertEqual((cfg["server"], cfg["port"], cfg["router_public"]), ("5.6.7.8", 4444, "RPUB"))
        self.assertTrue(bt.relay_source().startswith(b'"""WireGuard'))
        self.assertNotIn("icmp_key", cfg)                      # older servers: UDP only
        cfg = bt.relay_config("5.6.7.8", dict(awg, icmp_key="ab" * 16), "RPUB")
        self.assertEqual((cfg["icmp_key"], cfg["transport"]), ("ab" * 16, "auto"))

    def test_relay_address_avoids_other_containers(self):
        veths = [("veth-umstatus", "172.17.0.2/24"), ("veth-umbot", "172.17.0.3/24")]
        self.assertEqual(bt.free_relay_ip(veths, []), "172.17.0.4")
        mine = veths + [("veth-abrak", "172.17.0.4/24"), ("veth-pvawg", "172.17.0.4/24")]
        self.assertEqual(bt.free_relay_ip(mine, []), "172.17.0.5")          # the clash seen on a router
        moved = veths + [("veth-abrak", "172.17.0.4/24"), ("veth-pvawg", "172.17.0.5/24")]
        self.assertEqual(bt.free_relay_ip(moved, [("ether1", "172.17.0.6/24")]), "172.17.0.5")   # kept
        self.assertEqual(bt.free_relay_ip(veths + [("x", "172.17.0.4/24"), ("y", "172.17.0.5/24")],
                                          [("br", "172.17.0.6/24")]), "172.17.0.7")

    def test_icmp_carrier_installed_on_linux(self):
        import linux

        class H:
            def __init__(self):
                self.files, self.cmds = {}, []

            def run(self, c, check=True, **kw):
                self.cmds.append(c)
                return ""

            def write(self, path, data, mode=None):
                self.files[path] = data
        h = H()
        p = linux.ensure_icmp(h, {"awg": {"port": 4444}}, log=lambda *a: None)
        key = p["awg"]["icmp_key"]
        self.assertEqual(len(bytes.fromhex(key)), 16)
        self.assertEqual(json.loads(h.files["/etc/pv-agent/icmp.json"]), {"key": key, "awg_port": 4444})
        self.assertIn(b"class Server", h.files["/opt/pv-agent/pv_icmp.py"])
        self.assertIn("icmp_echo_ignore_all=0", h.files["/etc/systemd/system/pv-icmp.service"])
        self.assertEqual(linux.ensure_icmp(h, p, log=lambda *a: None)["awg"]["icmp_key"], key)   # kept


class XrayUpdateTests(unittest.TestCase):
    def fake(self, script_out):
        class H:
            def __init__(self):
                self.scripts = []

            def run(self, c, check=True, **kw):
                if c.startswith("test -x"):
                    return "Y"
                if c == "uname -m":
                    return "x86_64"
                if "xray version" in c:
                    return "26.10.31\n"
                self.scripts.append(c)
                return script_out
        return H()

    def test_updated(self):
        import linux
        h = self.fake("NEW v26.11.9\nDONE\n")
        self.assertEqual(linux.update_xray(h, log=lambda *a: None), ("26.10.31", "26.11.9"))
        self.assertIn('[ "v26.10.31" = "$tag" ]', h.scripts[0])
        self.assertIn("run -test -config", h.scripts[0])          # the new one must accept the config first

    def test_same_rejected_rolled_back(self):
        import linux
        self.assertEqual(linux.update_xray(self.fake("NEW v26.10.31\nSAME\n"), log=lambda *a: None),
                         ("26.10.31", "26.10.31"))
        for out in ("NEW v27.1.1\nREJECTED\nbad option\n", "NEW v27.1.1\nROLLED BACK\n", "curl: (6)\n"):
            with self.assertRaises(linux.LinuxError):
                linux.update_xray(self.fake(out), log=lambda *a: None)


if __name__ == "__main__":
    unittest.main()
