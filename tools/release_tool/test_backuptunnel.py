import ipaddress
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
        self.assertFalse(p.ok)                                 # the relay's address is taken

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


if __name__ == "__main__":
    unittest.main()
