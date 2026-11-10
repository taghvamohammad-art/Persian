"""Pure parts of provisioning: export filtering, config changes, bot files."""

import io
import os
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import provision as pv   # noqa: E402
import services as sv    # noqa: E402
import publisher as pb   # noqa: E402

EXPORT = """# 2026 by RouterOS 7.23.2
/interface ethernet set [ find default-name=ether1 ] disable-running-check=no
/interface bridge add name=br-containers
/user-manager user add name=25g00001 ***
/user-manager router add address=127.0.0.1 name=local shared-secret=s
/interface sstp-server server set authentication=mschap2 certificate=server default-profile=vpn enabled=yes
/ip address add address=91.207.18.201/24 interface=ether1 network=91.207.18.0
/ip address add address=172.17.0.1/24 interface=br-containers network=172.17.0.0
/ip route add gateway=91.207.18.1
/ip route add dst-address=10.50.0.0/16 gateway=172.17.0.9
/ip service set ssh port=2202
/ip service set www address=172.17.0.0/24,91.207.18.2011 port=64
/ip firewall nat add action=dst-nat chain=dstnat dst-address=91.207.18.201 dst-port=8443 protocol=tcp to-addresses=172.17.0.2 to-ports=8443
/ip firewall nat add action=masquerade chain=srcnat src-address=172.17.0.0/24
/ip firewall nat add action=masquerade chain=srcnat src-address=10.10.10.0/24
/ip pool add name=vpn ranges=10.10.10.2-10.10.10.200
/ppp profile add local-address=10.10.10.1 name=vpn remote-address=vpn
/container add cmd="python3 /app/umstatus.py serve" interface=veth-umstatus
/ip dhcp-client add interface=ether1
"""


class Filter(unittest.TestCase):
    def test_filter(self):
        keep, um, skipped = pv.filter_export(EXPORT, "91.207.18.201", "5.6.7.8")
        text = "\n".join(keep)
        self.assertIn("dst-address=5.6.7.8 dst-port=8443", text)
        self.assertIn("91.207.18.2011", text)                 # only whole addresses replaced
        self.assertNotIn("ether1", text)
        self.assertNotIn("/container", text)
        self.assertNotIn("ssh port", text)
        self.assertIn("/ip route add dst-address=10.50.0.0/16", text)
        self.assertNotIn("gateway=91.207.18.1\n", text + "\n")
        self.assertIn("/interface bridge add name=br-containers", text)
        self.assertEqual(len(um), 2)
        self.assertEqual(len(skipped), 3)

    def test_secondary(self):
        lines = pv.secondary_lines(EXPORT)
        self.assertIn("/ip pool add name=vpn ranges=10.10.10.2-10.10.10.200", lines)
        self.assertTrue(any("10.10.10.0/24" in l for l in lines))
        self.assertFalse(any("172.17.0." in l for l in lines))
        self.assertEqual(pv.sstp_cert_name(EXPORT), "server")

    def test_old_ip(self):
        self.assertEqual(pv.old_public_ip({"host": "91.207.18.201"}, {}), "91.207.18.201")
        parts = {"info/addresses.txt": b" 0 172.17.0.1/24 br\n 1 91.207.18.201/24 ether1\n"}
        self.assertEqual(pv.old_public_ip({"host": "vpn.example.com"}, parts), "91.207.18.201")

    def test_config_changes(self):
        cfg = {"version": 3, "servers": [{"name": "a", "host": "91.207.18.201", "port": 443}],
               "status_urls": ["https://91.207.18.201:8443/v1/status"],
               "config_urls": ["https://91.207.18.201:8443/v1/config", "https://raw.example/x"]}
        moved = pv.move_server_in_config(cfg, "91.207.18.201", "5.6.7.8")
        self.assertEqual(moved["servers"][0]["host"], "5.6.7.8")
        self.assertEqual(moved["config_urls"][1], "https://raw.example/x")
        self.assertEqual(cfg["servers"][0]["host"], "91.207.18.201")       # original untouched
        added = pv.add_server_to_config(moved, "sec", "9.9.9.9")
        self.assertEqual([s["host"] for s in added["servers"]], ["5.6.7.8", "9.9.9.9"])
        self.assertEqual(pv.add_server_to_config(added, "sec", "9.9.9.9"), added)


class Addresses(unittest.TestCase):
    def test_routeros_lists(self):
        self.assertEqual(sv.addr_list("93.118.136.58/32;5.181.156.189/32;5.181.156.189/32"),
                         ["93.118.136.58/32", "5.181.156.189/32"])
        self.assertEqual(sv.addr_list("a,b"), ["a", "b"])
        self.assertEqual(sv.addr_list(None), [])
        self.assertEqual(sv.with_prefix("1.2.3.4"), "1.2.3.4/32")


class Bot(unittest.TestCase):
    def test_env(self):
        env = sv.parse_env('﻿BOT_TOKEN=1:abc\n# c\nADMIN_IDS="1,2"\nMT_URL=https://x\nCUSTOM=7\n')
        out = sv.render_env(env, 64, "pw").decode()
        self.assertIn("ADMIN_IDS=1,2", out)
        self.assertIn("MT_URL=http://172.17.0.1:64", out)
        self.assertNotIn("https://x", out)
        self.assertIn("CUSTOM=7", out)
        self.assertIn("MT_PASSWORD=pw", out)
        with self.assertRaises(pb.ReleaseError):
            sv.check_bot_values({"BOT_TOKEN": "bad", "ADMIN_IDS": "1"})
        sv.check_bot_values({"BOT_TOKEN": "123:" + "a" * 35, "ADMIN_IDS": "1, 2"})

    def test_code_from_zipball(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("o-um-abc/umbot/__main__.py", "x")
            z.writestr("o-um-abc/umbot/db.py", "y")
            z.writestr("o-um-abc/tests/test_bot.py", "z")
            z.writestr("o-um-abc/README.md", "r")
        files = sv.bot_code_from_zip(buf.getvalue())
        self.assertEqual(sorted(files), ["umbot/__main__.py", "umbot/db.py"])


if __name__ == "__main__":
    unittest.main()
