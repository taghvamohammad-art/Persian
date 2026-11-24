import json
import unittest

import mtxray


class FakeR:
    def __init__(self, out):
        self.out = out

    def run(self, cmd, check=True):
        return self.out


class Ports(unittest.TestCase):
    def test_used_ports(self):
        out = "tcp|8291\ntcp|443\n|5000-5002|\nudp|13231\ntcp|30443|pv-xray\ntcp|8443\n"
        used = mtxray.used_ports(FakeR(out))
        self.assertIn(("tcp", 443), used)
        self.assertIn(("udp", 5001), used)          # dst-nat without protocol: both
        self.assertIn(("tcp", 5002), used)
        self.assertNotIn(("tcp", 30443), used)      # our own rule is made again
        self.assertIn(("udp", 13231), used)

    def test_pick_ports(self):
        used = {("tcp", 443), ("tcp", 8443)}         # SSTP and something else on the router
        p = mtxray.pick_ports({}, used)
        self.assertNotIn(p["vision_port"], (443, 8443))
        self.assertNotIn(p["xhttp_port"], (443, 8443))
        self.assertEqual(p["hy2_port"], 443)        # UDP 443 is free
        ports = [("tcp", p["vision_port"]), ("tcp", p["xhttp_port"]), ("tcp", p["ss_port"]),
                 ("tcp", p["status_port"])]
        self.assertEqual(len(set(ports)), 4)
        # kept on a re-run
        self.assertEqual(mtxray.pick_ports(dict(p), used), p)

    def test_template_and_agent(self):
        import linux
        p = linux.new_params({})
        p["reality_private"] = "secret"
        t = mtxray.template(p)
        text = json.dumps(t)
        self.assertIn("__REALITY_PRIVATE__", text)
        self.assertNotIn("secret", text)
        self.assertIn("__HY2_CERT__", text)
        self.assertEqual(t["log"]["access"], "/app/state/access.log")
        self.assertFalse([i for i in t["inbounds"] if i["tag"] in ("vless-cdn", "vless-dns")])
        a = mtxray.agent_config(p, "box", "1.2.3.4", [], [], {"5.6.7.8"})
        self.assertTrue(a["xray"]["supervise"])
        self.assertEqual(a["radius"]["nas_identifier"], "pv-box")
        self.assertEqual(a["box_status"]["allow"], ["5.6.7.8"])

    def test_status_url(self):
        import linux
        import settings as st
        r = {"host": "1.2.3.4", "xray_box": True,
             "xray_params": st.encrypt_blob({"status_token": "tok", "status_port": 30447})}
        self.assertEqual(linux.status_url(r), "http://1.2.3.4:30447/pvs/tok")


if __name__ == "__main__":
    unittest.main()
