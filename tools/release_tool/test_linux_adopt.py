import json
import unittest

import linux


class FakeHost:
    def __init__(self, files):
        self.files = files
        self.cmds = []

    def run(self, cmd, timeout=900, check=True):
        self.cmds.append(cmd)
        if "grep -oE 'location = /pvs/" in cmd:
            nginx = self.files.get("nginx", "")
            return "\n".join(l.strip() for l in nginx.splitlines() if "location = /pvs/" in l)
        if "template.json" in cmd and cmd.startswith("cat"):
            return self.files.get("template", "")
        if "awg0.conf" in cmd and cmd.startswith("cat"):
            return self.files.get("awg", "")
        if "xray x25519 -i" in cmd:
            return "PrivateKey: SRVPRIV\nPassword (PublicKey): SRVPUB\n"
        if "awg pubkey" in cmd:
            return "AWGPUB\n"
        raise AssertionError(cmd)


NGINX = """    location = /pvs/3Tkv0yk7Kbi0MyIdjXCcx1ja {
        allow 127.0.0.1;
"""
TEMPLATE = json.dumps({"inbounds": [{"tag": "vless-vision", "streamSettings": {"realitySettings": {
    "privateKey": "SRVPRIV", "shortIds": ["ab12cd34"]}}}]})
AWG = """[Interface]
PrivateKey = SRVAWG=
Address = 10.64.0.1/10
ListenPort = 24227
Jc = 4
Jmin = 41
Jmax = 80
S1 = 20
S2 = 30
H1 = 11
H2 = 22
H3 = 33
H4 = 44
PostUp = iptables -t nat -A POSTROUTING
[Peer]
PublicKey = PEER
"""


class AdoptTests(unittest.TestCase):
    def test_new_server_keeps_tool_params(self):
        p = linux.new_params()
        before = json.dumps(p, sort_keys=True)
        self.assertEqual(linux.adopt_server_secrets(FakeHost({}), p, log=lambda *_: None), [])
        self.assertEqual(json.dumps(p, sort_keys=True), before)

    def test_running_server_keys_win(self):
        p = linux.new_params({"status_token": "KnjSOjpPWsaitk40x3jjKE3T", "reality_private": "OLD",
                              "reality_public": "OLDPUB"})
        logs = []
        taken = linux.adopt_server_secrets(FakeHost({"nginx": NGINX, "template": TEMPLATE, "awg": AWG}), p,
                                           log=logs.append)
        self.assertEqual(sorted(taken), ["amneziawg", "reality", "short_id", "status_token"])
        self.assertEqual(p["status_token"], "3Tkv0yk7Kbi0MyIdjXCcx1ja")
        self.assertEqual((p["reality_private"], p["reality_public"], p["short_id"]), ("SRVPRIV", "SRVPUB", "ab12cd34"))
        self.assertEqual(p["awg"]["priv"], "SRVAWG=")
        self.assertEqual((p["awg"]["port"], p["awg"]["jc"], p["awg"]["h4"]), (24227, 4, 44))
        self.assertEqual(p["awg"]["public"], "AWGPUB")
        self.assertTrue(logs and "⚠" in logs[0])

    def test_matching_server_changes_nothing(self):
        p = linux.new_params({"status_token": "3Tkv0yk7Kbi0MyIdjXCcx1ja", "reality_private": "SRVPRIV",
                              "short_id": "ab12cd34"})
        p["awg"].update(priv="SRVAWG=", port=24227, jc=4, jmin=41, jmax=80, s1=20, s2=30, h1=11, h2=22, h3=33, h4=44)
        self.assertEqual(linux.adopt_server_secrets(FakeHost({"nginx": NGINX, "template": TEMPLATE, "awg": AWG}), p,
                                                    log=lambda *_: None), [])


if __name__ == "__main__":
    unittest.main()
