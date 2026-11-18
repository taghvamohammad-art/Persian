import base64
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import awgrelay as ar  # noqa: E402

SERVER = base64.b64encode(bytes(range(32))).decode()
ROUTER = base64.b64encode(bytes(range(32, 64))).decode()
CFG = {"h1": 1234567, "h2": 2345678, "h3": 3456789, "h4": 4567890, "s1": 37, "s2": 51,
       "jc": 4, "jmin": 40, "jmax": 70, "server_public": SERVER, "router_public": ROUTER}


def plain(kind, size, receiver_public):
    """A WireGuard message as a standard peer makes it (valid MAC1, zero MAC2)."""
    body = struct.pack("<I", kind) + os.urandom(size - 36)
    if kind in (ar.INIT, ar.RESPONSE):
        return body + ar.mac1(ar.mac1_key(receiver_public), body) + bytes(16)
    return body + os.urandom(32)


def mac_ok(msg, public):
    end = len(msg) - 32
    return ar.mac1(ar.mac1_key(public), msg[:end]) == msg[end:end + 16]


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.r = ar.Relay(CFG)

    def test_initiation_goes_out_as_amneziawg(self):
        out = self.r.outgoing(plain(ar.INIT, 148, SERVER))
        self.assertEqual(len(out), 5)                                  # Jc junk + the message
        for j in out[:4]:
            self.assertTrue(40 <= len(j) <= 70)
        msg = out[-1]
        self.assertEqual(len(msg), 37 + 148)
        self.assertEqual(struct.unpack("<I", msg[37:41])[0], CFG["h1"])
        self.assertTrue(mac_ok(msg[37:], SERVER))                      # the server accepts it

    def test_response_both_ways(self):
        out = self.r.outgoing(plain(ar.RESPONSE, 92, SERVER))
        self.assertEqual(len(out), 1)
        self.assertEqual(len(out[0]), 51 + 92)
        self.assertTrue(mac_ok(out[0][51:], SERVER))
        # the server answers the router's initiation
        body = struct.pack("<I", CFG["h2"]) + os.urandom(56)
        awg = os.urandom(51) + body + ar.mac1(ar.mac1_key(ROUTER), body) + bytes(16)
        back = self.r.incoming(awg)
        self.assertEqual(len(back), 92)
        self.assertEqual(back[:4], b"\x02\0\0\0")
        self.assertTrue(mac_ok(back, ROUTER))                          # the router accepts it
        self.assertEqual(back[4:60], body[4:])

    def test_server_initiation_reaches_router(self):
        body = struct.pack("<I", CFG["h1"]) + os.urandom(112)
        awg = os.urandom(37) + body + ar.mac1(ar.mac1_key(ROUTER), body) + bytes(16)
        back = self.r.incoming(awg)
        self.assertEqual(back[:4], b"\x01\0\0\0")
        self.assertTrue(mac_ok(back, ROUTER))

    def test_transport_untouched_but_relabelled(self):
        pkt = plain(ar.TRANSPORT, 200, SERVER)
        out = self.r.outgoing(pkt)
        self.assertEqual(out, [struct.pack("<I", CFG["h4"]) + pkt[4:]])
        self.assertEqual(self.r.incoming(out[0]), pkt)
        cookie = plain(ar.COOKIE, 64, SERVER)
        self.assertEqual(self.r.incoming(self.r.outgoing(cookie)[0]), cookie)

    def test_junk_and_garbage_dropped(self):
        self.assertIsNone(self.r.incoming(os.urandom(55)))
        self.assertIsNone(self.r.incoming(b"\x04\0\0\0" + os.urandom(60)))   # plain WG is not AmneziaWG
        self.assertEqual(self.r.outgoing(b"\x01\0\0\0" + bytes(10)), [])
        self.assertEqual(self.r.outgoing(b"ab"), [])

    def test_no_obfuscation_params(self):
        r = ar.Relay(dict(CFG, jc=0, s1=0, s2=0))
        out = r.outgoing(plain(ar.INIT, 148, SERVER))
        self.assertEqual(len(out), 1)
        self.assertEqual(len(out[0]), 148)


if __name__ == "__main__":
    unittest.main()
