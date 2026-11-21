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



sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "linux"))
import pv_icmp  # noqa: E402

KEY = bytes(range(16))


class Clock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t


class FakeUdp:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def close(self):
        pass


class IcmpTests(unittest.TestCase):
    """The relay's ICMP link against the Linux side, packets passed by hand
    (NAT may change the ICMP identifier on the way; nothing depends on it)."""

    def setUp(self):
        self.clock = Clock()
        self.to_server, self.to_client, self.udps = [], [], []

        def open_udp():
            u = FakeUdp()
            self.udps.append(u)
            return u
        self.srv = pv_icmp.Server(KEY, 51820, lambda *a: self.to_client.append(a), open_udp, now=self.clock)
        self.link = ar.IcmpLink(KEY, "203.0.113.5", self.to_server.append, now=self.clock)

    def deliver_up(self, nat_ident=4242):
        """Client requests -> server (identifier rewritten as by a NAT)."""
        while self.to_server:
            pkt = self.to_server.pop(0)
            kind, _, _, ident, seq = struct.unpack("!BBHHH", pkt[:8])
            self.assertEqual(kind, ar.ECHO_REQUEST)
            self.assertEqual(ar.checksum(pkt), 0)
            self.srv.request("198.51.100.7", nat_ident, seq, pkt[8:])

    def deliver_down(self):
        got = []
        while self.to_client:
            dest, kind, ident, seq, payload = self.to_client.pop(0)
            self.assertEqual((dest, kind), ("198.51.100.7", ar.ECHO_REPLY))
            d = self.link.reply(self.link.ident, seq, payload)   # NAT gives the identifier back
            if d is not None:
                got.append(d)
        return got

    def test_packets_both_ways(self):
        self.link.send(b"wg-up-1")
        self.deliver_up()
        self.assertEqual(self.udps[0].sent, [(b"wg-up-1", ("127.0.0.1", 51820))])
        self.assertEqual(self.to_client, [])                 # held: nothing to say yet
        sess_key = next(iter(self.srv.sessions))
        sess = self.srv.sessions[sess_key]
        for n in range(5):                                   # AmneziaWG answers a burst
            self.srv.from_awg(sess_key[0], sess_key[1], sess, b"wg-down-%d" % n)
        got = self.deliver_down()
        self.deliver_up()                                    # the link polled for more
        got += self.deliver_down()
        for _ in range(4):
            self.deliver_up()
            got += self.deliver_down()
        self.assertEqual(got, [b"wg-down-%d" % n for n in range(5)])

    def test_held_polls_answered_empty(self):
        self.link.pump()
        self.deliver_up()
        self.assertEqual(self.to_client, [])
        self.clock.t += pv_icmp.HOLD
        self.srv.tick()
        self.assertEqual(len(self.to_client), 1)
        self.assertEqual(self.deliver_down(), [])

    def test_busy_link_keeps_more_polls(self):
        self.link.pump()
        self.assertEqual(len(self.to_server), ar.IcmpLink.IDLE_POLLS)
        self.link.send(b"x")
        self.link.pump()
        self.assertEqual(len(self.link.outstanding), ar.IcmpLink.BUSY_POLLS)
        self.clock.t += 5                                    # all lost, idle again
        self.link.pump()
        self.assertEqual(len(self.link.outstanding), ar.IcmpLink.IDLE_POLLS)

    def test_ordinary_ping_answered_and_strangers_ignored(self):
        self.srv.request("192.0.2.9", 7, 1, b"abcdefgh" * 4)
        self.assertEqual(self.to_client, [("192.0.2.9", ar.ECHO_REPLY, 7, 1, b"abcdefgh" * 4)])
        forged = ar.seal(bytes(16), b"C", 0, b"\0\0\0\1", b"evil")      # wrong key: just a ping
        self.to_client.clear()
        self.srv.request("192.0.2.9", 7, 2, forged)
        self.assertEqual(self.to_client[0][4], forged)
        self.assertEqual(self.srv.sessions, {})
        self.assertIsNone(self.link.reply(self.link.ident, 9, ar.seal(KEY, b"S", 0, b"zzzz", b"x")))

    def test_wire_format_matches_linux_side(self):
        for name in ("checksum", "icmp_packet", "seal", "unseal", "parse_ip"):
            self.assertTrue(hasattr(pv_icmp, name))
        sealed = ar.seal(KEY, b"C", 1, b"abcd", b"data")
        self.assertEqual(sealed, pv_icmp.seal(KEY, b"C", 1, b"abcd", b"data"))
        self.assertEqual(pv_icmp.unseal(KEY, b"C", sealed), (1, b"abcd", b"data"))
        self.assertIsNone(pv_icmp.unseal(KEY, b"S", sealed))           # directions differ
        self.assertEqual(ar.icmp_packet(8, 1, 2, b"xy"), pv_icmp.icmp_packet(8, 1, 2, b"xy"))


class CarrierTests(unittest.TestCase):
    def test_moves_to_icmp_after_unanswered_handshakes_and_back(self):
        clock = Clock()
        c = ar.Carrier("auto", now=clock)
        self.assertEqual([c.route(True) for _ in range(ar.UDP_FAILED_INITS)], ["udp"] * ar.UDP_FAILED_INITS)
        self.assertEqual(c.route(False), "udp")
        self.assertEqual(c.route(True), "icmp")
        self.assertEqual(c.route(False), "icmp")
        self.assertEqual(c.route(True), "icmp")              # not time to try UDP yet
        clock.t += ar.UDP_RETRY
        self.assertEqual(c.route(True), "udp")               # one handshake tries UDP
        self.assertEqual(c.route(False), "icmp")
        c.heard_udp()                                        # and UDP answered
        self.assertEqual(c.route(False), "udp")

    def test_answered_handshakes_stay_on_udp(self):
        c = ar.Carrier("auto")
        for _ in range(20):
            self.assertEqual(c.route(True), "udp")
            c.heard_udp()

    def test_forced_and_unavailable(self):
        self.assertEqual(ar.Carrier("icmp").route(False), "icmp")
        c = ar.Carrier("auto", icmp_ok=False)
        self.assertEqual([c.route(True) for _ in range(10)], ["udp"] * 10)


@unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "raw sockets need root")
class IcmpLoopbackTests(unittest.TestCase):
    """Real raw sockets on 127.0.0.1: the relay talks ICMP to pv_icmp, which
    hands the packets to a stand-in for AmneziaWG (an echo on UDP)."""

    def test_round_trip_over_real_icmp(self):
        import socket
        import threading
        awg = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        awg.bind(("127.0.0.1", 0))
        awg.settimeout(5)

        def echo():
            while True:
                try:
                    data, addr = awg.recvfrom(65535)
                except OSError:
                    return
                awg.sendto(b"back:" + data, addr)
        threading.Thread(target=echo, daemon=True).start()
        cfg = {"key": KEY.hex(), "awg_port": awg.getsockname()[1]}
        threading.Thread(target=pv_icmp.serve, args=(cfg, lambda m: None), daemon=True).start()
        import time
        time.sleep(0.3)
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        raw.settimeout(0.2)
        link = ar.IcmpLink(KEY, "127.0.0.1", lambda pkt: raw.sendto(pkt, ("127.0.0.1", 0)))
        want = [b"pkt%d" % i + bytes(1300) for i in range(20)]
        for w in want:
            link.send(w)
        got, end = [], time.time() + 5
        while len(got) < len(want) and time.time() < end:
            try:
                packet = raw.recv(65535)
            except socket.timeout:
                link.pump()
                continue
            p = ar.parse_ip(packet)
            if p and p[1] == ar.ECHO_REPLY and p[2] == link.ident:
                d = link.reply(p[2], p[3], p[4])
                if d:
                    got.append(d)
        awg.close()
        self.assertEqual(sorted(got), sorted(b"back:" + w for w in want))

if __name__ == "__main__":
    unittest.main()
