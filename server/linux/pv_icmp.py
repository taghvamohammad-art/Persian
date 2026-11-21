"""ICMP carrier for the main router's backup tunnel (Linux side).

When Iran's filtering cuts UDP towards the Linux server (it has happened on
some routes since October 2026, while ping still passes), the relay on the
main router (server/mikrotik/awgrelay.py) wraps the AmneziaWG packets in
ICMP echo requests instead. This service unwraps them, hands them to the
local AmneziaWG port over UDP, and sends AmneziaWG's answers back inside
echo replies. Echo replies can only answer requests, so the relay keeps a
few empty "polls" outstanding; they are held here up to HOLD seconds and
used for whatever AmneziaWG sends back.

Packets are recognised by a magic and a keyed tag; any other echo request
gets the ordinary reply (the kernel's own replies are off while this runs,
so ping keeps working). The contents stay AmneziaWG's: encrypted and
authenticated end to end; nothing here can read them.

Standard library only:  python3 pv_icmp.py /etc/pv-agent/icmp.json
"""

import collections
import hashlib
import hmac
import json
import os
import select
import socket
import struct
import sys
import time

MAGIC = b"PVI1"
TAG_LEN = 8
POLL, MORE = 0x01, 0x02
ECHO_REPLY, ECHO_REQUEST = 0, 8
HOLD = 0.5                 # an empty poll waits this long for AmneziaWG to have something
MAX_PENDING = 64           # polls held per session
MAX_QUEUE = 512            # packets from AmneziaWG waiting for a poll
SESSION_IDLE = 180


# ---------------------------------------------------------------- wire format (same in awgrelay.py)

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def icmp_packet(kind, ident, seq, payload):
    head = struct.pack("!BBHHH", kind, 0, 0, ident, seq)
    return struct.pack("!BBHHH", kind, 0, checksum(head + payload), ident, seq) + payload


def parse_ip(packet):
    """(source, type, ident, seq, payload) of an IPv4 packet carrying ICMP echo, or None."""
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    if packet[9] != 1 or len(packet) < ihl + 8:
        return None
    kind, _code, _sum, ident, seq = struct.unpack("!BBHHH", packet[ihl:ihl + 8])
    return socket.inet_ntoa(packet[12:16]), kind, ident, seq, packet[ihl + 8:]


def _tag(key, direction, body):
    return hmac.new(key, direction + body, hashlib.sha256).digest()[:TAG_LEN]


def seal(key, direction, flags, session, data=b""):
    body = bytes([flags]) + session + data
    return MAGIC + _tag(key, direction, body) + body


def unseal(key, direction, payload):
    """(flags, session, data) or None when not ours."""
    if len(payload) < len(MAGIC) + TAG_LEN + 5 or payload[:4] != MAGIC:
        return None
    tag, body = payload[4:4 + TAG_LEN], payload[4 + TAG_LEN:]
    if not hmac.compare_digest(tag, _tag(key, direction, body)):
        return None
    return body[0], body[1:5], body[5:]


# ---------------------------------------------------------------- server

class Session:
    def __init__(self, udp, now):
        self.udp = udp
        self.queue = collections.deque()
        self.pending = collections.deque()      # (ident, seq, since)
        self.seen = now


class Server:
    def __init__(self, key, awg_port, send_icmp, open_udp=None, now=time.monotonic):
        self.key = key
        self.awg = ("127.0.0.1", int(awg_port))
        self.send_icmp = send_icmp              # (dest, type, ident, seq, payload)
        self.open_udp = open_udp or self._udp
        self.now = now
        self.sessions = {}                      # (source, session id) -> Session
        self.stats = {"up": 0, "down": 0, "pings": 0, "empty": 0}

    @staticmethod
    def _udp():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.setblocking(False)
        return s

    def request(self, src, ident, seq, payload):
        got = unseal(self.key, b"C", payload)
        if got is None:                          # an ordinary ping
            self.stats["pings"] += 1
            self.send_icmp(src, ECHO_REPLY, ident, seq, payload)
            return
        flags, sid, data = got
        now = self.now()
        sess = self.sessions.get((src, sid))
        if sess is None:
            sess = self.sessions[(src, sid)] = Session(self.open_udp(), now)
        sess.seen = now
        if data and not flags & POLL:
            try:
                sess.udp.sendto(data, self.awg)
                self.stats["up"] += 1
            except OSError:
                pass
        sess.pending.append((ident, seq, now))
        while len(sess.pending) > MAX_PENDING:
            self._answer(src, sid, sess, sess.pending.popleft(), b"")
        self.flush(src, sid, sess)

    def from_awg(self, src, sid, sess, data):
        sess.queue.append(data)
        while len(sess.queue) > MAX_QUEUE:
            sess.queue.popleft()
        self.flush(src, sid, sess)

    def flush(self, src, sid, sess):
        while sess.pending and sess.queue:
            self._answer(src, sid, sess, sess.pending.popleft(), sess.queue.popleft())

    def _answer(self, src, sid, sess, poll, data):
        ident, seq, _ = poll
        flags = MORE if sess.queue else 0
        if data:
            self.stats["down"] += 1
        else:
            self.stats["empty"] += 1
        self.send_icmp(src, ECHO_REPLY, ident, seq, seal(self.key, b"S", flags, sid, data))

    def tick(self):
        now = self.now()
        for (src, sid), sess in list(self.sessions.items()):
            while sess.pending and now - sess.pending[0][2] >= HOLD:
                self._answer(src, sid, sess, sess.pending.popleft(), b"")
            if now - sess.seen > SESSION_IDLE:
                sess.udp.close()
                del self.sessions[(src, sid)]

    def sockets(self):
        return {sess.udp: key for key, sess in self.sessions.items()}


def serve(cfg, log=print):
    raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            raw.setsockopt(socket.SOL_SOCKET, opt, 4 << 20)
        except OSError:
            pass

    def send_icmp(dest, kind, ident, seq, payload):
        try:
            raw.sendto(icmp_packet(kind, ident, seq, payload), (dest, 0))
        except OSError:
            pass

    srv = Server(bytes.fromhex(cfg["key"]), cfg["awg_port"], send_icmp)
    log("pv-icmp: ready, AmneziaWG on port %s" % cfg["awg_port"])
    last_report = time.monotonic()
    while True:
        socks = srv.sockets()
        ready, _, _ = select.select([raw] + list(socks), [], [], 0.1)
        for s in ready:
            if s is raw:
                try:
                    packet, _ = raw.recvfrom(65535)
                except OSError:
                    continue
                got = parse_ip(packet)
                if got and got[1] == ECHO_REQUEST:
                    srv.request(got[0], got[2], got[3], got[4])
                continue
            src, sid = socks[s]
            sess = srv.sessions.get((src, sid))
            while sess is not None:
                try:
                    data = s.recv(65535)
                except OSError:
                    break
                srv.from_awg(src, sid, sess, data)
        srv.tick()
        if time.monotonic() - last_report > 600:
            log("pv-icmp: %(up)d up, %(down)d down, %(empty)d empty, %(pings)d pings" % srv.stats
                + ", %d sessions" % len(srv.sessions))
            last_report = time.monotonic()


def main(argv):
    with open(argv[1] if len(argv) > 1 else "/etc/pv-agent/icmp.json") as f:
        cfg = json.load(f)
    while True:
        try:
            serve(cfg, log=lambda m: print(m, flush=True))
        except Exception as e:                   # keep the carrier up whatever happens
            print("pv-icmp: %s; again in 5s" % e, flush=True)
            time.sleep(5)


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    main(sys.argv)
