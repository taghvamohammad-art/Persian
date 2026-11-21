"""WireGuard -> AmneziaWG relay, for the backup tunnel of the main router.

RouterOS speaks plain WireGuard only; Iran's filtering drops that, while the
Linux servers run AmneziaWG. This small relay runs in a container on the
router: the router's WireGuard interface sends to it, and it rewrites each
packet into AmneziaWG's form (message types H1..H4, S1/S2 random bytes in
front of the handshake, Jc junk packets before each initiation) and back.

The message type is covered by the handshake's MAC1, so MAC1 is computed
again with the receiver's public key (both public keys are in the config).
Transport packets are only relabelled; their contents are never touched or
readable here.

When Iran's filtering cuts UDP to the server while ping still passes, the
same AmneziaWG packets go inside ICMP echo requests instead, to pv_icmp.py on
the Linux server (config "icmp_key"); answers come back in echo replies.
"transport": "auto" (default) uses UDP and moves to ICMP after handshakes
stop getting answers, trying UDP again every UDP_RETRY seconds; "udp" and
"icmp" force one (tests).

Standard library only:  python3 awgrelay.py /app/relay.json
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

INIT, RESPONSE, COOKIE, TRANSPORT = 1, 2, 3, 4
INIT_SIZE, RESPONSE_SIZE, COOKIE_SIZE, TRANSPORT_MIN = 148, 92, 64, 32


def mac1_key(public_b64):
    import base64
    pub = base64.b64decode(public_b64)
    if len(pub) != 32:
        raise ValueError("public key must be 32 bytes")
    return hashlib.blake2s(b"mac1----" + pub).digest()


def mac1(key, data):
    return hashlib.blake2s(data, key=key, digest_size=16).digest()


def _with_type(msg, kind, key):
    """msg with its type field set to kind; MAC1 again for handshake messages."""
    head = struct.pack("<I", kind) + msg[4:]
    if key is None:
        return head
    end = len(msg) - 32                       # mac1 | mac2 at the end
    return head[:end] + mac1(key, head[:end]) + head[end + 16:]


class Relay:
    def __init__(self, cfg, rand=os.urandom, randint=None):
        self.h = [int(cfg["h%d" % i]) for i in (1, 2, 3, 4)]
        self.s1, self.s2 = int(cfg.get("s1", 0)), int(cfg.get("s2", 0))
        self.jc, self.jmin, self.jmax = int(cfg.get("jc", 0)), int(cfg.get("jmin", 0)), int(cfg.get("jmax", 0))
        self.to_server = mac1_key(cfg["server_public"])      # MAC1 of what the server receives
        self.to_router = mac1_key(cfg["router_public"])      # MAC1 of what the router receives
        self.rand = rand
        self.randint = randint or (lambda a, b: a + int.from_bytes(rand(4), "big") % (b - a + 1))

    def outgoing(self, pkt):
        """Plain WireGuard from the router -> list of datagrams for the server."""
        if len(pkt) < 4:
            return []
        kind = struct.unpack("<I", pkt[:4])[0]
        if kind == TRANSPORT and len(pkt) >= TRANSPORT_MIN:
            return [struct.pack("<I", self.h[3]) + pkt[4:]]
        if kind == INIT and len(pkt) == INIT_SIZE:
            junk = [self.rand(self.randint(self.jmin, self.jmax)) for _ in range(self.jc)] \
                if self.jc and self.jmax >= self.jmin > 0 else []
            return junk + [self.rand(self.s1) + _with_type(pkt, self.h[0], self.to_server)]
        if kind == RESPONSE and len(pkt) == RESPONSE_SIZE:
            return [self.rand(self.s2) + _with_type(pkt, self.h[1], self.to_server)]
        if kind == COOKIE and len(pkt) == COOKIE_SIZE:
            return [_with_type(pkt, self.h[2], None)]
        return []

    def incoming(self, pkt):
        """AmneziaWG from the server -> plain WireGuard for the router (None: junk)."""
        n = len(pkt)

        def head(at):
            return struct.unpack("<I", pkt[at:at + 4])[0] if n >= at + 4 else None

        if n == self.s1 + INIT_SIZE and head(self.s1) == self.h[0]:
            return _with_type(pkt[self.s1:], INIT, self.to_router)
        if n == self.s2 + RESPONSE_SIZE and head(self.s2) == self.h[1]:
            return _with_type(pkt[self.s2:], RESPONSE, self.to_router)
        if n == COOKIE_SIZE and head(0) == self.h[2]:
            return _with_type(pkt, COOKIE, None)
        if n >= TRANSPORT_MIN and head(0) == self.h[3]:
            return struct.pack("<I", TRANSPORT) + pkt[4:]
        return None


# ---------------------------------------------------------------- ICMP carrier
# the wire format is the same as in server/linux/pv_icmp.py

ICMP_MAGIC = b"PVI1"
ICMP_TAG = 8
POLL, MORE = 0x01, 0x02
ECHO_REPLY, ECHO_REQUEST = 0, 8
UDP_FAILED_INITS = 3       # handshakes sent over UDP without any answer -> ICMP
UDP_RETRY = 120            # in ICMP mode, a handshake goes over UDP this often


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
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    if packet[9] != 1 or len(packet) < ihl + 8:
        return None
    kind, _code, _sum, ident, seq = struct.unpack("!BBHHH", packet[ihl:ihl + 8])
    return socket.inet_ntoa(packet[12:16]), kind, ident, seq, packet[ihl + 8:]


def _tag(key, direction, body):
    return hmac.new(key, direction + body, hashlib.sha256).digest()[:ICMP_TAG]


def seal(key, direction, flags, session, data=b""):
    body = bytes([flags]) + session + data
    return ICMP_MAGIC + _tag(key, direction, body) + body


def unseal(key, direction, payload):
    if len(payload) < len(ICMP_MAGIC) + ICMP_TAG + 5 or payload[:4] != ICMP_MAGIC:
        return None
    tag, body = payload[4:4 + ICMP_TAG], payload[4 + ICMP_TAG:]
    if not hmac.compare_digest(tag, _tag(key, direction, body)):
        return None
    return body[0], body[1:5], body[5:]


class IcmpLink:
    """Client end: every request carries a packet or is an empty poll; the
    server answers each one, with a packet when it has one. A few polls are
    kept outstanding so the server always has a way to send."""
    IDLE_POLLS, BUSY_POLLS, LOST = 1, 8, 2.0

    def __init__(self, key, server, send_raw, rand=os.urandom, now=time.monotonic):
        self.key, self.server, self.send_raw, self.now = key, server, send_raw, now
        self.session = rand(4)
        self.ident = int.from_bytes(rand(2), "big")
        self.seq = 0
        self.outstanding = collections.OrderedDict()   # seq -> sent at
        self.busy_until = 0.0

    def _request(self, flags, data=b""):
        self.seq = (self.seq + 1) & 0xFFFF
        self.outstanding[self.seq] = self.now()
        self.send_raw(icmp_packet(ECHO_REQUEST, self.ident, self.seq, seal(self.key, b"C", flags, self.session, data)))

    def send(self, data):
        self.busy_until = self.now() + 2
        self._request(0, data)

    def reply(self, ident, seq, payload):
        """An echo reply from the server -> AmneziaWG packet or None."""
        got = unseal(self.key, b"S", payload)
        if got is None or got[1] != self.session:
            return None
        flags, _, data = got
        self.outstanding.pop(seq, None)
        if data or flags & MORE:
            self.busy_until = self.now() + 2
        self.pump()
        return data or None

    def pump(self):
        now = self.now()
        while self.outstanding and now - next(iter(self.outstanding.values())) > self.LOST:
            self.outstanding.popitem(last=False)
        want = self.BUSY_POLLS if now < self.busy_until else self.IDLE_POLLS
        while len(self.outstanding) < want:
            self._request(POLL)


class Carrier:
    """Which way AmneziaWG packets go: UDP, or ICMP once UDP stops answering."""

    def __init__(self, transport="auto", icmp_ok=True, now=time.monotonic):
        self.transport = transport if icmp_ok else "udp"
        self.mode = "icmp" if self.transport == "icmp" else "udp"
        self.inits = 0                 # handshakes over UDP since the last UDP answer
        self.retry_at = 0.0
        self.now = now

    def heard_udp(self):
        self.inits = 0
        if self.transport == "auto":
            self.mode = "udp"

    def route(self, is_init):
        """'udp' or 'icmp' for a packet going to the server."""
        if self.transport != "auto":
            return self.mode
        if self.mode == "udp":
            if is_init:
                self.inits += 1
                if self.inits > UDP_FAILED_INITS:
                    self.mode, self.retry_at, self.inits = "icmp", self.now() + UDP_RETRY, 0
                    return "icmp"
            return "udp"
        if is_init and self.now() >= self.retry_at:        # is UDP back?
            self.retry_at = self.now() + UDP_RETRY
            return "udp"
        return "icmp"


def serve(cfg, log=print):
    relay = Relay(cfg)
    server = (cfg["server"], int(cfg["port"]))
    inside = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    inside.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    inside.bind((cfg.get("listen_host", "0.0.0.0"), int(cfg.get("listen", 51820))))
    outside = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    socks = [inside, outside]
    raw = link = None
    if cfg.get("icmp_key") and cfg.get("transport", "auto") != "udp":
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            link = IcmpLink(bytes.fromhex(cfg["icmp_key"]), server[0],
                            lambda pkt: raw.sendto(pkt, (server[0], 0)))
            socks.append(raw)
        except OSError as e:
            log("awgrelay: no ICMP carrier (%s); UDP only" % e)
            raw = link = None
    carrier = Carrier(cfg.get("transport", "auto"), icmp_ok=link is not None)
    for s in socks:
        for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
            try:
                s.setsockopt(socket.SOL_SOCKET, opt, 4 << 20)
            except OSError:
                pass
    router = None
    stats = {"up": 0, "down": 0, "handshakes": 0, "dropped": 0, "icmp_up": 0, "icmp_down": 0}
    last_report = time.time()
    mode = carrier.mode
    log("awgrelay: %s:%d -> %s:%d (%s)" % (inside.getsockname() + server + (carrier.transport,)))

    def note_mode():
        if cfg.get("mode_file"):
            try:
                with open(cfg["mode_file"], "w") as f:
                    f.write(mode)
            except OSError:
                pass
    note_mode()

    def to_router(d):
        try:
            inside.sendto(d, router)
            stats["down"] += 1
        except OSError:
            stats["dropped"] += 1

    while True:
        ready, _, _ = select.select(socks, [], [], 0.2 if link else 60)
        for s in ready:
            try:
                data, addr = s.recvfrom(65535)
            except OSError:
                continue
            if s is inside:
                router = addr
                out = relay.outgoing(data)
                is_init = data[:1] == b"\x01"
                if len(out) > 1 or (out and is_init):
                    stats["handshakes"] += 1
                way = carrier.route(is_init) if out else "udp"
                for d in out:
                    try:
                        if way == "icmp":
                            link.send(d)
                            stats["icmp_up"] += 1
                        else:
                            outside.sendto(d, server)
                    except OSError as e:
                        stats["dropped"] += 1
                        if stats["dropped"] % 1000 == 1:
                            log("awgrelay: send to server: %s" % e)
                stats["up"] += 1
            elif s is outside:
                if addr[0] != server[0] or addr[1] != server[1] or router is None:
                    continue
                carrier.heard_udp()
                d = relay.incoming(data)
                if d is None:
                    stats["dropped"] += 1
                    continue
                to_router(d)
            else:
                got = parse_ip(data)
                if not got or got[0] != server[0] or got[1] != ECHO_REPLY or got[2] != link.ident:
                    continue
                pkt = link.reply(got[2], got[3], got[4])
                if pkt is None or router is None:
                    continue
                d = relay.incoming(pkt)
                if d is not None:
                    stats["icmp_down"] += 1
                    to_router(d)
        if link is not None and carrier.mode == "icmp":
            try:
                link.pump()
            except OSError:
                pass
        if carrier.mode != mode:
            mode = carrier.mode
            log("awgrelay: now over %s" % mode.upper())
            note_mode()
        if time.time() - last_report > 600:
            log("awgrelay: %(up)d up, %(down)d down, %(handshakes)d handshakes, %(dropped)d dropped, "
                "ICMP %(icmp_up)d up %(icmp_down)d down" % stats + " (%s)" % mode)
            last_report = time.time()


def main(argv):
    path = argv[1] if len(argv) > 1 else "/app/relay.json"
    with open(path) as f:
        cfg = json.load(f)
    cfg.setdefault("mode_file", os.path.join(os.path.dirname(os.path.abspath(path)), "mode.txt"))
    while True:
        try:
            serve(cfg, log=lambda m: print(m, flush=True))
        except Exception as e:                   # keep the tunnel up whatever happens
            print("awgrelay: %s; again in 5s" % e, flush=True)
            time.sleep(5)


if __name__ == "__main__":
    main(sys.argv)
