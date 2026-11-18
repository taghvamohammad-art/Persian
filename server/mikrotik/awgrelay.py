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

Standard library only:  python3 awgrelay.py /app/relay.json
"""

import hashlib
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


def serve(cfg, log=print):
    relay = Relay(cfg)
    server = (cfg["server"], int(cfg["port"]))
    inside = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    inside.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    inside.bind((cfg.get("listen_host", "0.0.0.0"), int(cfg.get("listen", 51820))))
    outside = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for s in (inside, outside):
        for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
            try:
                s.setsockopt(socket.SOL_SOCKET, opt, 4 << 20)
            except OSError:
                pass
    router = None
    stats = {"up": 0, "down": 0, "handshakes": 0, "dropped": 0}
    last_report = time.time()
    log("awgrelay: %s:%d -> %s:%d" % (inside.getsockname() + server))
    while True:
        ready, _, _ = select.select([inside, outside], [], [], 60)
        for s in ready:
            try:
                data, addr = s.recvfrom(65535)
            except OSError:
                continue
            if s is inside:
                router = addr
                out = relay.outgoing(data)
                if len(out) > 1 or (out and data[:1] == b"\x01"):
                    stats["handshakes"] += 1
                for d in out:
                    try:
                        outside.sendto(d, server)
                    except OSError as e:
                        stats["dropped"] += 1
                        if stats["dropped"] % 1000 == 1:
                            log("awgrelay: send to server: %s" % e)
                stats["up"] += 1
            else:
                if addr[0] != server[0] or addr[1] != server[1] or router is None:
                    continue
                d = relay.incoming(data)
                if d is None:
                    stats["dropped"] += 1
                    continue
                try:
                    inside.sendto(d, router)
                except OSError:
                    stats["dropped"] += 1
                stats["down"] += 1
        if time.time() - last_report > 600:
            log("awgrelay: %(up)d up, %(down)d down, %(handshakes)d handshakes, %(dropped)d dropped" % stats)
            last_report = time.time()


def main(argv):
    with open(argv[1] if len(argv) > 1 else "/app/relay.json") as f:
        cfg = json.load(f)
    while True:
        try:
            serve(cfg, log=lambda m: print(m, flush=True))
        except Exception as e:                   # keep the tunnel up whatever happens
            print("awgrelay: %s; again in 5s" % e, flush=True)
            time.sleep(5)


if __name__ == "__main__":
    main(sys.argv)
