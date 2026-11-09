"""Per-user credentials derived from the User Manager username and password.

The server (pv-agent) and every client compute the same values, so nothing
is handed out per user: knowing the username and password is the account.
A password changed in User Manager changes all of them, which revokes the
old ones on the next sync. Keep this file in step with docs/CREDENTIALS.md
and the app implementations.
"""

import base64
import hashlib
import ipaddress
import uuid

NAMESPACE = uuid.UUID("8f1c2d0e-6b1a-4c55-9a3e-5e9b0a7d2c41")
AWG_SUBNET = ipaddress.ip_network("10.64.0.0/10")


def _key(username, password):
    return ("%s\n%s" % (username.strip().lower(), password)).encode("utf-8")


def vless_uuid(username, password):
    return str(uuid.uuid5(NAMESPACE, _key(username, password).decode("utf-8")))


def hy2_auth(username, password):
    return hashlib.sha256(b"pv-hy2\n" + _key(username, password)).hexdigest()[:32]


def ss_key(username, password):
    """User key for 2022-blake3-aes-128-gcm (16 bytes, base64)."""
    return base64.b64encode(hashlib.sha256(b"pv-ss\n" + _key(username, password)).digest()[:16]).decode()


def awg_private(username, password):
    """WireGuard private key (clamped Curve25519 scalar, base64)."""
    k = bytearray(hashlib.sha256(b"pv-awg\n" + _key(username, password)).digest())
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return base64.b64encode(bytes(k)).decode()


def awg_address(username):
    """Tunnel address from the username alone (survives a password change)."""
    h = int.from_bytes(hashlib.sha256(b"pv-awg-ip\n" + username.strip().lower().encode()).digest()[:4], "big")
    size = AWG_SUBNET.num_addresses
    offset = 2 + h % (size - 3)          # .0 is the network, .1 the server, last is broadcast
    return str(AWG_SUBNET.network_address + offset)
