// Package pvcore is the app's engine for the Linux servers: Xray (VLESS
// Reality, XHTTP, Hysteria2, Shadowsocks-2022) and AmneziaWG, built with
// gomobile into an Android library. Credentials are derived from the User
// Manager username and password exactly like server/linux/pvcreds.py.
package pvcore

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

var namespace = []byte{0x8f, 0x1c, 0x2d, 0x0e, 0x6b, 0x1a, 0x4c, 0x55, 0x9a, 0x3e, 0x5e, 0x9b, 0x0a, 0x7d, 0x2c, 0x41}

func credKey(user, pass string) []byte {
	return []byte(strings.ToLower(strings.TrimSpace(user)) + "\n" + pass)
}

// VlessUUID is uuid5(namespace, user + "\n" + password).
func VlessUUID(user, pass string) string {
	h := sha1.New()
	h.Write(namespace)
	h.Write(credKey(user, pass))
	u := h.Sum(nil)[:16]
	u[6] = (u[6] & 0x0f) | 0x50
	u[8] = (u[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

func tagged(tag string, user, pass string) [32]byte {
	return sha256.Sum256(append([]byte(tag+"\n"), credKey(user, pass)...))
}

// Hy2Auth is the Hysteria2 password.
func Hy2Auth(user, pass string) string {
	s := tagged("pv-hy2", user, pass)
	return hex.EncodeToString(s[:])[:32]
}

// SSKey is the Shadowsocks-2022 (aes-128) user key.
func SSKey(user, pass string) string {
	s := tagged("pv-ss", user, pass)
	return base64.StdEncoding.EncodeToString(s[:16])
}

func awgPrivateRaw(user, pass string) []byte {
	k := tagged("pv-awg", user, pass)
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k[:]
}

// AwgPrivate is the WireGuard private key (base64).
func AwgPrivate(user, pass string) string {
	return base64.StdEncoding.EncodeToString(awgPrivateRaw(user, pass))
}

// AwgAddress is the tunnel address, from the username alone.
func AwgAddress(user string) string {
	s := sha256.Sum256([]byte("pv-awg-ip\n" + strings.ToLower(strings.TrimSpace(user))))
	h := binary.BigEndian.Uint32(s[:4])
	const size = 1 << 22 // 10.64.0.0/10
	offset := 2 + h%(size-3)
	base := uint32(10)<<24 | uint32(64)<<16
	ip := base + offset
	return fmt.Sprintf("%d.%d.%d.%d", ip>>24, (ip>>16)&255, (ip>>8)&255, ip&255)
}
