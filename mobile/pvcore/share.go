package pvcore

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Hotspot sharing. Android sends what hotspot devices do straight to the
// internet, not through the VPN; without root the way to share the tunnel
// is a proxy: devices on the hotspot set it in their Wi-Fi settings. One
// port speaks both HTTP proxy (CONNECT and plain) and SOCKS5 (TCP).
//
// Every connection goes into the running Xray tunnel (its local SOCKS
// port, looked up per connection, so protocol switches are followed); with
// no Xray tunnel the proxy refuses rather than going out directly. Only
// devices on the phone's own local networks (not the uplink) may connect.

var (
	shareMu     sync.Mutex
	shareLn     net.Listener
	shareUplink string
	sharePort   int
	shareGiven  []*net.IPNet // from the app (Android 11+ hides interfaces from Go)
)

// SetShareNets: the phone's hotspot / tethering networks as the app sees
// them, one "ip/prefix" per line. Android 11+ does not let Go list network
// interfaces, so the app passes them in (and again when they change).
func SetShareNets(spec string) {
	var nets []*net.IPNet
	for _, l := range strings.Fields(spec) {
		if ip, n, err := net.ParseCIDR(l); err == nil && ip.To4() != nil && ip.IsPrivate() {
			n.IP = ip
			nets = append(nets, n)
		}
	}
	shareMu.Lock()
	shareGiven = nets
	shareMu.Unlock()
}

// StartShare opens the proxy on port (all local addresses; access checked
// per connection). uplink: the interface the phone reaches the internet
// on (never allowed). Calling it again replaces the previous one.
func StartShare(port int, uplink string) error {
	StopShare()
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return err
	}
	shareMu.Lock()
	shareLn, shareUplink, sharePort = ln, uplink, port
	shareMu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveShare(c)
		}
	}()
	return nil
}

// StopShare closes the proxy (open connections end with the tunnel).
func StopShare() {
	shareMu.Lock()
	defer shareMu.Unlock()
	if shareLn != nil {
		shareLn.Close()
		shareLn = nil
	}
}

// SetShareUplink: the phone moved to another network (Wi-Fi <-> mobile data).
func SetShareUplink(uplink string) {
	shareMu.Lock()
	shareUplink = uplink
	shareMu.Unlock()
}

// ShareAddresses: "ip:port" lines where hotspot devices can reach the
// proxy ("" when no hotspot / tethering network is up or sharing is off).
func ShareAddresses() string {
	shareMu.Lock()
	on, port, uplink := shareLn != nil, sharePort, shareUplink
	shareMu.Unlock()
	if !on {
		return ""
	}
	var out []string
	for _, n := range localNets(uplink) {
		out = append(out, net.JoinHostPort(n.IP.String(), strconv.Itoa(port)))
	}
	sort.Strings(out)
	return strings.Join(out, "\n")
}

// localNets: private IPv4 networks of the phone's interfaces that are not
// the uplink, loopback or a tunnel: the hotspot / USB / Bluetooth tethering.
func localNets(uplink string) []*net.IPNet {
	shareMu.Lock()
	out := append([]*net.IPNet(nil), shareGiven...)
	shareMu.Unlock()
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, i := range ifs {
		name := strings.ToLower(i.Name)
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || i.Name == uplink ||
			strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "rmnet") || strings.HasPrefix(name, "ccmni") ||
			strings.HasPrefix(name, "dummy") || strings.HasPrefix(name, "p2p") {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && n.IP.IsPrivate() && !hasNet(out, n) {
				out = append(out, n)
			}
		}
	}
	return out
}

var shareAnyone = false // tests: allow loopback clients

func hasNet(list []*net.IPNet, n *net.IPNet) bool {
	for _, x := range list {
		if x.IP.Equal(n.IP) {
			return true
		}
	}
	return false
}

func shareAllowed(remote net.Addr) bool {
	ta, ok := remote.(*net.TCPAddr)
	if !ok {
		return false
	}
	if shareAnyone {
		return true
	}
	shareMu.Lock()
	uplink := shareUplink
	shareMu.Unlock()
	for _, n := range localNets(uplink) {
		if n.Contains(ta.IP) && !ta.IP.Equal(n.IP) {
			return true
		}
	}
	return false
}

// dialTunnel: a TCP connection to host:port through the running Xray tunnel.
func dialTunnel(host string, port int) (net.Conn, error) {
	mu.Lock()
	sp := socksAt
	mu.Unlock()
	if sp == 0 {
		return nil, errors.New("no tunnel")
	}
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", sp), 5*time.Second)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(30 * time.Second))
	req := []byte{5, 1, 0}
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	var r [2]byte
	if _, err := io.ReadFull(c, r[:]); err != nil || r[0] != 5 || r[1] != 0 {
		c.Close()
		return nil, errors.New("socks greeting")
	}
	msg := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		msg = append(append(msg, 1), ip.To4()...)
	} else if ip != nil {
		msg = append(append(msg, 4), ip.To16()...)
	} else {
		if len(host) > 255 {
			c.Close()
			return nil, errors.New("host name too long")
		}
		msg = append(append(msg, 3, byte(len(host))), host...)
	}
	msg = binary.BigEndian.AppendUint16(msg, uint16(port))
	if _, err := c.Write(msg); err != nil {
		c.Close()
		return nil, err
	}
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[1] != 0 {
		c.Close()
		return nil, errors.New("tunnel refused the connection")
	}
	skip := map[byte]int{1: 4, 4: 16}[h[3]]
	if h[3] == 3 {
		var l [1]byte
		io.ReadFull(c, l[:])
		skip = int(l[0])
	}
	if _, err := io.CopyN(io.Discard, c, int64(skip+2)); err != nil {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if t, ok := dst.(interface{ CloseWrite() error }); ok {
			t.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	a.Close()
	b.Close()
}

func serveShare(c net.Conn) {
	if !shareAllowed(c.RemoteAddr()) {
		c.Close()
		return
	}
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	first, err := br.Peek(1)
	if err != nil {
		c.Close()
		return
	}
	if first[0] == 5 {
		serveSocks(c, br)
		return
	}
	serveHTTP(c, br)
}

func serveSocks(c net.Conn, br *bufio.Reader) {
	var g [2]byte
	if _, err := io.ReadFull(br, g[:]); err != nil {
		c.Close()
		return
	}
	if _, err := io.CopyN(io.Discard, br, int64(g[1])); err != nil {
		c.Close()
		return
	}
	c.Write([]byte{5, 0})
	var h [4]byte
	if _, err := io.ReadFull(br, h[:]); err != nil || h[1] != 1 { // CONNECT only
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		c.Close()
		return
	}
	var host string
	switch h[3] {
	case 1:
		b := make([]byte, 4)
		io.ReadFull(br, b)
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		io.ReadFull(br, b)
		host = net.IP(b).String()
	case 3:
		l, _ := br.ReadByte()
		b := make([]byte, l)
		io.ReadFull(br, b)
		host = string(b)
	default:
		c.Close()
		return
	}
	var p [2]byte
	if _, err := io.ReadFull(br, p[:]); err != nil {
		c.Close()
		return
	}
	up, err := dialTunnel(host, int(binary.BigEndian.Uint16(p[:])))
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		c.Close()
		return
	}
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	c.SetReadDeadline(time.Time{})
	pipe(&bufConn{c, br}, up)
}

func serveHTTP(c net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		c.Close()
		return
	}
	host := req.Host
	if req.URL != nil && req.URL.Host != "" {
		host = req.URL.Host
	}
	port := 80
	if req.Method == http.MethodConnect {
		port = 443
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	if host == "" {
		c.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
		c.Close()
		return
	}
	up, err := dialTunnel(host, port)
	if err != nil {
		c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})
	if req.Method == http.MethodConnect {
		c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		pipe(&bufConn{c, br}, up)
		return
	}
	// plain HTTP: this one request, then the connection closes
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	req.Close = true
	req.RequestURI = ""
	if err := req.Write(up); err != nil {
		c.Close()
		up.Close()
		return
	}
	io.Copy(c, up)
	c.Close()
	up.Close()
}

// bufConn: reads first what the bufio.Reader already buffered.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (b *bufConn) CloseWrite() error {
	if t, ok := b.Conn.(*net.TCPConn); ok {
		return t.CloseWrite()
	}
	return nil
}
