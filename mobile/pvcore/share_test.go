package pvcore

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// fakeSocks: a SOCKS5 server like Xray's local inbound (CONNECT, no auth).
func fakeSocks(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				var g [3]byte
				io.ReadFull(c, g[:])
				c.Write([]byte{5, 0})
				var h [4]byte
				io.ReadFull(c, h[:])
				var host string
				switch h[3] {
				case 1:
					b := make([]byte, 4)
					io.ReadFull(c, b)
					host = net.IP(b).String()
				case 3:
					var l [1]byte
					io.ReadFull(c, l[:])
					b := make([]byte, l[0])
					io.ReadFull(c, b)
					host = string(b)
				}
				var p [2]byte
				io.ReadFull(c, p[:])
				if host == "example.test" {
					host = "127.0.0.1"
				}
				up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))))
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					c.Close()
					return
				}
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				pipe(c, up)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestShareProxy(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %s", r.URL.Path)
	}))
	defer web.Close()
	wport := web.Listener.Addr().(*net.TCPAddr).Port

	shareAnyone = true
	defer func() { shareAnyone = false }()
	mu.Lock()
	socksAt = 0
	mu.Unlock()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if err := StartShare(port, "none"); err != nil {
		t.Fatal(err)
	}
	defer StopShare()
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	target := fmt.Sprintf("http://example.test:%d/a", wport)

	// no tunnel: refused, never direct
	if r, err := client.Get(target); err == nil && r.StatusCode == 200 {
		t.Fatal("must not go out without the tunnel")
	}

	sp := fakeSocks(t)
	mu.Lock()
	socksAt = sp
	mu.Unlock()
	defer func() { mu.Lock(); socksAt = 0; mu.Unlock() }()

	// plain HTTP through the proxy
	r, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if string(b) != "hello /a" {
		t.Fatalf("plain HTTP: %q", b)
	}

	// CONNECT
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "CONNECT example.test:%d HTTP/1.1\r\nHost: example.test\r\n\r\n", wport)
	br := bufio.NewReader(c)
	line, _ := br.ReadString('\n')
	if !strings.Contains(line, "200") {
		t.Fatalf("CONNECT: %q", line)
	}
	br.ReadString('\n')
	fmt.Fprintf(c, "GET /b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	rest, _ := io.ReadAll(br)
	c.Close()
	if !strings.HasSuffix(string(rest), "hello /b") {
		t.Fatalf("CONNECT tunnel: %q", rest)
	}

	// SOCKS5
	c, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte{5, 1, 0})
	var g [2]byte
	io.ReadFull(c, g[:])
	msg := append([]byte{5, 1, 0, 3, byte(len("example.test"))}, "example.test"...)
	msg = binary.BigEndian.AppendUint16(msg, uint16(wport))
	c.Write(msg)
	var rep [10]byte
	io.ReadFull(c, rep[:])
	if rep[1] != 0 {
		t.Fatalf("SOCKS reply %v", rep)
	}
	fmt.Fprintf(c, "GET /c HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	rest, _ = io.ReadAll(c)
	c.Close()
	if !strings.HasSuffix(string(rest), "hello /c") {
		t.Fatalf("SOCKS tunnel: %q", rest)
	}

	// networks given by the app (Android 11+) are listed and allowed
	SetShareNets("192.168.77.1/24\n10.0.0.5/8\n8.8.8.8/24 garbage")
	if got := ShareAddresses(); !strings.Contains(got, fmt.Sprintf("192.168.77.1:%d", port)) ||
		!strings.Contains(got, "10.0.0.5:") || strings.Contains(got, "8.8.8.8") {
		t.Fatalf("addresses: %q", got)
	}
	shareAnyone = false
	if !shareAllowed(&net.TCPAddr{IP: net.ParseIP("192.168.77.20")}) || shareAllowed(&net.TCPAddr{IP: net.ParseIP("192.168.78.20")}) {
		t.Fatal("hotspot client check")
	}
	SetShareNets("")

	// strangers (not on the hotspot) are refused
	if r, err := client.Get(target); err == nil && r.StatusCode == 200 {
		t.Fatal("a client from outside the hotspot got through")
	}
}
