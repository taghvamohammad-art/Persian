package pvcore

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// A SOCKS5 server with UDP ASSOCIATE in front of a DNS server, both
// minimal: what Xray's socks inbound does for the app's DNS.
func fakeSocksDNS(t *testing.T, answer net.IP) int {
	t.Helper()
	dns, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dns.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := dns.ReadFromUDP(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			resp := append([]byte{}, q[:2]...)
			resp = append(resp, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
			resp = append(resp, q[12:]...)
			resp = append(resp, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
			resp = append(resp, answer.To4()...)
			dns.WriteToUDP(resp, from)
		}
	}()
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
				defer c.Close()
				b := make([]byte, 3)
				io.ReadFull(c, b)
				c.Write([]byte{5, 0})
				req := make([]byte, 10)
				io.ReadFull(c, req)
				relay, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				defer relay.Close()
				p := relay.LocalAddr().(*net.UDPAddr).Port
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, byte(p >> 8), byte(p)})
				buf := make([]byte, 1500)
				relay.SetDeadline(time.Now().Add(5 * time.Second))
				n, client, err := relay.ReadFromUDP(buf)
				if err != nil || n < 10 {
					return
				}
				// the question goes to "1.1.1.1:53" in the header; here to the fake DNS
				dns2, _ := net.DialUDP("udp", nil, dns.LocalAddr().(*net.UDPAddr))
				defer dns2.Close()
				dns2.Write(buf[10:n])
				dns2.SetDeadline(time.Now().Add(5 * time.Second))
				ans := make([]byte, 1500)
				m, err := dns2.Read(ans)
				if err != nil {
					return
				}
				head := append([]byte{0, 0, 0, 1}, buf[4:8]...)
				head = binary.BigEndian.AppendUint16(head, binary.BigEndian.Uint16(buf[8:10]))
				relay.WriteToUDP(append(head, ans[:m]...), client)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestSocksDNS(t *testing.T) {
	port := fakeSocksDNS(t, net.IPv4(142, 250, 1, 2))
	ips, err := socksDNS(port, "1.1.1.1:53", "www.google.com", 3*time.Second)
	if err != nil || len(ips) != 1 || ips[0] != "142.250.1.2" {
		t.Fatalf("%v %v", ips, err)
	}
}

func TestDNSAnswerErrors(t *testing.T) {
	q := dnsQuery("a.b")
	if _, err := dnsAnswers(q, []byte{9, 9}); err == nil {
		t.Fatal("wrong id accepted")
	}
	bad := append([]byte{}, q...)
	bad[3] = 3 // NXDOMAIN
	if _, err := dnsAnswers(bad, q[:2]); err == nil {
		t.Fatal("rcode ignored")
	}
}

func TestDiagnoseWithoutEngine(t *testing.T) {
	if got := Diagnose(1000); got == "" || !strings.Contains(got, "no engine running") {
		t.Fatal(got)
	}
}

func TestEchoPackets(t *testing.T) {
	src, dst := netip.MustParseAddr("10.64.1.2"), netip.MustParseAddr("1.1.1.1")
	p := echoRequest(src, dst, pingID, 201, awgProbeBig)
	if len(p) != awgProbeBig || inetChecksum(p[:20]) != 0 || inetChecksum(p[20:]) != 0 {
		t.Fatal("bad request packet")
	}
	if _, ok := echoReplySeq(p, pingID); ok {
		t.Fatal("a request taken for a reply")
	}
	r := append([]byte{}, p...) // what 1.1.1.1 sends back
	copy(r[12:16], p[16:20])
	copy(r[16:20], p[12:16])
	r[20] = 0
	if seq, ok := echoReplySeq(r, pingID); !ok || seq != 201 {
		t.Fatal(seq, ok)
	}
	if _, ok := echoReplySeq(r, 1); ok {
		t.Fatal("other id accepted")
	}
}

func TestPingTunCarriesPings(t *testing.T) {
	pt := newPingTun(netip.MustParseAddr("10.64.1.2"))
	defer pt.Close()
	done := make(chan [2]bool)
	go func() { s, b := pt.pingBoth(2 * time.Second); done <- [2]bool{s, b} }()
	buf := [][]byte{make([]byte, 2000)}
	sizes := []int{0}
	for i := 0; i < 4; i++ { // the device reads the requests and "answers" them
		if _, err := pt.Read(buf, sizes, 0); err != nil {
			t.Fatal(err)
		}
		r := append([]byte{}, buf[0][:sizes[0]]...)
		r[20] = 0
		pt.Write([][]byte{r}, 0)
	}
	if got := <-done; !got[0] || !got[1] {
		t.Fatal(got)
	}
}
