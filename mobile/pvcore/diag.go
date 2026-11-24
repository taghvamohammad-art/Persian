package pvcore

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Endpoints of the support test (each answers small and fast from anywhere).
var (
	DiagTraceURL = "https://1.1.1.1/cdn-cgi/trace"
	DiagNameURL  = "https://www.google.com/generate_204"
	DiagSpeedURL = "https://speed.cloudflare.com/__down?bytes=2000000"
	DiagDNS      = "1.1.1.1:53"
)

// Diagnose looks inside the running tunnel for "connected but nothing
// loads" (JSON, for the app's test screen). With an Xray protocol it asks
// through the engine's own SOCKS port what an app would: a page by IP,
// a name resolved by the server, a DNS question over UDP (what apps do
// first: the VPN's DNS servers are reached through the tunnel), the
// public IP the internet sees, and a short download. With AmneziaWG it
// reports the handshake and the bytes moved. Each step stands alone, so
// one failure points at what is broken.
func Diagnose(timeoutMs int) string {
	mu.Lock()
	kind, port, dev := running, socksAt, awgDev
	mu.Unlock()
	out := map[string]any{"running": kind, "tunnel_bytes": TunnelBytes()}
	timeout := time.Duration(timeoutMs) * time.Millisecond
	switch {
	case kind == "":
		out["error"] = "no engine running"
	case dev != nil:
		state, err := dev.IpcGet()
		if err != nil {
			out["error"] = err.Error()
			break
		}
		out["awg"] = awgSummary(state)
	default:
		out["steps"] = diagSteps(port, timeout)
	}
	b, _ := json.Marshal(out)
	return string(b)
}

type diagStep struct {
	Name  string `json:"name"`
	Ok    bool   `json:"ok"`
	Ms    int    `json:"ms"`
	Info  string `json:"info,omitempty"`
	Error string `json:"error,omitempty"`
}

func diagSteps(port int, timeout time.Duration) []diagStep {
	proxy, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", port))
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}}
	var steps []diagStep
	run := func(name string, f func() (string, error)) {
		start := time.Now()
		info, err := f()
		s := diagStep{Name: name, Ok: err == nil, Ms: int(time.Since(start).Milliseconds()), Info: info}
		if err != nil {
			s.Error = err.Error()
		}
		steps = append(steps, s)
	}
	get := func(u string, limit int64) ([]byte, error) {
		resp, err := client.Get(u)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
		if err != nil {
			return body, err
		}
		if resp.StatusCode >= 400 {
			return body, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return body, nil
	}
	run("trace", func() (string, error) { // by IP: no DNS involved
		body, err := get(DiagTraceURL, 4096)
		if err != nil {
			return "", err
		}
		var keep []string
		for _, line := range strings.Split(string(body), "\n") {
			for _, k := range []string{"ip=", "loc=", "colo="} {
				if strings.HasPrefix(line, k) {
					keep = append(keep, line)
				}
			}
		}
		return strings.Join(keep, " "), nil
	})
	run("name", func() (string, error) { // the server resolves the name
		_, err := get(DiagNameURL, 1024)
		return "", err
	})
	run("dns_udp", func() (string, error) { // what apps do first
		ips, err := socksDNS(port, DiagDNS, "www.google.com", timeout)
		return strings.Join(ips, ","), err
	})
	run("download", func() (string, error) {
		start := time.Now()
		body, err := get(DiagSpeedURL, 4<<20)
		secs := time.Since(start).Seconds()
		if len(body) == 0 {
			return "", err
		}
		return fmt.Sprintf("%d KB, %.1f Mbit/s", len(body)/1024, float64(len(body))*8/1e6/secs), err
	})
	return steps
}

func awgSummary(state string) map[string]any {
	var sec, rx, tx int64 = -1, 0, 0
	for _, line := range strings.Split(state, "\n") {
		if v, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
			fmt.Sscan(v, &sec)
		} else if v, ok := strings.CutPrefix(line, "rx_bytes="); ok {
			fmt.Sscan(v, &rx)
		} else if v, ok := strings.CutPrefix(line, "tx_bytes="); ok {
			fmt.Sscan(v, &tx)
		}
	}
	age := -1
	if sec > 0 {
		age = int(time.Since(time.Unix(sec, 0)).Seconds())
	}
	port, roam := roamState()
	return map[string]any{"handshake_age_s": age, "rx_bytes": rx, "tx_bytes": tx, "port": port, "roam": roam}
}

// socksDNS asks a DNS question over UDP through a SOCKS5 proxy (UDP
// ASSOCIATE), the way apps' DNS goes through the tunnel. Returns the A records.
func socksDNS(port int, server, name string, timeout time.Duration) ([]string, error) {
	deadline := time.Now().Add(timeout)
	ctl, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), timeout)
	if err != nil {
		return nil, err
	}
	defer ctl.Close()
	ctl.SetDeadline(deadline)
	if _, err := ctl.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	hello := make([]byte, 2)
	if _, err := io.ReadFull(ctl, hello); err != nil || hello[1] != 0 {
		return nil, fmt.Errorf("socks hello: %v", err)
	}
	if _, err := ctl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	relay, err := readSocksReply(ctl)
	if err != nil {
		return nil, err
	}
	if relay.IP.IsUnspecified() {
		relay.IP = net.IPv4(127, 0, 0, 1)
	}
	udp, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		return nil, err
	}
	defer udp.Close()
	udp.SetDeadline(deadline)
	dst, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}
	q := dnsQuery(name)
	head := []byte{0, 0, 0, 1}
	head = append(head, dst.IP.To4()...)
	head = binary.BigEndian.AppendUint16(head, uint16(dst.Port))
	if _, err := udp.Write(append(head, q...)); err != nil {
		return nil, err
	}
	buf := make([]byte, 2048)
	n, err := udp.Read(buf)
	if err != nil {
		return nil, err
	}
	if n < 10 || buf[3] != 1 {
		return nil, errors.New("bad socks udp reply")
	}
	return dnsAnswers(buf[10:n], q[:2])
}

func readSocksReply(r io.Reader) (*net.UDPAddr, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	if head[1] != 0 {
		return nil, fmt.Errorf("socks: UDP refused (%d)", head[1])
	}
	var ip net.IP
	switch head[3] {
	case 1:
		ip = make(net.IP, 4)
	case 4:
		ip = make(net.IP, 16)
	default:
		return nil, fmt.Errorf("socks: address type %d", head[3])
	}
	if _, err := io.ReadFull(r, ip); err != nil {
		return nil, err
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(p))}, nil
}

func dnsQuery(name string) []byte {
	q := []byte{0x70, 0x76, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

func dnsAnswers(msg, id []byte) ([]string, error) {
	if len(msg) < 12 || msg[0] != id[0] || msg[1] != id[1] {
		return nil, errors.New("bad DNS answer")
	}
	if rcode := msg[3] & 0x0F; rcode != 0 {
		return nil, fmt.Errorf("DNS rcode %d", rcode)
	}
	qd, an := int(binary.BigEndian.Uint16(msg[4:])), int(binary.BigEndian.Uint16(msg[6:]))
	i := 12
	skipName := func() bool {
		for i < len(msg) {
			l := int(msg[i])
			switch {
			case l == 0:
				i++
				return true
			case l&0xC0 == 0xC0:
				i += 2
				return true
			default:
				i += l + 1
			}
		}
		return false
	}
	for ; qd > 0; qd-- {
		if !skipName() {
			return nil, errors.New("bad DNS answer")
		}
		i += 4
	}
	var ips []string
	for ; an > 0 && i < len(msg); an-- {
		if !skipName() || i+10 > len(msg) {
			break
		}
		typ := binary.BigEndian.Uint16(msg[i:])
		l := int(binary.BigEndian.Uint16(msg[i+8:]))
		i += 10
		if i+l > len(msg) {
			break
		}
		if typ == 1 && l == 4 {
			ips = append(ips, net.IP(msg[i:i+4]).String())
		}
		i += l
	}
	if len(ips) == 0 {
		return nil, errors.New("no A record")
	}
	return ips, nil
}
