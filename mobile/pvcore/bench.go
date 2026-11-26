package pvcore

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The test app (ir.persianvpn.tester): every protocol of a server, each
// way of reaching it (every CDN way, AmneziaWG on several ports), and the
// lab protocols of xray-lab (tools/release_tool/lab.py), one at a time:
// first whether it connects (three requests), then its speed (a download
// for a few seconds). Nothing here touches the VPN; the test app has none.

// BenchSpeedURL: a large download from a fast, widely reachable host.
var BenchSpeedURL = "https://speed.cloudflare.com/__down?bytes=100000000"

type benchItem struct {
	Name   string          `json:"name"`
	Server json.RawMessage `json:"server"`
	Lab    []struct {
		ID       string         `json:"id"`
		Label    string         `json:"label"`
		Outbound map[string]any `json:"outbound"`
	} `json:"lab"`
}

type benchTest struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Group string `json:"group"`
}

var protoLabels = map[string]string{
	"vless-reality-vision": "Reality (VLESS Vision)", "vless-xhttp-reality": "XHTTP + Reality",
	"hysteria2": "Hysteria2", "shadowsocks-2022": "Shadowsocks-2022", "vless-xhttp-cdn": "CDN",
	"vless-dns": "تونل DNS", "amneziawg": "AmneziaWG",
}

// BenchList: the tests of one server of the export, as JSON.
func BenchList(itemJSON string) string {
	var it benchItem
	if err := json.Unmarshal([]byte(itemJSON), &it); err != nil {
		return "[]"
	}
	var out []benchTest
	if len(it.Server) > 0 {
		if s, err := parseServer(string(it.Server)); err == nil {
			for _, p := range s.Protocols {
				label := protoLabels[p.Type]
				if label == "" {
					label = p.Type
				}
				switch p.Type {
				case "amneziawg":
					ports := awgPortList(p.Port, p.Hop)
					pick := []int{ports[0]}
					for i := 1; i < len(ports) && len(pick) < 5; i += max(1, len(ports)/4) {
						pick = append(pick, ports[i])
					}
					for _, port := range pick {
						out = append(out, benchTest{"awg@" + strconv.Itoa(port),
							fmt.Sprintf("%s پورت %d", label, port), "اصلی"})
					}
				case "vless-xhttp-cdn":
					for i, v := range cdnVariants {
						if v.addr == "" && v.ip >= max(1, len(p.IPs)) {
							continue
						}
						out = append(out, benchTest{"cdn#" + strconv.Itoa(i), label + " " + v.String(), "اصلی"})
					}
				default:
					out = append(out, benchTest{p.Type, label, "اصلی"})
				}
			}
			out = append(out, benchTest{"pool", "مجموعه‌ی Xray (مثل اپ)", "اصلی"})
		}
	}
	for _, l := range it.Lab {
		out = append(out, benchTest{"lab:" + l.ID, l.Label, "آزمایشی"})
	}
	b, _ := json.Marshal(out)
	return string(b)
}

type benchResult struct {
	OK    bool    `json:"ok"`
	Ms    int     `json:"ms"`
	Got   int     `json:"got"`
	Tries int     `json:"tries"`
	Mbps  float64 `json:"mbps"`
	MB    float64 `json:"mb"`
	Error string  `json:"error,omitempty"`
}

// BenchRun: one test (an id from BenchList), as JSON.
func BenchRun(itemJSON, id, user, pass string, speedSeconds int) string {
	r := benchRun(itemJSON, id, user, pass, time.Duration(speedSeconds)*time.Second)
	b, _ := json.Marshal(r)
	return string(b)
}

func benchRun(itemJSON, id, user, pass string, speed time.Duration) benchResult {
	var it benchItem
	if err := json.Unmarshal([]byte(itemJSON), &it); err != nil {
		return benchResult{Error: err.Error()}
	}
	server := string(it.Server)
	port, err := freePort()
	if err != nil {
		return benchResult{Error: err.Error()}
	}
	var cfg string
	switch {
	case strings.HasPrefix(id, "awg@"):
		p, _ := strconv.Atoi(strings.TrimPrefix(id, "awg@"))
		return benchAwg(server, user, pass, p, speed)
	case strings.HasPrefix(id, "lab:"):
		for _, l := range it.Lab {
			if "lab:"+l.ID == id {
				ob := map[string]any{}
				for k, v := range l.Outbound {
					ob[k] = v
				}
				ob["tag"] = "proxy"
				b, err := json.Marshal(baseConfig(port, []any{ob}, nil, map[string]any{"outboundTag": "proxy"}))
				if err != nil {
					return benchResult{Error: err.Error()}
				}
				cfg = string(b)
			}
		}
		if cfg == "" {
			return benchResult{Error: "unknown test"}
		}
	case strings.HasPrefix(id, "cdn#"):
		i, _ := strconv.Atoi(strings.TrimPrefix(id, "cdn#"))
		if i < 0 || i >= len(cdnVariants) {
			return benchResult{Error: "unknown test"}
		}
		v := cdnVariants[i]
		cfg, err = xrayConfigWith(server, "vless-xhttp-cdn", user, pass, port, func(q *Protocol) { q.variant = &v })
	case id == "pool":
		s, perr := parseServer(server)
		if perr != nil {
			return benchResult{Error: perr.Error()}
		}
		var choices []map[string]any
		for _, p := range s.Protocols {
			if p.Type != "amneziawg" && p.Type != "vless-dns" {
				choices = append(choices, map[string]any{"server": json.RawMessage(server), "kind": p.Type})
			}
		}
		cj, _ := json.Marshal(choices)
		cfg, err = PoolConfig(string(cj), user, pass, port)
	default:
		cfg, err = XrayConfig(server, id, user, pass, port)
	}
	if err != nil {
		return benchResult{Error: err.Error()}
	}
	inst, err := startXrayInstance(cfg)
	if err != nil {
		return benchResult{Error: err.Error()}
	}
	defer inst.Close()
	proxy, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", port))
	tr := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	return benchHTTP(tr, speed)
}

// benchHTTP: three test requests, then a download for `speed`.
func benchHTTP(tr *http.Transport, speed time.Duration) benchResult {
	res := benchResult{Tries: 3}
	client := &http.Client{Timeout: 10 * time.Second, Transport: tr}
	total := 0
	var last error
	for i := 0; i < res.Tries; i++ {
		start := time.Now()
		resp, err := client.Get(ProbeURL)
		if err != nil {
			last = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != 204 && resp.StatusCode != 200 {
			last = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		res.Got++
		total += int(time.Since(start).Milliseconds())
	}
	if res.Got == 0 {
		res.Error = shortBenchErr(last)
		return res
	}
	res.OK = true
	res.Ms = total / res.Got
	if speed <= 0 {
		return res
	}
	ctx, cancel := context.WithTimeout(context.Background(), speed+5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", BenchSpeedURL, nil)
	start := time.Now()
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		res.Error = "speed: " + shortBenchErr(err)
		return res
	}
	defer resp.Body.Close()
	buf := make([]byte, 64<<10)
	var n int64
	first := time.Time{}
	for time.Since(start) < speed+5*time.Second {
		k, err := resp.Body.Read(buf)
		if k > 0 && first.IsZero() {
			first = time.Now()
		}
		n += int64(k)
		if err != nil || (!first.IsZero() && time.Since(first) >= speed) {
			if err != nil && err != io.EOF && n == 0 {
				res.Error = "speed: " + shortBenchErr(err)
			}
			break
		}
	}
	if !first.IsZero() {
		if el := time.Since(first).Seconds(); el > 0 {
			res.Mbps = float64(n) * 8 / el / 1e6
		}
	}
	res.MB = float64(n) / 1e6
	return res
}

func shortBenchErr(err error) string {
	if err == nil {
		return "?"
	}
	e := err.Error()
	switch {
	case strings.Contains(e, "deadline exceeded") || strings.Contains(e, "Timeout"):
		return "timeout"
	case strings.Contains(e, "EOF"):
		return "EOF (قطع از طرف سرور یا فیلتر)"
	case strings.Contains(e, "connection refused"):
		return "connection refused"
	case strings.Contains(e, "connection reset"):
		return "connection reset (فیلتر)"
	}
	if len(e) > 90 {
		e = e[:90]
	}
	return e
}

// benchDialer: an http.Transport whose connections go through dial (the
// host is looked up outside, on the phone's own DNS).
func benchTransport(dial func(ctx context.Context, ip net.IP, port int) (net.Conn, error)) *http.Transport {
	return &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, ps, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, _ := strconv.Atoi(ps)
			ip := net.ParseIP(host)
			if ip == nil {
				ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
				if err != nil || len(ips) == 0 {
					return nil, fmt.Errorf("lookup %s: %v", host, err)
				}
				ip = ips[0]
			}
			return dial(ctx, ip, port)
		}}
}
