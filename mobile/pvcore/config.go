package pvcore

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
)

// Protocol is one entry of a Linux server in the app config (linux.server_entry).
type Protocol struct {
	Type      string `json:"type"`
	Port      int    `json:"port"`
	SNI       string `json:"sni"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
	Path      string `json:"path"`
	PinSha256 string `json:"pin_sha256"`
	Method    string `json:"method"`
	ServerKey string `json:"server_key"`
	Jc        int    `json:"jc"`
	Jmin      int    `json:"jmin"`
	Jmax      int    `json:"jmax"`
	S1        int    `json:"s1"`
	S2        int    `json:"s2"`
	H1        int64  `json:"h1"`
	H2        int64  `json:"h2"`
	H3        int64  `json:"h3"`
	H4        int64  `json:"h4"`
	// CDN (vless-xhttp-cdn) and DNS tunnel (vless-dns)
	Host       string   `json:"host"`
	Encryption string   `json:"encryption"`
	IPs        []string `json:"ips"`
	ECHConfig  string   `json:"ech_config"`
	ECHDNS     []string `json:"ech_dns"`
	Domain     string   `json:"domain"`
	Resolvers  []string `json:"resolvers"`
	Plain      bool     `json:"plain"` // tests only: straight to the server, no TLS/ECH, no public resolvers
}

// Server is a Linux server of the app config.
type Server struct {
	Name      string     `json:"name"`
	Host      string     `json:"host"`
	Protocols []Protocol `json:"protocols"`
}

// XrayTypes are the protocols the Xray engine serves, in order of preference
// when they are equally fast.
var XrayTypes = []string{"vless-reality-vision", "vless-xhttp-reality", "hysteria2", "shadowsocks-2022",
	"vless-xhttp-cdn", "vless-dns"}

var (
	resolverMu sync.Mutex
	resolvers  []string
)

// SetResolvers gives the phone's own DNS servers (comma separated IPs) to the
// DNS tunnel; they are tried before the public ones, since in a shutdown
// only the operator's resolvers may still reach the internet.
func SetResolvers(csv string) {
	var out []string
	for _, a := range strings.Split(csv, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if ip := net.ParseIP(a); ip != nil {
			a = "udp://" + net.JoinHostPort(ip.String(), "53")
		} else if !strings.Contains(a, "://") {
			a = "udp://" + a
		}
		out = append(out, a)
	}
	resolverMu.Lock()
	resolvers = out
	resolverMu.Unlock()
}

func tunnelResolvers(p *Protocol) []string {
	resolverMu.Lock()
	out := append([]string{}, resolvers...)
	resolverMu.Unlock()
	seen := map[string]bool{}
	for _, r := range out {
		seen[r] = true
	}
	for _, r := range p.Resolvers {
		if !seen[r] {
			out = append(out, r)
		}
	}
	return out
}

func parseServer(serverJSON string) (*Server, error) {
	var s Server
	if err := json.Unmarshal([]byte(serverJSON), &s); err != nil {
		return nil, fmt.Errorf("server config: %w", err)
	}
	if s.Host == "" {
		return nil, fmt.Errorf("server config: no host")
	}
	return &s, nil
}

func (s *Server) protocol(kind string) (*Protocol, error) {
	for i := range s.Protocols {
		if s.Protocols[i].Type == kind {
			return &s.Protocols[i], nil
		}
	}
	return nil, fmt.Errorf("server %s has no %s", s.Host, kind)
}

func reality(p *Protocol) map[string]any {
	return map[string]any{"serverName": p.SNI, "publicKey": p.PublicKey, "shortId": p.ShortID, "fingerprint": "chrome"}
}

func outbound(s *Server, p *Protocol, user, pass string) (map[string]any, error) {
	switch p.Type {
	case "vless-reality-vision":
		return map[string]any{"tag": "proxy", "protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{"address": s.Host, "port": p.Port,
				"users": []any{map[string]any{"id": VlessUUID(user, pass), "encryption": "none", "flow": "xtls-rprx-vision"}}}}},
			"streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": reality(p)}}, nil
	case "vless-xhttp-reality":
		return map[string]any{"tag": "proxy", "protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{"address": s.Host, "port": p.Port,
				"users": []any{map[string]any{"id": VlessUUID(user, pass), "encryption": "none"}}}}},
			"streamSettings": map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": p.Path},
				"security": "reality", "realitySettings": reality(p)}}, nil
	case "hysteria2":
		return map[string]any{"tag": "proxy", "protocol": "hysteria",
			"settings": map[string]any{"version": 2, "address": s.Host, "port": p.Port},
			"streamSettings": map[string]any{"network": "hysteria",
				"hysteriaSettings": map[string]any{"version": 2, "auth": Hy2Auth(user, pass)},
				"security":         "tls",
				"tlsSettings": map[string]any{"serverName": "pv", "alpn": []string{"h3"},
					"pinnedPeerCertSha256": p.PinSha256}}}, nil
	case "shadowsocks-2022":
		return map[string]any{"tag": "proxy", "protocol": "shadowsocks",
			"settings": map[string]any{"servers": []any{map[string]any{"address": s.Host, "port": p.Port,
				"method": p.Method, "password": p.ServerKey + ":" + SSKey(user, pass)}}}}, nil
	case "vless-xhttp-cdn":
		addr, port := p.Host, p.Port
		if len(p.IPs) > 0 {
			addr = p.IPs[0] // Cloudflare's address: no DNS lookup that could be tampered with
		}
		stream := map[string]any{"network": "xhttp",
			"xhttpSettings": map[string]any{"path": p.Path, "host": p.Host, "mode": "packet-up"}}
		if p.Plain {
			addr = s.Host
		} else {
			ech, err := echConfig(p)
			if err != nil {
				return nil, err
			}
			stream["security"] = "tls"
			stream["tlsSettings"] = map[string]any{"serverName": p.Host, "fingerprint": "chrome",
				"alpn": []string{"h2", "http/1.1"}, "echConfigList": ech}
		}
		return map[string]any{"tag": "proxy", "protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{"address": addr, "port": port,
				"users": []any{map[string]any{"id": VlessUUID(user, pass), "encryption": p.Encryption}}}}},
			"streamSettings": stream}, nil
	case "vless-dns":
		rs := tunnelResolvers(p)
		if p.Plain {
			rs = []string{"udp://" + net.JoinHostPort(s.Host, "53")}
		}
		if len(rs) == 0 {
			return nil, fmt.Errorf("dns tunnel: no resolvers")
		}
		return map[string]any{"tag": "proxy", "protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{"address": "8.8.8.8", "port": 53,
				"users": []any{map[string]any{"id": VlessUUID(user, pass), "encryption": p.Encryption}}}}},
			"streamSettings": map[string]any{"network": "mkcp",
				"kcpSettings": map[string]any{"mtu": 130, "tti": 200},
				"finalmask": map[string]any{"udp": []any{map[string]any{"type": "xdns", "settings": map[string]any{
					"domains":   []any{map[string]any{"names": []string{p.Domain}, "edns0": 1232}},
					"resolvers": []any{map[string]any{"addrs": rs}}}}}}}}, nil
	}
	return nil, fmt.Errorf("not an Xray protocol: %s", p.Type)
}

// TunnelDNS: the phone's DNS queries (UDP to port 53) are answered by
// Xray itself, over TCP through the tunnel. UDP through some protocols can
// stall while TCP still works; then every app would look "connected but
// no internet" although the health check (TCP) passes. Only IPv4 answers:
// the tunnel carries no IPv6, and AAAA answers make apps wait for a dead
// path first.
var TunnelDNS = map[string]any{
	"servers":       []any{"tcp://1.1.1.1:53", "tcp://8.8.8.8:53"},
	"queryStrategy": "UseIPv4",
}

func baseConfig(socksPort int, outs []any, rules []any) map[string]any {
	return map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"dns": TunnelDNS,
		// bytes to and from the apps, for the watchdog (TunnelBytes)
		"stats":  map[string]any{},
		"policy": map[string]any{"system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true}},
		"inbounds": []any{map[string]any{"tag": "socks", "listen": "127.0.0.1", "port": socksPort,
			"protocol": "socks", "settings": map[string]any{"udp": true, "auth": "noauth"},
			"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}}},
		"outbounds": append(outs, map[string]any{"tag": "direct", "protocol": "freedom"},
			map[string]any{"tag": "dns-out", "protocol": "dns"},
			map[string]any{"tag": "block", "protocol": "blackhole"}),
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": append([]any{
			map[string]any{"inboundTag": []string{"socks", "tun"}, "network": "udp", "port": "53",
				"outboundTag": "dns-out"},
			// QUIC (HTTP/3) over the tunnel's UDP stalls easily; refused, the
			// apps use TCP right away (the usual VPN-client setting)
			map[string]any{"inboundTag": []string{"socks", "tun"}, "network": "udp", "port": "443",
				"outboundTag": "block"},
			map[string]any{"ip": []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"},
				"outboundTag": "direct"}}, rules...)},
	}
}

// XrayConfig is the client config for one protocol of a server, with a SOCKS
// inbound on 127.0.0.1:socksPort that the TUN is forwarded to.
func XrayConfig(serverJSON, kind, user, pass string, socksPort int) (string, error) {
	s, err := parseServer(serverJSON)
	if err != nil {
		return "", err
	}
	p, err := s.protocol(kind)
	if err != nil {
		return "", err
	}
	out, err := outbound(s, p, user, pass)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(baseConfig(socksPort, []any{out}, nil))
	return string(b), err
}

type poolChoice struct {
	Server json.RawMessage `json:"server"`
	Kind   string          `json:"kind"`
}

// PoolConfig: every choice as its own outbound, the fastest working one
// picked continuously (observatory + leastPing balancer); the first choice
// is used until the first measurement is in.
func PoolConfig(choicesJSON, user, pass string, socksPort int) (string, error) {
	var choices []poolChoice
	if err := json.Unmarshal([]byte(choicesJSON), &choices); err != nil {
		return "", fmt.Errorf("pool: %w", err)
	}
	var outs []any
	var errs []string
	for _, c := range choices {
		s, err := parseServer(string(c.Server))
		if err == nil {
			var p *Protocol
			if p, err = s.protocol(c.Kind); err == nil {
				var out map[string]any
				if out, err = outbound(s, p, user, pass); err == nil {
					out["tag"] = fmt.Sprintf("p-%d", len(outs))
					outs = append(outs, out)
					continue
				}
			}
		}
		errs = append(errs, c.Kind+": "+err.Error())
	}
	if len(outs) == 0 {
		return "", fmt.Errorf("pool: nothing usable (%s)", strings.Join(errs, "; "))
	}
	cfg := baseConfig(socksPort, outs, []any{map[string]any{"network": "tcp,udp", "balancerTag": "best"}})
	cfg["observatory"] = map[string]any{"subjectSelector": []string{"p-"}, "probeUrl": ProbeURL,
		"probeInterval": "1m", "enableConcurrency": true}
	cfg["routing"].(map[string]any)["balancers"] = []any{map[string]any{"tag": "best", "selector": []string{"p-"},
		"strategy": map[string]any{"type": "leastPing"}, "fallbackTag": "p-0"}}
	b, err := json.Marshal(cfg)
	return string(b), err
}

func b64ToHex(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("bad key")
	}
	return hex.EncodeToString(raw), nil
}

// AwgUAPI is the AmneziaWG device configuration (UAPI text) for a user.
func AwgUAPI(serverJSON, user, pass string) (string, error) {
	s, err := parseServer(serverJSON)
	if err != nil {
		return "", err
	}
	p, err := s.protocol("amneziawg")
	if err != nil {
		return "", err
	}
	priv := hex.EncodeToString(awgPrivateRaw(user, pass))
	pub, err := b64ToHex(p.PublicKey)
	if err != nil {
		return "", fmt.Errorf("server awg key: %w", err)
	}
	host := s.Host
	if net.ParseIP(host) == nil {
		addrs, err := net.LookupIP(host)
		if err != nil || len(addrs) == 0 {
			return "", fmt.Errorf("resolve %s: %v", host, err)
		}
		host = addrs[0].String()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	fmt.Fprintf(&b, "jc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d\nh1=%d\nh2=%d\nh3=%d\nh4=%d\n",
		p.Jc, p.Jmin, p.Jmax, p.S1, p.S2, p.H1, p.H2, p.H3, p.H4)
	fmt.Fprintf(&b, "replace_peers=true\npublic_key=%s\nendpoint=%s\n", pub, net.JoinHostPort(host, fmt.Sprint(p.Port)))
	b.WriteString("persistent_keepalive_interval=25\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\n")
	return b.String(), nil
}

// Types lists the protocol types a server offers (JSON array), for the app.
func Types(serverJSON string) (string, error) {
	s, err := parseServer(serverJSON)
	if err != nil {
		return "", err
	}
	var out []string
	for _, p := range s.Protocols {
		out = append(out, p.Type)
	}
	b, _ := json.Marshal(out)
	return string(b), nil
}
