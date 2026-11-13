package pvcore

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Windows: Xray's own TUN inbound (Wintun) carries the whole system; it
// adds the routes itself, binds its own connections to the real network
// interface, and its WFP filters keep DNS and IPv6 from leaking past the
// tunnel. A SOCKS inbound stays for the health check.

const WinTunName = "Persian VPN"

// WindowsConfig is PoolConfig plus the TUN inbound.
// WindowsConfig: bypass lists programs (file names such as "firefox.exe")
// whose connections leave directly instead of through the tunnel.
func WindowsConfig(choicesJSON, user, pass string, socksPort int, bypass []string) (string, error) {
	base, err := PoolConfig(choicesJSON, user, pass, socksPort)
	if err != nil {
		return "", err
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(base), &cfg); err != nil {
		return "", err
	}
	tun := map[string]any{"tag": "tun", "port": 0, "protocol": "tun",
		"settings": map[string]any{
			"name": WinTunName, "desc": WinTunName, "mtu": 1500,
			"gateway":                []string{"172.19.0.1/30"},
			"dns":                    []string{"1.1.1.1", "8.8.8.8"},
			"autoSystemRoutingTable": []string{"0.0.0.0/0"},
			"autoSystemWfpBlockLeak": []string{"dns", "misconfigtun"},
		},
		"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}}
	cfg["inbounds"] = append(cfg["inbounds"].([]any), tun)
	if names := bypassNames(bypass); len(names) > 0 {
		routing := cfg["routing"].(map[string]any)
		rules := routing["rules"].([]any)
		rule := map[string]any{"inboundTag": []string{"tun"}, "process": names, "outboundTag": "direct"}
		routing["rules"] = append([]any{rule}, rules...)
	}
	b, err := json.Marshal(cfg)
	return string(b), err
}

// StartWindows runs the pool with the TUN; Check works on it as on Android.
func StartWindows(choicesJSON, user, pass string, bypass []string) error {
	mu.Lock()
	defer mu.Unlock()
	stopLocked()
	port, err := freePort()
	if err != nil {
		return err
	}
	cfg, err := WindowsConfig(choicesJSON, user, pass, port, bypass)
	if err != nil {
		return err
	}
	inst, err := startXrayInstance(cfg)
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	xrayInst = inst
	running = "pool"
	socksAt = port
	return nil
}

// bypassNames keeps plain program file names (no paths, no rule syntax).
func bypassNames(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range in {
		n = strings.TrimSpace(n)
		if i := strings.LastIndexAny(n, `/\`); i >= 0 {
			n = n[i+1:]
		}
		if n == "" || strings.ContainsAny(n, `:*?"<>|`) || seen[strings.ToLower(n)] || len(out) >= 100 {
			continue
		}
		seen[strings.ToLower(n)] = true
		out = append(out, n)
	}
	return out
}
