package pvcore

import (
	"encoding/json"
	"fmt"
)

// Windows: Xray's own TUN inbound (Wintun) carries the whole system; it
// adds the routes itself, binds its own connections to the real network
// interface, and its WFP filters keep DNS and IPv6 from leaking past the
// tunnel. A SOCKS inbound stays for the health check.

const WinTunName = "Persian VPN"

// WindowsConfig is PoolConfig plus the TUN inbound.
func WindowsConfig(choicesJSON, user, pass string, socksPort int) (string, error) {
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
	b, err := json.Marshal(cfg)
	return string(b), err
}

// StartWindows runs the pool with the TUN; Check works on it as on Android.
func StartWindows(choicesJSON, user, pass string) error {
	mu.Lock()
	defer mu.Unlock()
	stopLocked()
	port, err := freePort()
	if err != nil {
		return err
	}
	cfg, err := WindowsConfig(choicesJSON, user, pass, port)
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
