//go:build windows

package main

// "سپر VPN" (shield): programs that may reach the internet only through
// the VPN. While the tunnel is not connected (off, probing, retrying, the
// service just started, the user disconnected) Windows Firewall blocks
// all their outgoing traffic; while it is connected only their IPv6
// traffic is blocked (the tunnel carries IPv4 only, so IPv6 would leak).
// The list survives restarts in ProgramData; the rules stay in place if
// the service dies, so the failure is a closed door, not a leak.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const shieldRule = "PersianVPN Shield"

type shield struct {
	mu        sync.Mutex
	programs  []string
	applied   string // what the firewall holds now (key of programs + state)
	connected bool
}

var guard shield

func shieldFile() string {
	dir := os.Getenv("ProgramData")
	if dir == "" {
		dir = `C:\ProgramData`
	}
	return filepath.Join(dir, "PersianVPN", "shield.json")
}

// cleanPrograms keeps absolute .exe paths, once each.
func cleanPrograms(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range in {
		p = strings.TrimSpace(p)
		if !filepath.IsAbs(p) || !strings.EqualFold(filepath.Ext(p), ".exe") || strings.ContainsAny(p, "\"\r\n") {
			continue
		}
		k := strings.ToLower(filepath.Clean(p))
		if !seen[k] {
			seen[k] = true
			out = append(out, filepath.Clean(p))
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}

// shieldRules: the netsh "add rule" argument lists for one state.
func shieldRules(programs []string, connected bool) [][]string {
	var out [][]string
	for _, p := range programs {
		base := []string{"advfirewall", "firewall", "add", "rule", "name=" + shieldRule, "dir=out",
			"action=block", "enable=yes", "program=" + p}
		if connected {
			out = append(out, append(base, "remoteip=2000::/3"))
		} else {
			out = append(out, base)
		}
	}
	return out
}

func (g *shield) load() {
	data, err := os.ReadFile(shieldFile())
	if err != nil {
		return
	}
	var list []string
	if json.Unmarshal(data, &list) == nil {
		g.mu.Lock()
		g.programs = cleanPrograms(list)
		g.mu.Unlock()
	}
}

// set replaces the list (from the app) and applies it at once.
func (g *shield) set(programs []string) error {
	list := cleanPrograms(programs)
	if err := os.MkdirAll(filepath.Dir(shieldFile()), 0o755); err != nil {
		return err
	}
	data, _ := json.Marshal(list)
	if err := os.WriteFile(shieldFile(), data, 0o644); err != nil {
		return err
	}
	g.mu.Lock()
	g.programs = list
	g.mu.Unlock()
	g.apply()
	return nil
}

func (g *shield) list() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string{}, g.programs...)
}

// state follows the tunnel: called on every state change of the session.
func (g *shield) state(connected bool) {
	g.mu.Lock()
	changed := g.connected != connected
	g.connected = connected
	g.mu.Unlock()
	if changed {
		g.apply()
	}
}

func (g *shield) apply() {
	g.mu.Lock()
	defer g.mu.Unlock()
	key := strings.Join(g.programs, "|")
	if g.connected {
		key += "|connected"
	}
	if key == g.applied {
		return
	}
	hidden("netsh", "advfirewall", "firewall", "delete", "rule", "name="+shieldRule).Run()
	for _, args := range shieldRules(g.programs, g.connected) {
		hidden("netsh", args...).Run()
	}
	g.applied = key
}
