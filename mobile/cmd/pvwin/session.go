//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"persianvpn/mobile/pvcore"
)

// session keeps the tunnel up: it tries every protocol of every server,
// runs the working Xray ones together (Xray keeps moving new connections
// to the fastest) or AmneziaWG when that is clearly faster, watches the
// tunnel, and starts over when it stops working.
type session struct {
	mu        sync.Mutex
	state     string // off, probing, connected, retry
	protocols []string
	lastError string
	stop      chan struct{}
	done      chan struct{}
	// for the test screen
	servers    []json.RawMessage
	user, pass string
}

// events: the last lines of what the session did (probes, plan, checks),
// for the app's test screen
var (
	eventMu sync.Mutex
	events  []string
)

func note(format string, a ...any) {
	eventMu.Lock()
	defer eventMu.Unlock()
	events = append(events, time.Now().Format("2006-01-02 15:04:05")+" "+fmt.Sprintf(format, a...))
	if len(events) > 80 {
		events = events[len(events)-80:]
	}
}

func eventLog() []string {
	eventMu.Lock()
	defer eventMu.Unlock()
	return append([]string(nil), events...)
}

// creds: the servers and account of the current session (nil when off).
func (s *session) creds() ([]json.RawMessage, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.servers, s.user, s.pass
}

type choice struct {
	server json.RawMessage
	name   string
	kind   string
	ms     int
}

func (s *session) set(state string, protocols []string, err string) {
	s.mu.Lock()
	s.state, s.protocols, s.lastError = state, protocols, err
	s.mu.Unlock()
	guard.state(state == "connected")
}

func (s *session) status() (string, []string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == "" {
		return "off", nil, ""
	}
	return s.state, s.protocols, s.lastError
}

func (s *session) Disconnect() {
	s.mu.Lock()
	stop, done := s.stop, s.done
	s.stop, s.done = nil, nil
	s.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}
	pvcore.Stop()
	stopSstp()
	s.set("off", nil, "")
}

func (s *session) Connect(cfg *pvcore.SignedConfig, user, pass string, bypass []string) {
	s.Disconnect()
	stop, done := make(chan struct{}), make(chan struct{})
	s.mu.Lock()
	s.stop, s.done = stop, done
	s.servers, s.user, s.pass = cfg.LinuxServers, user, pass
	s.mu.Unlock()
	note("connect")
	s.set("probing", nil, "")
	go func() {
		defer close(done)
		s.run(cfg, user, pass, bypass, stop)
	}()
}

// The protocols tried first: they look like ordinary HTTPS (Reality) or
// carry their own disguise (AmneziaWG). Trying every protocol of every
// server from the same computer within seconds, on each connect, is itself
// a pattern a filter can see; the rest are tried only when these fail.
var stealthKinds = map[string]bool{"vless-reality-vision": true, "vless-xhttp-reality": true, "amneziawg": true}

// lastGood: the server that worked last (its name), tried first.
var lastGood string

// onlyKinds is the server entry with just the given protocols (nil: all).
func onlyKinds(sv json.RawMessage, kinds map[string]bool) json.RawMessage {
	if kinds == nil {
		return sv
	}
	var m map[string]any
	if json.Unmarshal(sv, &m) != nil {
		return sv
	}
	list, _ := m["protocols"].([]any)
	var keep []any
	for _, p := range list {
		if pm, ok := p.(map[string]any); ok && kinds[fmt.Sprint(pm["type"])] {
			keep = append(keep, pm)
		}
	}
	if len(keep) == 0 {
		return nil
	}
	m["protocols"] = keep
	out, err := json.Marshal(m)
	if err != nil {
		return sv
	}
	return out
}

func serverName(sv json.RawMessage) string {
	var meta struct {
		Name string `json:"name"`
	}
	json.Unmarshal(sv, &meta)
	return meta.Name
}

func probeOne(sv json.RawMessage, user, pass string) []choice {
	var res []choice
	var r map[string]any
	name := serverName(sv)
	raw := pvcore.Probe(string(sv), user, pass, 7000)
	note("probe %s: %s", name, raw)
	json.Unmarshal([]byte(raw), &r)
	for k, v := range r {
		if ms, ok := v.(float64); ok && ms >= 0 {
			res = append(res, choice{sv, name, k, int(ms)})
		}
	}
	return res
}

// probeAll: first the disguised protocols, one server at a time (the one
// that worked last first), stopping at the first server where one works;
// only when none does, every protocol of every server together.
func probeAll(servers []json.RawMessage, user, pass string, full bool) []choice {
	ordered := append([]json.RawMessage(nil), servers...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return serverName(ordered[i]) == lastGood && serverName(ordered[j]) != lastGood
	})
	for _, sv := range ordered {
		if full {
			break
		}
		if part := onlyKinds(sv, stealthKinds); part != nil {
			if res := probeOne(part, user, pass); len(res) > 0 {
				sort.Slice(res, func(i, j int) bool { return res[i].ms < res[j].ms })
				return res
			}
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var res []choice
	for _, sv := range servers {
		sv := sv
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := probeOne(sv, user, pass)
			mu.Lock()
			res = append(res, r...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(res, func(i, j int) bool { return res[i].ms < res[j].ms })
	return res
}

// fallbackKinds are carried only when nothing disguised works: their
// traffic is plain random bytes (Shadowsocks) or QUIC-like (Hysteria2),
// which filters pick out by statistics and then slow down the whole address.
var fallbackKinds = map[string]bool{"shadowsocks-2022": true, "hysteria2": true}

// attempts in order: each is a list of choices started together (one
// AmneziaWG server, or a pool of Xray protocols).
// noAwg: programs must bypass the tunnel, which only the Xray TUN can do.
func plan(all []choice, noAwg bool) [][]choice {
	var pool, weak, dns []choice
	var awg *choice
	for i, c := range all {
		if noAwg && c.kind == "amneziawg" {
			continue
		}
		switch c.kind {
		case "vless-dns":
			dns = append(dns, c)
		case "amneziawg":
			if awg == nil {
				awg = &all[i]
			}
		default:
			// one server at a time: traffic over two servers opens two User
			// Manager sessions, and a one-user account is refused on the second
			if fallbackKinds[c.kind] {
				if len(weak) == 0 || weak[0].name == c.name {
					weak = append(weak, c)
				}
			} else if len(pool) == 0 || pool[0].name == c.name {
				pool = append(pool, c)
			}
		}
	}
	// the faster of the two, counting how often each broke lately on this
	// computer (a tunnel that drops every few minutes is not fast)
	if len(pool) > 0 && awg != nil {
		note("plan: pool %dms×%d, amneziawg %dms×%d", pool[0].ms, 1+failCount("pool"), awg.ms, 1+failCount("amneziawg"))
	}
	var out [][]choice
	// AmneziaWG first (it holds up better here and carries its own disguise),
	// unless it broke down often lately on this computer
	poolFirst := awg == nil || (len(pool) > 0 && failCount("amneziawg") >= 3)
	if poolFirst {
		if len(pool) > 0 {
			out = append(out, pool)
		}
		if awg != nil {
			out = append(out, []choice{*awg})
		}
	} else {
		out = append(out, []choice{*awg})
		if len(pool) > 0 {
			out = append(out, pool)
		}
	}
	if len(weak) > 0 {
		out = append(out, weak) // Shadowsocks/Hysteria2 only when the above fail
	}
	if len(dns) > 0 {
		out = append(out, dns) // the DNS tunnel only when nothing else works
	}
	return out
}

// ---------------------------------------------------------------- stability

// failures of each kind ("pool" or "amneziawg") in the last hour make it
// count as slower: each one doubles, triples... its measured time
var (
	failMu sync.Mutex
	fails  = map[string][]time.Time{}
)

const failWindow = time.Hour

func kindOf(attempt []choice) string {
	if len(attempt) > 0 && attempt[0].kind == "amneziawg" {
		return "amneziawg"
	}
	return "pool"
}

func noteFailure(kind string) {
	failMu.Lock()
	defer failMu.Unlock()
	fails[kind] = append(recent(fails[kind]), time.Now())
}

func recent(ts []time.Time) []time.Time {
	var out []time.Time
	for _, t := range ts {
		if time.Since(t) < failWindow {
			out = append(out, t)
		}
	}
	return out
}

func failCount(kind string) int {
	failMu.Lock()
	defer failMu.Unlock()
	return len(recent(fails[kind]))
}

func score(ms int, kind string) int {
	return ms * (1 + failCount(kind))
}

func start(chosen []choice, user, pass string, bypass []string) ([]string, error) {
	var names []string
	for _, c := range chosen {
		names = append(names, fmt.Sprintf("%s/%s %dms", c.name, c.kind, c.ms))
	}
	if chosen[0].kind == "amneziawg" {
		return names, pvcore.StartAwgWindows(string(chosen[0].server), user, pass)
	}
	var list []map[string]any
	for _, c := range chosen {
		list = append(list, map[string]any{"server": c.server, "kind": c.kind})
	}
	cj, _ := json.Marshal(list)
	return names, pvcore.StartWindows(string(cj), user, pass, bypass)
}

// sstpCheck: through Windows' own routes, which the SSTP connection owns.
func sstpCheck() int {
	c := &http.Client{Timeout: 10 * time.Second}
	t := time.Now()
	r, err := c.Get(pvcore.ProbeURL)
	if err != nil {
		return -1
	}
	r.Body.Close()
	return int(time.Since(t).Milliseconds())
}

func (s *session) run(cfg *pvcore.SignedConfig, user, pass string, bypass []string, stop chan struct{}) {
	servers := cfg.LinuxServers
	wait := func(d time.Duration) bool {
		select {
		case <-stop:
			return false
		case <-time.After(d):
			return true
		}
	}
	backoff := 5 * time.Second
	// on SSTP because no Linux protocol worked: Linux is tried again every
	// returnGap. The probes may go out through the SSTP tunnel (Windows'
	// client takes the default route) and pass where the direct way does
	// not; a return that ends on SSTP again doubles the gap.
	returnGap := 5 * time.Minute
	triedReturn := false
	// after a breakdown every protocol is tried, so the fallbacks are there too
	fullNext := false
	for {
		select {
		case <-stop:
			return
		default:
		}
		var names []string
		lastErr := "no protocol works"
		up := false
		kind := ""
		attempts := plan(probeAll(servers, user, pass, fullNext), len(bypass) > 0)
		if !fullNext {
			// the quick probe tries only some protocols: when what it found
			// cannot be used here, every protocol of every server after it
			attempts = append(attempts, [][]choice{nil}...)
		}
		for _, attempt := range attempts {
			if attempt == nil {
				if up {
					break
				}
				for _, a := range plan(probeAll(servers, user, pass, true), len(bypass) > 0) {
					if names2, err := start(a, user, pass, bypass); err == nil {
						names, up, kind = names2, true, kindOf(a)
						lastGood = a[0].name
						note("connected: %v", names)
						break
					} else {
						lastErr = err.Error()
						note("start failed: %s", lastErr)
					}
				}
				break
			}
			select {
			case <-stop:
				return
			default:
			}
			var err error
			if names, err = start(attempt, user, pass, bypass); err == nil {
				up, kind = true, kindOf(attempt)
				lastGood = attempt[0].name
				note("connected: %v", names)
				break
			}
			lastErr = err.Error()
			note("start failed: %s", lastErr)
		}
		fullNext = !up
		sstp := false
		if !up && len(cfg.Servers) > 0 {
			// the last resort: Windows' own SSTP client to the MikroTik
			if name, err := startSstp(cfg, user, pass); err == nil {
				names, up, sstp = []string{name}, true, true
			} else {
				lastErr = err.Error()
			}
		}
		if !up {
			s.set("retry", nil, lastErr)
			if !wait(backoff) {
				return
			}
			if backoff < time.Minute {
				backoff *= 2
			}
			continue
		}
		backoff = 5 * time.Second
		s.set("connected", names, "")
		if sstp && triedReturn && returnGap < time.Hour {
			returnGap *= 2
		}
		if !sstp {
			returnGap, triedReturn = 5*time.Minute, false
		}
		onSince := time.Now()
		failures := 0
		back := false
		for failures < 2 {
			if !wait(25 * time.Second) {
				return
			}
			if sstp && len(servers) > 0 && time.Since(onSince) >= returnGap {
				onSince = time.Now()
				for _, c := range probeAll(servers, user, pass, false) {
					if c.kind != "vless-dns" {
						back = true
						break
					}
				}
				if back {
					note("Linux servers work again, leaving SSTP")
					triedReturn = true
					break
				}
			}
			ok := false
			if sstp {
				ok = sstpCheck() >= 0
			} else {
				ok = pvcore.Check(10000) >= 0
			}
			if !ok {
				failures++
				note("check failed (%d)", failures)
				noteFailure(kind) // every failed check counts against that kind
			} else {
				failures = 0
			}
		}
		pvcore.Stop()
		stopSstp()
		if back {
			continue
		}
		note("tunnel stopped working, starting over")
		fullNext = true
		s.set("retry", nil, "tunnel stopped working")
	}
}
