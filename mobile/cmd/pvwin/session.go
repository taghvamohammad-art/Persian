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

func (s *session) Connect(cfg *pvcore.SignedConfig, user, pass string) {
	s.Disconnect()
	stop, done := make(chan struct{}), make(chan struct{})
	s.mu.Lock()
	s.stop, s.done = stop, done
	s.mu.Unlock()
	s.set("probing", nil, "")
	go func() {
		defer close(done)
		s.run(cfg, user, pass, stop)
	}()
}

func probeAll(servers []json.RawMessage, user, pass string) []choice {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var res []choice
	for _, sv := range servers {
		sv := sv
		wg.Add(1)
		go func() {
			defer wg.Done()
			var meta struct {
				Name string `json:"name"`
			}
			json.Unmarshal(sv, &meta)
			var r map[string]any
			json.Unmarshal([]byte(pvcore.Probe(string(sv), user, pass, 7000)), &r)
			for k, v := range r {
				if ms, ok := v.(float64); ok && ms >= 0 {
					mu.Lock()
					res = append(res, choice{sv, meta.Name, k, int(ms)})
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	sort.Slice(res, func(i, j int) bool { return res[i].ms < res[j].ms })
	return res
}

// attempts in order: each is a list of choices started together (one
// AmneziaWG server, or a pool of Xray protocols).
func plan(all []choice) [][]choice {
	var pool, dns []choice
	var awg *choice
	for i, c := range all {
		switch c.kind {
		case "vless-dns":
			dns = append(dns, c)
		case "amneziawg":
			if awg == nil {
				awg = &all[i]
			}
		default:
			pool = append(pool, c)
		}
	}
	var out [][]choice
	if len(pool) > 0 && (awg == nil || pool[0].ms <= awg.ms*3/2) {
		out = append(out, pool)
		if awg != nil {
			out = append(out, []choice{*awg})
		}
	} else {
		if awg != nil {
			out = append(out, []choice{*awg})
		}
		if len(pool) > 0 {
			out = append(out, pool)
		}
	}
	if len(dns) > 0 {
		out = append(out, dns) // the DNS tunnel only when nothing else works
	}
	return out
}

func start(chosen []choice, user, pass string) ([]string, error) {
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
	return names, pvcore.StartWindows(string(cj), user, pass)
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

func (s *session) run(cfg *pvcore.SignedConfig, user, pass string, stop chan struct{}) {
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
	for {
		select {
		case <-stop:
			return
		default:
		}
		var names []string
		lastErr := "no protocol works"
		up := false
		for _, attempt := range plan(probeAll(servers, user, pass)) {
			select {
			case <-stop:
				return
			default:
			}
			var err error
			if names, err = start(attempt, user, pass); err == nil {
				up = true
				break
			}
			lastErr = err.Error()
		}
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
		failures := 0
		for failures < 2 {
			if !wait(25 * time.Second) {
				return
			}
			ok := false
			if sstp {
				ok = sstpCheck() >= 0
			} else {
				ok = pvcore.Check(10000) >= 0
			}
			if !ok {
				failures++
			} else {
				failures = 0
			}
		}
		pvcore.Stop()
		stopSstp()
		s.set("retry", nil, "tunnel stopped working")
	}
}
