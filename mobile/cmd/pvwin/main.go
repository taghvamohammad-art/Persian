// pvwin is the Windows engine of Persian VPN, run (as administrator) by the
// Windows app. It tries every protocol of every Linux server, runs the
// working Xray ones together through a Wintun adapter (Xray keeps moving
// new connections to the fastest), watches the tunnel and starts over
// when it stops working. It stops when its standard input closes.
//
//	pvwin -servers servers.json -user NAME      (password in PV_PASS)
//
// Events on standard output, one JSON object per line:
//
//	{"event":"probing"} {"event":"connected","protocols":[...]}
//	{"event":"retry","error":"..."} {"event":"stopped"}
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"persianvpn/mobile/pvcore"
)

var out = json.NewEncoder(os.Stdout)
var outMu sync.Mutex

func emit(ev map[string]any) {
	outMu.Lock()
	defer outMu.Unlock()
	out.Encode(ev)
}

type choice struct {
	server json.RawMessage
	name   string
	kind   string
	ms     int
}

func probeAll(servers []json.RawMessage, user, pass string) []choice {
	var mu sync.Mutex
	var wg sync.WaitGroup
	var res []choice
	for _, s := range servers {
		s := s
		wg.Add(1)
		go func() {
			defer wg.Done()
			var meta struct {
				Name string `json:"name"`
			}
			json.Unmarshal(s, &meta)
			var r map[string]any
			json.Unmarshal([]byte(pvcore.Probe(string(s), user, pass, 7000)), &r)
			for k, v := range r {
				ms, ok := v.(float64)
				if !ok || ms < 0 || k == "amneziawg" {
					continue
				}
				mu.Lock()
				res = append(res, choice{s, meta.Name, k, int(ms)})
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	sort.Slice(res, func(i, j int) bool { return res[i].ms < res[j].ms })
	return res
}

// plan: every working protocol except the DNS tunnel; the tunnel alone
// only when nothing else works.
func plan(all []choice) []choice {
	var pool, dns []choice
	for _, c := range all {
		if c.kind == "vless-dns" {
			dns = append(dns, c)
		} else {
			pool = append(pool, c)
		}
	}
	if len(pool) > 0 {
		return pool
	}
	return dns
}

func main() {
	serversFile := flag.String("servers", "", "JSON array of the config's linux_servers")
	user := flag.String("user", "", "username")
	flag.Parse()
	pass := os.Getenv("PV_PASS")
	raw, err := os.ReadFile(*serversFile)
	if err != nil {
		emit(map[string]any{"event": "error", "error": err.Error()})
		os.Exit(2)
	}
	var servers []json.RawMessage
	if err := json.Unmarshal(raw, &servers); err != nil || len(servers) == 0 {
		emit(map[string]any{"event": "error", "error": "no servers"})
		os.Exit(2)
	}

	stop := make(chan struct{})
	go func() { // the app closes our input to stop us
		bufio.NewReader(os.Stdin).ReadString(0)
		close(stop)
	}()
	defer func() {
		pvcore.Stop()
		emit(map[string]any{"event": "stopped"})
	}()

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
		emit(map[string]any{"event": "probing"})
		chosen := plan(probeAll(servers, *user, pass))
		if len(chosen) == 0 {
			emit(map[string]any{"event": "retry", "error": "no protocol works"})
			if !wait(backoff) {
				return
			}
			if backoff < time.Minute {
				backoff *= 2
			}
			continue
		}
		var list []map[string]any
		var names []string
		for _, c := range chosen {
			list = append(list, map[string]any{"server": c.server, "kind": c.kind})
			names = append(names, fmt.Sprintf("%s/%s %dms", c.name, c.kind, c.ms))
		}
		cj, _ := json.Marshal(list)
		if err := pvcore.StartWindows(string(cj), *user, pass); err != nil {
			emit(map[string]any{"event": "retry", "error": err.Error()})
			if !wait(backoff) {
				return
			}
			continue
		}
		backoff = 5 * time.Second
		emit(map[string]any{"event": "connected", "protocols": names})
		failures := 0
		for failures < 2 {
			if !wait(25 * time.Second) {
				return
			}
			if pvcore.Check(10000) < 0 {
				failures++
			} else {
				failures = 0
			}
		}
		pvcore.Stop()
		emit(map[string]any{"event": "retry", "error": "tunnel stopped working"})
	}
}
