package pvcore

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// The CDN route can fail on a network for reasons of its own: ECH (its
// outer name is the same for every Cloudflare site and some networks slow
// or drop it), or one Cloudflare address being blocked. The probe tries a
// few ways at once and the one that works is used from then on (for this
// run of the app); the first is the default.
type cdnVariant struct {
	noECH bool
	ip    int // index into the protocol's Cloudflare addresses
}

func (v cdnVariant) String() string {
	ech := "ECH"
	if v.noECH {
		ech = "SNI"
	}
	return fmt.Sprintf("%s/ip%d", ech, v.ip+1)
}

var cdnVariants = []cdnVariant{{false, 0}, {true, 0}, {false, 1}, {true, 1}}

var (
	cdnMu     sync.Mutex
	cdnChosen = map[string]cdnVariant{}
)

func cdnVariantOf(host string) cdnVariant {
	cdnMu.Lock()
	defer cdnMu.Unlock()
	return cdnChosen[host]
}

func setCdnVariant(host string, v cdnVariant) {
	cdnMu.Lock()
	cdnChosen[host] = v
	cdnMu.Unlock()
}

// probeCdn tries the variants at once (each its own Xray, so they do not
// meet the chosen-variant setting of the others) and keeps the fastest
// that works, the default when several do.
func probeCdn(serverJSON, user, pass string, timeout time.Duration) (int, error) {
	s, err := parseServer(serverJSON)
	if err != nil {
		return -1, err
	}
	p, err := s.protocol("vless-xhttp-cdn")
	if err != nil {
		return -1, err
	}
	vs := cdnVariants
	if len(p.IPs) < 2 {
		vs = vs[:2]
	}
	if p.Plain {
		vs = vs[:1]
	}
	type res struct {
		v   cdnVariant
		ms  int
		err error
	}
	out := make(chan res, len(vs))
	for _, v := range vs {
		v := v
		go func() {
			ms, err := probeXrayWith(serverJSON, "vless-xhttp-cdn", user, pass, timeout, func(q *Protocol) { q.variant = &v })
			out <- res{v, ms, err}
		}()
	}
	best := res{ms: -1}
	var errs []string
	for range vs {
		r := <-out
		if r.err != nil {
			errs = append(errs, fmt.Sprintf("%v: %v", r.v, shortErr(r.err)))
			continue
		}
		if best.ms < 0 || r.v == vs[0] || (best.v != vs[0] && r.ms < best.ms) {
			best = r
		}
	}
	if best.ms < 0 {
		return -1, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	setCdnVariant(p.Host, best.v)
	return best.ms, nil
}

func shortErr(err error) string {
	e := err.Error()
	switch {
	case strings.Contains(e, "deadline exceeded") || strings.Contains(e, "Timeout"):
		return "timeout"
	case len(e) > 60:
		return e[:60]
	}
	return e
}
