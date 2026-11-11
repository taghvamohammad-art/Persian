package pvcore

import (
	"encoding/base64"
	"fmt"
	"time"

	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

// echConfig is Cloudflare's current ECH key for the CDN host, asked from
// several DNS servers at once (some may be blocked); the copy saved in the
// app config when the server was set up is the last resort.
func echConfig(p *Protocol) (string, error) {
	if len(p.ECHDNS) == 0 {
		if p.ECHConfig != "" {
			return p.ECHConfig, nil
		}
		return "", fmt.Errorf("ech: no config")
	}
	found := make(chan []byte, len(p.ECHDNS))
	for _, server := range p.ECHDNS {
		server := server
		go func() {
			b, err := xtls.QueryRecord(p.Host, server, nil)
			if err != nil || len(b) == 0 {
				found <- nil
				return
			}
			found <- b
		}()
	}
	deadline := time.After(5 * time.Second)
	for range p.ECHDNS {
		select {
		case b := <-found:
			if b != nil {
				return base64.StdEncoding.EncodeToString(b), nil
			}
		case <-deadline:
			goto fallback
		}
	}
fallback:
	if p.ECHConfig != "" {
		return p.ECHConfig, nil
	}
	return "", fmt.Errorf("ech: no DNS server answered")
}
