package pvcore

import (
	"strings"
	"testing"
)

func TestCdnVariants(t *testing.T) {
	two := strings.Replace(testServer, `"ips":["104.16.1.1"]`, `"ips":["104.16.1.1","172.67.1.1"]`, 1)
	cfg, err := xrayConfigWith(two, "vless-xhttp-cdn", "25g00001", "abc123", 1, func(p *Protocol) {
		p.variant = &cdnVariant{noECH: true, ip: 1}
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfg, "echConfigList") || !strings.Contains(cfg, `"address":"172.67.1.1"`) ||
		!strings.Contains(cfg, `"serverName":"cdn.example"`) {
		t.Error("variant without ECH on the second address:", cfg)
	}
	// the chosen variant is what the app's own config (and the pool) uses
	setCdnVariant("cdn.example", cdnVariant{noECH: true})
	defer setCdnVariant("cdn.example", cdnVariant{})
	cfg, _ = XrayConfig(two, "vless-xhttp-cdn", "25g00001", "abc123", 1)
	if strings.Contains(cfg, "echConfigList") || !strings.Contains(cfg, `"address":"104.16.1.1"`) {
		t.Error("chosen variant not used:", cfg)
	}
	cfg, _ = xrayConfigWith(two, "vless-xhttp-cdn", "25g00001", "abc123", 1, func(p *Protocol) {
		p.variant = &cdnVariant{noECH: true, addr: "188.114.96.3"}
	})
	if !strings.Contains(cfg, `"address":"188.114.96.3"`) || !strings.Contains(cfg, `"serverName":"cdn.example"`) {
		t.Error("clean address:", cfg)
	}
	cfg, _ = xrayConfigWith(two, "vless-xhttp-cdn", "25g00001", "abc123", 1, func(p *Protocol) {
		p.variant = &cdnVariant{noECH: true, addr: "@dns"}
	})
	if !strings.Contains(cfg, `"address":"cdn.example"`) {
		t.Error("by name:", cfg)
	}
	if (cdnVariant{noECH: true, addr: "@dns"}).String() != "SNI/dns" {
		t.Error("name of the dns way")
	}
	// one address: the index wraps instead of failing
	cfg, err = xrayConfigWith(testServer, "vless-xhttp-cdn", "25g00001", "abc123", 1, func(p *Protocol) {
		p.variant = &cdnVariant{ip: 1}
	})
	if err != nil || !strings.Contains(cfg, `"address":"104.16.1.1"`) {
		t.Error("one address:", err, cfg)
	}
}
