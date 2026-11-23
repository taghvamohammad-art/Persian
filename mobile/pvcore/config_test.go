package pvcore

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf/serial"
)

const testServer = `{"name":"t","host":"1.2.3.4","protocols":[
 {"type":"vless-reality-vision","port":443,"sni":"www.microsoft.com","public_key":"PK","short_id":"ab12"},
 {"type":"vless-xhttp-reality","port":8443,"sni":"www.microsoft.com","path":"/x","public_key":"PK","short_id":"ab12"},
 {"type":"hysteria2","port":443,"pin_sha256":"ff00"},
 {"type":"shadowsocks-2022","port":20001,"method":"2022-blake3-aes-128-gcm","server_key":"c2VydmVya2V5c2VydmVya2V5"},
 {"type":"vless-xhttp-cdn","host":"cdn.example","port":443,"path":"/c","encryption":"mlkem768x25519plus.native.0rtt.KEY","ips":["104.16.1.1"],"ech_config":"AEX+DQBB"},
 {"type":"vless-dns","domain":"d.example","encryption":"mlkem768x25519plus.native.0rtt.KEY","resolvers":["udp://8.8.8.8:53"]},
 {"type":"amneziawg","port":30001,"public_key":"iEOjwrLAGYLR3gCJd8hsCtL+1cqeTz1lO1EWQXlQYlw=","jc":4,"jmin":40,"jmax":70,"s1":20,"s2":30,"h1":11,"h2":22,"h3":33,"h4":44}]}`

func TestXrayConfigs(t *testing.T) {
	for _, kind := range XrayTypes {
		cfg, err := XrayConfig(testServer, kind, "25g00001", "abc123", 10808)
		if err != nil {
			t.Fatal(kind, err)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(cfg), &m); err != nil {
			t.Fatal(kind, err)
		}
		if !strings.Contains(cfg, `"port":10808`) {
			t.Error(kind, "no socks inbound")
		}
	}
	cfg, _ := XrayConfig(testServer, "shadowsocks-2022", "25g00001", "abc123", 1)
	if !strings.Contains(cfg, "c2VydmVya2V5c2VydmVya2V5:kIPsqZJOWdJYPjSbZ7zSrQ==") {
		t.Error("ss password", cfg)
	}
	SetResolvers("10.0.0.1, 8.8.8.8:53,")
	cfg, _ = XrayConfig(testServer, "vless-dns", "25g00001", "abc123", 1)
	if !strings.Contains(cfg, `"addrs":["udp://10.0.0.1:53","udp://8.8.8.8:53"]`) || !strings.Contains(cfg, `"edns0":1232`) {
		t.Error("dns tunnel resolvers", cfg)
	}
	cfg, _ = XrayConfig(testServer, "vless-xhttp-cdn", "25g00001", "abc123", 1)
	if !strings.Contains(cfg, `"address":"104.16.1.1"`) || !strings.Contains(cfg, `"echConfigList":"AEX+DQBB"`) {
		t.Error("cdn", cfg)
	}
	if _, err := XrayConfig(testServer, "nope", "a", "b", 1); err == nil {
		t.Error("unknown protocol accepted")
	}
}

func TestPoolConfig(t *testing.T) {
	choices := `[{"server":` + testServer + `,"kind":"hysteria2"},{"server":` + testServer + `,"kind":"shadowsocks-2022"},` +
		`{"server":` + testServer + `,"kind":"nope"}]`
	cfg, err := PoolConfig(choices, "25g00001", "abc123", 10808)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"tag":"p-0"`, `"tag":"p-1"`, `"balancerTag":"best"`, `"leastPing"`, `"fallbackTag":"p-0"`} {
		if !strings.Contains(cfg, want) {
			t.Error("pool config lacks", want, cfg)
		}
	}
	if strings.Contains(cfg, `"p-2"`) {
		t.Error("unknown protocol made an outbound")
	}
	if _, err := PoolConfig(`[{"server":`+testServer+`,"kind":"nope"}]`, "a", "b", 1); err == nil {
		t.Error("empty pool accepted")
	}
}

func TestAwgUAPI(t *testing.T) {
	u, err := AwgUAPI(testServer, "25g00001", "abc123")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"endpoint=1.2.3.4:30001", "jc=4\n", "h4=44\n", "allowed_ip=0.0.0.0/0",
		"public_key=8843a3c2b2c01982d1de008977c86c0ad2fed5ca9e4f3d653b5116417950625c"} {
		if !strings.Contains(u, want) {
			t.Errorf("missing %q in\n%s", want, u)
		}
	}
}

func TestWindowsConfig(t *testing.T) {
	choices := `[{"server":` + testServer + `,"kind":"hysteria2"}]`
	cfg, err := WindowsConfig(choices, "25g00001", "abc123", 10808, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"protocol":"tun"`, `"autoSystemRoutingTable":["0.0.0.0/0"]`, `"protocol":"socks"`, `"balancerTag":"best"`} {
		if !strings.Contains(cfg, want) {
			t.Error("windows config lacks", want)
		}
	}
}

func TestWindowsBypass(t *testing.T) {
	choices := `[{"server":` + testServer + `,"kind":"hysteria2"}]`
	cfg, err := WindowsConfig(choices, "u", "p", 10808, []string{"C:\\Program Files\\Mozilla Firefox\\firefox.exe", "Telegram.exe", "firefox.exe", "bad*name", ""})
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	json.Unmarshal([]byte(cfg), &c)
	rules := c["routing"].(map[string]any)["rules"].([]any)
	r := rules[0].(map[string]any)
	names := r["process"].([]any)
	if r["outboundTag"] != "direct" || len(names) != 2 || names[0] != "firefox.exe" || names[1] != "Telegram.exe" {
		t.Fatalf("bypass rule: %v", r)
	}
	plain, _ := WindowsConfig(choices, "u", "p", 10808, nil)
	if strings.Contains(plain, `"process"`) {
		t.Fatal("no bypass rule without programs")
	}
}

func TestHysteria2Salamander(t *testing.T) {
	pin := strings.Repeat("ab", 32) // Xray checks the pin's form
	server := strings.Replace(testServer, `"pin_sha256":"ff00"}`, `"pin_sha256":"`+pin+`","obfs":"s3cret"}`, 1)
	cfg, err := XrayConfig(server, "hysteria2", "25g00001", "abc123", 10808)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, `"type":"salamander"`) || !strings.Contains(cfg, `"password":"s3cret"`) {
		t.Fatal("no salamander mask:", cfg)
	}
	// Xray itself must accept it (the field names are Xray's)
	if _, err := serial.LoadJSONConfig(strings.NewReader(cfg)); err != nil {
		t.Fatal(err)
	}
	plain, _ := XrayConfig(testServer, "hysteria2", "25g00001", "abc123", 10808)
	if strings.Contains(plain, "salamander") {
		t.Fatal("mask without obfs") // servers set up before keep working
	}
}
