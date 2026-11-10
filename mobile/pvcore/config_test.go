package pvcore

import (
	"encoding/json"
	"strings"
	"testing"
)

const testServer = `{"name":"t","host":"1.2.3.4","protocols":[
 {"type":"vless-reality-vision","port":443,"sni":"www.microsoft.com","public_key":"PK","short_id":"ab12"},
 {"type":"vless-xhttp-reality","port":8443,"sni":"www.microsoft.com","path":"/x","public_key":"PK","short_id":"ab12"},
 {"type":"hysteria2","port":443,"pin_sha256":"ff00"},
 {"type":"shadowsocks-2022","port":20001,"method":"2022-blake3-aes-128-gcm","server_key":"c2VydmVya2V5c2VydmVya2V5"},
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
	if _, err := XrayConfig(testServer, "nope", "a", "b", 1); err == nil {
		t.Error("unknown protocol accepted")
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
