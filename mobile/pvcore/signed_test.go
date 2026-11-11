package pvcore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestVerifyEnvelope(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pub := base64.StdEncoding.EncodeToString(der) + "\n"
	payload := []byte(`{"version":7,"linux_servers":[{"name":"l1"}],"windows_update":{"version_code":12,"engine_sha256":"ab"}}`)
	sum := sha256.Sum256(payload)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, sum[:])
	env := func(p, s []byte) string {
		b, _ := json.Marshal(map[string]string{"payload": base64.StdEncoding.EncodeToString(p),
			"sig": base64.StdEncoding.EncodeToString(s)})
		return string(b)
	}
	cfg, err := VerifyEnvelope(env(payload, sig), pub)
	if err != nil || cfg.Version != 7 || len(cfg.LinuxServers) != 1 || cfg.WindowsUpdate.VersionCode != 12 {
		t.Fatal(cfg, err)
	}
	if _, err := VerifyEnvelope(env([]byte(`{"version":8}`), sig), pub); err == nil {
		t.Error("tampered payload accepted")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der2, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	if _, err := VerifyEnvelope(env(payload, sig), base64.StdEncoding.EncodeToString(der2)); err == nil {
		t.Error("wrong key accepted")
	}
}
