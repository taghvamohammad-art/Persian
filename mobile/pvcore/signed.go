package pvcore

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// SignedConfig is what the Windows service takes from the owner's signed
// app config (tools/sign_config.py). The service runs with system rights
// and listens to any local program, so it only ever uses servers and
// updates that carry the owner's signature.
type SignedConfig struct {
	Version      int               `json:"version"`
	LinuxServers []json.RawMessage `json:"linux_servers"`
	// MikroTik SSTP servers, the last resort
	Servers []struct {
		Name string `json:"name"`
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"servers"`
	SstpPins          []string      `json:"sstp_pins"`
	WindowsUpdate     *WindowsBuild `json:"windows_update"`
	WindowsUpdateBeta *WindowsBuild `json:"windows_update_beta"` // test build (testers only)
}

// WindowsBuild: what the service needs to accept an engine upgrade.
type WindowsBuild struct {
	VersionCode  int    `json:"version_code"`
	EngineSHA256 string `json:"engine_sha256"`
}

// VerifyEnvelope checks {"payload": b64, "sig": b64} against the public key
// (base64 DER, as in config_key.public.txt) and returns the config inside.
func VerifyEnvelope(envelope, publicKeyB64 string) (*SignedConfig, error) {
	var env struct {
		Payload string `json:"payload"`
		Sig     string `json:"sig"`
	}
	if err := json.Unmarshal([]byte(envelope), &env); err != nil {
		return nil, errors.New("config: not an envelope")
	}
	payload, err1 := base64.StdEncoding.DecodeString(env.Payload)
	sig, err2 := base64.StdEncoding.DecodeString(env.Sig)
	der, err3 := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKeyB64))
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errors.New("config: bad encoding")
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("config: bad public key")
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("config: not an EC key")
	}
	sum := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return nil, errors.New("config: signature invalid")
	}
	var cfg SignedConfig
	if err := json.Unmarshal(payload, &cfg); err != nil {
		return nil, errors.New("config: bad payload")
	}
	return &cfg, nil
}
