//go:build windows

package main

// SSTP through Windows' own VPN client, the last resort when no Linux
// protocol works. Windows only accepts the router's certificate when it
// trusts it, so the certificate the router presents is checked against the
// signed config's pins and, being a self-signed leaf (not a CA: it cannot
// vouch for anything else), added to the machine's trusted roots.

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"persianvpn/mobile/pvcore"
)

const sstpName = "Persian VPN SSTP"

func hidden(name string, args ...string) *exec.Cmd {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return c
}

func powershell(script string) (string, error) {
	out, err := hidden("powershell", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	return string(out), err
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// trustRouter fetches the certificate, checks the pins, trusts it.
func trustRouter(host string, port int, pins []string) (*x509.Certificate, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 8 * time.Second}, "tcp",
		net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	certs := conn.ConnectionState().PeerCertificates
	conn.Close()
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate")
	}
	leaf := certs[0]
	sum := sha256.Sum256(leaf.Raw)
	ok := false
	for _, p := range pins {
		if strings.EqualFold(strings.ReplaceAll(p, ":", ""), hex.EncodeToString(sum[:])) {
			ok = true
		}
	}
	if !ok {
		return nil, fmt.Errorf("certificate not in the signed pins")
	}
	if leaf.IsCA {
		return nil, fmt.Errorf("router certificate is a CA; not trusting it system-wide")
	}
	path := filepath.Join(os.TempDir(), "pv-sstp.cer")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), 0o600); err != nil {
		return nil, err
	}
	defer os.Remove(path)
	if out, err := hidden("certutil", "-f", "-addstore", "Root", path).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("certutil: %s", strings.TrimSpace(string(out)))
	}
	return leaf, nil
}

// sstpAddress is the name Windows must dial so the certificate matches.
func sstpAddress(host string, leaf *x509.Certificate) string {
	for _, ip := range leaf.IPAddresses {
		if ip.String() == host {
			return host
		}
	}
	if len(leaf.DNSNames) > 0 {
		return leaf.DNSNames[0]
	}
	if leaf.Subject.CommonName != "" {
		return leaf.Subject.CommonName
	}
	return host
}

// pinHostsEntry makes a certificate name resolve to the router's IP.
func pinHostsEntry(name, ip string) {
	if net.ParseIP(name) != nil || name == ip {
		return
	}
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts")
	data, _ := os.ReadFile(path)
	var keep []string
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if !strings.HasSuffix(line, "# persian-vpn") {
			keep = append(keep, line)
		}
	}
	for len(keep) > 0 && keep[len(keep)-1] == "" {
		keep = keep[:len(keep)-1]
	}
	keep = append(keep, fmt.Sprintf("%s %s # persian-vpn", ip, name), "")
	os.WriteFile(path, []byte(strings.Join(keep, "\r\n")), 0o644)
}

func startSstp(cfg *pvcore.SignedConfig, user, pass string) (string, error) {
	var lastErr error = fmt.Errorf("no SSTP server")
	for _, sv := range cfg.Servers {
		port := sv.Port
		if port == 0 {
			port = 443
		}
		leaf, err := trustRouter(sv.Host, port, cfg.SstpPins)
		if err != nil {
			lastErr = err
			continue
		}
		addr := sstpAddress(sv.Host, leaf)
		pinHostsEntry(addr, sv.Host)
		if port != 443 {
			addr = net.JoinHostPort(addr, strconv.Itoa(port))
		}
		hidden("rasdial", sstpName, "/disconnect").Run()
		script := fmt.Sprintf("Remove-VpnConnection -Name %[1]s -AllUserConnection -Force -ErrorAction SilentlyContinue; "+
			"Add-VpnConnection -Name %[1]s -ServerAddress %[2]s -TunnelType Sstp -EncryptionLevel Required "+
			"-AuthenticationMethod MSChapv2 -AllUserConnection -RememberCredential:$false -Force",
			psQuote(sstpName), psQuote(addr))
		if out, err := powershell(script); err != nil {
			lastErr = fmt.Errorf("vpn connection: %s", strings.TrimSpace(out))
			continue
		}
		out, err := hidden("rasdial", sstpName, user, pass).CombinedOutput()
		if err != nil {
			lastErr = fmt.Errorf("rasdial: %s", strings.TrimSpace(string(out)))
			continue
		}
		return sv.Name + "/sstp", nil
	}
	return "", lastErr
}

func stopSstp() { hidden("rasdial", sstpName, "/disconnect").Run() }
