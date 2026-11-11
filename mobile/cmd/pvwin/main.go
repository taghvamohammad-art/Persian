//go:build windows

// pvwin is the Windows engine of Persian VPN: a service (installed once,
// with administrator rights) that the app talks to on a local port, so
// the app itself runs as an ordinary user.
//
//	pvwin install     copy to Program Files, create and start the service
//	pvwin uninstall   stop and remove the service
//	pvwin service     what the service manager runs
//	pvwin console     the same in a console window (tests)
//
// Requests are JSON lines on 127.0.0.1:47811, one answer line each:
//
//	{"cmd":"status"}
//	{"cmd":"connect","envelope":"<signed app config>","user":"..","pass":".."}
//	{"cmd":"disconnect"}
//	{"cmd":"upgrade","envelope":"<signed app config>","path":"C:\\...\\pvwin.exe"}
//
// Any local program can reach that port, so the service only ever uses
// servers, and only ever installs an engine, named in a config signed
// with the owner's key (config_key.public.txt next to the service).
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"persianvpn/mobile/pvcore"
)

const (
	serviceName = "PersianVPN"
	listenAddr  = "127.0.0.1:47811"
)

var version = "0" // the build number, set when building

var tunnel session

type request struct {
	Cmd      string `json:"cmd"`
	Envelope string `json:"envelope"`
	User     string `json:"user"`
	Pass     string `json:"pass"`
	Path     string `json:"path"`
}

func exeDir() string {
	exe, _ := os.Executable()
	return filepath.Dir(exe)
}

func signedConfig(envelope string) (*pvcore.SignedConfig, error) {
	pub, err := os.ReadFile(filepath.Join(exeDir(), "config_key.public.txt"))
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	return pvcore.VerifyEnvelope(envelope, string(pub))
}

func handle(req request) map[string]any {
	switch req.Cmd {
	case "status":
	case "connect":
		cfg, err := signedConfig(req.Envelope)
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		if len(cfg.LinuxServers) == 0 && len(cfg.Servers) == 0 {
			return map[string]any{"ok": false, "error": "no servers"}
		}
		tunnel.Connect(cfg, req.User, req.Pass)
	case "disconnect":
		tunnel.Disconnect()
	case "upgrade":
		if err := upgrade(req); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		go func() { // answer first, then let the service manager start the new engine
			time.Sleep(500 * time.Millisecond)
			tunnel.Disconnect()
			os.Exit(3)
		}()
		return map[string]any{"ok": true, "restarting": true}
	default:
		return map[string]any{"ok": false, "error": "unknown command"}
	}
	state, protocols, lastErr := tunnel.status()
	v, _ := strconv.Atoi(version)
	return map[string]any{"ok": true, "state": state, "protocols": protocols, "error": lastErr, "version": v}
}

// upgrade replaces this engine with a newer one whose SHA-256 the signed
// config names; the exit that follows makes the service manager start it.
func upgrade(req request) error {
	cfg, err := signedConfig(req.Envelope)
	if err != nil {
		return err
	}
	cur, _ := strconv.Atoi(version)
	if cfg.WindowsUpdate == nil || cfg.WindowsUpdate.EngineSHA256 == "" || cfg.WindowsUpdate.VersionCode <= cur {
		return fmt.Errorf("no newer signed engine")
	}
	data, err := os.ReadFile(req.Path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), cfg.WindowsUpdate.EngineSHA256) {
		return fmt.Errorf("engine does not match the signed hash")
	}
	exe, _ := os.Executable()
	next, old := exe+".new", exe+".old"
	if err := os.WriteFile(next, data, 0o755); err != nil {
		return err
	}
	os.Remove(old)
	if err := os.Rename(exe, old); err != nil { // a running program can be renamed
		return err
	}
	if err := os.Rename(next, exe); err != nil {
		os.Rename(old, exe)
		return err
	}
	return nil
}

func serve() error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	os.Remove(filepath.Join(exeDir(), "pvwin.exe.old"))
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReaderSize(c, 1<<20)
				enc := json.NewEncoder(c)
				for {
					c.SetReadDeadline(time.Now().Add(5 * time.Minute))
					line, err := r.ReadBytes('\n')
					if err != nil {
						return
					}
					var req request
					if json.Unmarshal(line, &req) != nil {
						enc.Encode(map[string]any{"ok": false, "error": "bad request"})
						continue
					}
					enc.Encode(handle(req))
				}
			}()
		}
	}()
	return nil
}

type handler struct{}

func (handler) Execute(_ []string, r <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	if err := serve(); err != nil {
		return true, 1
	}
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			st <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			st <- svc.Status{State: svc.StopPending}
			tunnel.Disconnect()
			return false, 0
		}
	}
	return false, 0
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func stopService(s *mgr.Service) {
	s.Control(svc.Stop)
	for i := 0; i < 40; i++ {
		if st, err := s.Query(); err != nil || st.State == svc.Stopped {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func install() error {
	dir := filepath.Join(os.Getenv("ProgramFiles"), "PersianVPN")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager (run as administrator): %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		stopService(s)
		s.Close()
	}
	src := exeDir()
	exe := filepath.Join(dir, "pvwin.exe")
	self, _ := os.Executable()
	if !strings.EqualFold(self, exe) {
		if err := copyFile(self, exe); err != nil {
			return err
		}
		for _, name := range []string{"wintun.dll", "config_key.public.txt"} {
			if err := copyFile(filepath.Join(src, name), filepath.Join(dir, name)); err != nil {
				return err
			}
		}
	}
	s, err := m.OpenService(serviceName)
	if err != nil {
		s, err = m.CreateService(serviceName, exe, mgr.Config{
			StartType: mgr.StartAutomatic, DisplayName: "Persian VPN",
			Description: "Persian VPN tunnel"}, "service")
		if err != nil {
			return err
		}
	}
	defer s.Close()
	s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: time.Second}}, 60)
	s.SetRecoveryActionsOnNonCrashFailures(true)
	return s.Start("service")
}

func uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return nil
	}
	defer s.Close()
	stopService(s)
	return s.Delete()
}

func main() {
	cmd := "service"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "install":
		err = install()
	case "uninstall":
		err = uninstall()
	case "console":
		if err = serve(); err == nil {
			fmt.Println("listening on", listenAddr, "version", version)
			bufio.NewReader(os.Stdin).ReadString(0) // until input closes
			tunnel.Disconnect()
		}
	case "version":
		fmt.Println(version)
	default:
		err = svc.Run(serviceName, handler{})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pvwin:", err)
		os.Exit(1)
	}
}
