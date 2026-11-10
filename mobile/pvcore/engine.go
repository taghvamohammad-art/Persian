package pvcore

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/xjasonlyu/tun2socks/v2/engine"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// ProbeURL answers 204 quickly from anywhere; used to test a protocol.
var ProbeURL = "https://www.gstatic.com/generate_204"

var (
	mu       sync.Mutex
	xrayInst *core.Instance
	tunOn    bool
	awgDev   *device.Device
	running  string
	socksAt  int
)

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func startXrayInstance(cfg string) (*core.Instance, error) {
	c, err := serial.LoadJSONConfig(strings.NewReader(cfg))
	if err != nil {
		return nil, fmt.Errorf("xray config: %w", err)
	}
	inst, err := core.New(c)
	if err != nil {
		return nil, fmt.Errorf("xray: %w", err)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return nil, fmt.Errorf("xray start: %w", err)
	}
	return inst, nil
}

func stopLocked() {
	if tunOn {
		engine.Stop()
		tunOn = false
	}
	if xrayInst != nil {
		xrayInst.Close()
		xrayInst = nil
	}
	if awgDev != nil {
		awgDev.Close()
		awgDev = nil
	}
	running = ""
	socksAt = 0
}

// Stop ends whatever engine is running.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	stopLocked()
}

// Running is the protocol type in use ("" when stopped).
func Running() string {
	mu.Lock()
	defer mu.Unlock()
	return running
}

// StartXray runs one Xray protocol of a server behind the VPN's TUN (fd).
// The app's own sockets bypass the VPN (its package is excluded), so the
// engine's connections to the server go out directly.
// The descriptor belongs to the engine: it is closed on failure too.
func StartXray(serverJSON, kind, user, pass string, tunFd, mtu int) error {
	mu.Lock()
	defer mu.Unlock()
	stopLocked()
	fail := func(err error) error {
		syscall.Close(tunFd)
		return err
	}
	port, err := freePort()
	if err != nil {
		return fail(err)
	}
	cfg, err := XrayConfig(serverJSON, kind, user, pass, port)
	if err != nil {
		return fail(err)
	}
	inst, err := startXrayInstance(cfg)
	if err != nil {
		return fail(err)
	}
	xrayInst = inst
	engine.Insert(&engine.Key{
		Proxy:    fmt.Sprintf("socks5://127.0.0.1:%d", port),
		Device:   fmt.Sprintf("fd://%d", tunFd),
		MTU:      mtu,
		LogLevel: "error",
	})
	engine.Start()
	tunOn = true
	running = kind
	socksAt = port
	return nil
}

// StartAwg runs AmneziaWG on the VPN's TUN (fd).
func StartAwg(serverJSON, user, pass string, tunFd int) error {
	mu.Lock()
	defer mu.Unlock()
	stopLocked()
	uapi, err := AwgUAPI(serverJSON, user, pass)
	if err != nil {
		syscall.Close(tunFd)
		return err
	}
	tdev, _, err := tun.CreateUnmonitoredTUNFromFD(tunFd)
	if err != nil {
		syscall.Close(tunFd)
		return fmt.Errorf("awg tun: %w", err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "awg: "))
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return fmt.Errorf("awg config: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("awg up: %w", err)
	}
	awgDev = dev
	running = "amneziawg"
	return nil
}

// Check tells whether the running engine still reaches the internet:
// milliseconds of a test request through it, or -1. For AmneziaWG it is
// the age of the last handshake (servers answer every 2 minutes at most
// while keepalives flow), so no extra traffic is made.
func Check(timeoutMs int) int {
	mu.Lock()
	kind, port, dev := running, socksAt, awgDev
	mu.Unlock()
	switch {
	case kind == "":
		return -1
	case dev != nil:
		state, err := dev.IpcGet()
		if err != nil {
			return -1
		}
		for _, line := range strings.Split(state, "\n") {
			if v, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
				var sec int64
				fmt.Sscan(v, &sec)
				if sec == 0 {
					return -1
				}
				age := time.Since(time.Unix(sec, 0))
				if age > 200*time.Second {
					return -1
				}
				return int(age.Milliseconds())
			}
		}
		return -1
	default:
		ms, err := getThrough(port, time.Duration(timeoutMs)*time.Millisecond)
		if err != nil {
			return -1
		}
		return ms
	}
}

func getThrough(port int, timeout time.Duration) (int, error) {
	proxy, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", port))
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}}
	start := time.Now()
	resp, err := client.Get(ProbeURL)
	if err != nil {
		return -1, err
	}
	resp.Body.Close()
	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return -1, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return int(time.Since(start).Milliseconds()), nil
}

// ---------------------------------------------------------------- probing

func probeXray(serverJSON, kind, user, pass string, timeout time.Duration) (int, error) {
	port, err := freePort()
	if err != nil {
		return -1, err
	}
	cfg, err := XrayConfig(serverJSON, kind, user, pass, port)
	if err != nil {
		return -1, err
	}
	inst, err := startXrayInstance(cfg)
	if err != nil {
		return -1, err
	}
	defer inst.Close()
	return getThrough(port, timeout)
}

// nullTun is a TUN that carries nothing: enough to see whether the
// AmneziaWG handshake with the server succeeds.
type nullTun struct {
	events chan tun.Event
	closed chan struct{}
	once   sync.Once
}

func newNullTun() *nullTun {
	t := &nullTun{events: make(chan tun.Event, 1), closed: make(chan struct{})}
	t.events <- tun.EventUp
	return t
}

func (t *nullTun) File() *os.File { return nil }
func (t *nullTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-t.closed
	return 0, os.ErrClosed
}
func (t *nullTun) Write(bufs [][]byte, offset int) (int, error) { return len(bufs), nil }
func (t *nullTun) MTU() (int, error)                            { return 1420, nil }
func (t *nullTun) Name() (string, error)                        { return "probe", nil }
func (t *nullTun) Events() <-chan tun.Event                     { return t.events }
func (t *nullTun) BatchSize() int                               { return 1 }
func (t *nullTun) Close() error {
	t.once.Do(func() { close(t.closed); close(t.events) })
	return nil
}

func probeAwg(serverJSON, user, pass string, timeout time.Duration) (int, error) {
	uapi, err := AwgUAPI(serverJSON, user, pass)
	if err != nil {
		return -1, err
	}
	uapi = strings.Replace(uapi, "persistent_keepalive_interval=25", "persistent_keepalive_interval=1", 1)
	dev := device.NewDevice(newNullTun(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	if err := dev.IpcSet(uapi); err != nil {
		return -1, err
	}
	start := time.Now()
	if err := dev.Up(); err != nil {
		return -1, err
	}
	for time.Since(start) < timeout {
		state, err := dev.IpcGet()
		if err == nil && strings.Contains(state, "last_handshake_time_sec=") &&
			!strings.Contains(state, "last_handshake_time_sec=0\n") {
			return int(time.Since(start).Milliseconds()), nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return -1, fmt.Errorf("no handshake")
}

// Probe tries every protocol of a server at once and returns JSON
// {"<type>": milliseconds or -1, ...}; "errors" holds the reasons.
func Probe(serverJSON, user, pass string, timeoutMs int) string {
	s, err := parseServer(serverJSON)
	out := map[string]any{}
	errs := map[string]string{}
	if err != nil {
		errs["config"] = err.Error()
		out["errors"] = errs
		b, _ := json.Marshal(out)
		return string(b)
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond
	var wg sync.WaitGroup
	var lock sync.Mutex
	for _, p := range s.Protocols {
		kind := p.Type
		wg.Add(1)
		go func() {
			defer wg.Done()
			var ms int
			var err error
			if kind == "amneziawg" {
				ms, err = probeAwg(serverJSON, user, pass, timeout)
			} else {
				ms, err = probeXray(serverJSON, kind, user, pass, timeout)
			}
			lock.Lock()
			out[kind] = ms
			if err != nil {
				errs[kind] = err.Error()
			}
			lock.Unlock()
		}()
	}
	wg.Wait()
	out["errors"] = errs
	b, _ := json.Marshal(out)
	return string(b)
}

// Best is the fastest working protocol of a Probe result ("" if none).
func Best(probeJSON string) string {
	var m map[string]any
	if json.Unmarshal([]byte(probeJSON), &m) != nil {
		return ""
	}
	best, bestMs := "", 1<<30
	for k, v := range m {
		ms, ok := v.(float64)
		if !ok || ms < 0 {
			continue
		}
		if int(ms) < bestMs {
			best, bestMs = k, int(ms)
		}
	}
	return best
}
