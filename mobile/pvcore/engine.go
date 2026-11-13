package pvcore

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
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
	// AmneziaWG byte counters at the last Check: sending without receiving
	// anything back means the tunnel is up on paper only
	awgRx, awgTx int64

	extraStop func()
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
		stopNetstack()
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
	if extraStop != nil { // system routes of the Windows AmneziaWG tunnel
		extraStop()
		extraStop = nil
	}
	running = ""
	socksAt = 0
	awgRx, awgTx = -1, -1
}

// Stop ends whatever engine is running.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	stopLocked()
}

// TunnelBytes: "up down", the bytes the apps sent into the Xray tunnel and
// got back since it started ("-1 -1" when not an Xray tunnel). Apps that
// keep sending and get nothing back while the health check still passes
// mean the tunnel is stuck for them.
func TunnelBytes() string {
	mu.Lock()
	inst := xrayInst
	mu.Unlock()
	if inst == nil {
		return "-1 -1"
	}
	m, ok := inst.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		return "-1 -1"
	}
	val := func(name string) int64 {
		if c := m.GetCounter(name); c != nil {
			return c.Value()
		}
		return -1
	}
	in := "socks"
	if runtime.GOOS == "windows" {
		in = "tun"
	}
	return fmt.Sprintf("%d %d", val("inbound>>>"+in+">>>traffic>>>uplink"), val("inbound>>>"+in+">>>traffic>>>downlink"))
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
	return startXrayWith(func(port int) (string, error) {
		return XrayConfig(serverJSON, kind, user, pass, port)
	}, kind, tunFd, mtu)
}

// StartXrayPool runs several protocols (of one or more servers) at once:
// Xray measures them every minute and sends new connections over the
// fastest working one, so a slower or blocked protocol is left without the
// tunnel ever going down. choicesJSON: [{"server": {...}, "kind": "..."}],
// best first.
func StartXrayPool(choicesJSON, user, pass string, tunFd, mtu int) error {
	return startXrayWith(func(port int) (string, error) {
		return PoolConfig(choicesJSON, user, pass, port)
	}, "pool", tunFd, mtu)
}

func startXrayWith(build func(port int) (string, error), kind string, tunFd, mtu int) error {
	mu.Lock()
	defer mu.Unlock()
	stopLocked()
	fail := func(err error) error {
		closeFd(tunFd)
		return err
	}
	port, err := freePort()
	if err != nil {
		return fail(err)
	}
	cfg, err := build(port)
	if err != nil {
		return fail(err)
	}
	inst, err := startXrayInstance(cfg)
	if err != nil {
		return fail(err)
	}
	if err := startNetstack(tunFd, mtu, port); err != nil {
		inst.Close()
		return fail(err)
	}
	xrayInst = inst
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
		closeFd(tunFd)
		return err
	}
	tdev, err := tunFromFd(tunFd)
	if err != nil {
		closeFd(tunFd)
		return fmt.Errorf("awg tun: %w", err)
	}
	return awgOnLocked(tdev, uapi)
}

// awgOnLocked runs AmneziaWG on a TUN (which it closes on failure).
func awgOnLocked(tdev tun.Device, uapi string) error {
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
		return awgHealth(state)
	default:
		ms, err := getThrough(port, time.Duration(timeoutMs)*time.Millisecond)
		if err != nil {
			return -1
		}
		return ms
	}
}

// awgHealth: a recent handshake, and replies to what was sent since the
// last check (a filtered path can keep handshakes alive while data is lost).
func awgHealth(state string) int {
	var sec, rx, tx int64 = -1, 0, 0
	for _, line := range strings.Split(state, "\n") {
		if v, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
			fmt.Sscan(v, &sec)
		} else if v, ok := strings.CutPrefix(line, "rx_bytes="); ok {
			fmt.Sscan(v, &rx)
		} else if v, ok := strings.CutPrefix(line, "tx_bytes="); ok {
			fmt.Sscan(v, &tx)
		}
	}
	mu.Lock()
	lastRx, lastTx := awgRx, awgTx
	awgRx, awgTx = rx, tx
	mu.Unlock()
	if sec <= 0 {
		return -1
	}
	age := time.Since(time.Unix(sec, 0))
	if age > 200*time.Second {
		return -1
	}
	if lastTx >= 0 && tx-lastTx > 8192 && rx == lastRx {
		return -1
	}
	return int(age.Milliseconds())
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

// ProbePool runs the pool of all Xray protocols of a server (as the app
// does when connected) and fetches the test page through it twice: right
// away and after Xray's first measurements. Tests and support.
func ProbePool(serverJSON, user, pass string, timeoutMs int) string {
	s, err := parseServer(serverJSON)
	if err != nil {
		return err.Error()
	}
	var choices []map[string]any
	for _, p := range s.Protocols {
		if p.Type != "amneziawg" && p.Type != "vless-dns" {
			choices = append(choices, map[string]any{"server": json.RawMessage(serverJSON), "kind": p.Type})
		}
	}
	cj, _ := json.Marshal(choices)
	port, err := freePort()
	if err != nil {
		return err.Error()
	}
	cfg, err := PoolConfig(string(cj), user, pass, port)
	if err != nil {
		return err.Error()
	}
	inst, err := startXrayInstance(cfg)
	if err != nil {
		return err.Error()
	}
	defer inst.Close()
	timeout := time.Duration(timeoutMs) * time.Millisecond
	first, err1 := getThrough(port, timeout)
	time.Sleep(5 * time.Second)
	second, err2 := getThrough(port, timeout)
	return fmt.Sprintf("pool: %d %v / %d %v", first, err1, second, err2)
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
	anyOK := false
	tunnel := make(chan struct{})
	hasTunnel := false
	for _, p := range s.Protocols {
		kind := p.Type
		slow := kind == "vless-dns" // the DNS tunnel is the last resort and slow to answer
		if slow {
			hasTunnel = true
		} else {
			wg.Add(1)
		}
		go func() {
			if slow {
				defer close(tunnel)
			} else {
				defer wg.Done()
			}
			var ms int
			var err error
			switch {
			case kind == "amneziawg":
				ms, err = probeAwg(serverJSON, user, pass, timeout)
			case slow:
				ms, err = probeXray(serverJSON, kind, user, pass, 3*timeout)
			default:
				ms, err = probeXray(serverJSON, kind, user, pass, timeout)
			}
			lock.Lock()
			out[kind] = ms
			if err != nil {
				errs[kind] = err.Error()
			}
			if ms >= 0 {
				anyOK = true
			}
			lock.Unlock()
		}()
	}
	wg.Wait()
	if hasTunnel {
		lock.Lock()
		ok := anyOK
		lock.Unlock()
		if ok {
			// something faster works: do not wait for the tunnel
			select {
			case <-tunnel:
			case <-time.After(200 * time.Millisecond):
			}
		} else {
			<-tunnel
		}
		lock.Lock()
		if _, done := out["vless-dns"]; !done {
			out["vless-dns"] = -1
			errs["vless-dns"] = "skipped"
		}
		lock.Unlock()
	}
	lock.Lock()
	defer lock.Unlock()
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
