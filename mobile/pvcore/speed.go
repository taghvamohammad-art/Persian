package pvcore

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// Speed checks: a filter can let a server's address answer small requests
// quickly while it carries only a few KB/s (the latency probes then call it
// the best). A short, bounded download tells the two apart; the app then
// puts CDN (through Cloudflare, not the server's address) first.

// SpeedURL: SpeedMaxBytes of data from a fast, widely reachable host.
var SpeedURL = "https://speed.cloudflare.com/__down?bytes=%d"

// SpeedMaxBytes bounds a check: on a fast path it ends in well under a
// second, so it costs little mobile data.
var SpeedMaxBytes = 1_000_000

// Speed measures one protocol of a server before connecting: KB/s of a
// download of at most SpeedMaxBytes during at most `seconds` (counted from
// the first byte), or -1 when nothing came.
func Speed(serverJSON, kind, user, pass string, seconds int) int {
	limit := time.Duration(seconds) * time.Second
	if kind == "amneziawg" {
		tr, closeFn, err := awgStackTransport(serverJSON, user, pass, 0)
		if err != nil {
			return -1
		}
		defer closeFn()
		return speedVia(tr, limit)
	}
	port, err := freePort()
	if err != nil {
		return -1
	}
	cfg, err := XrayConfig(serverJSON, kind, user, pass, port)
	if err != nil {
		return -1
	}
	inst, err := startXrayInstance(cfg)
	if err != nil {
		return -1
	}
	defer inst.Close()
	return speedVia(socksTransport(port), limit)
}

// SpeedRunning measures the running Xray tunnel (through its SOCKS port):
// KB/s, -1 when it failed, -2 when it cannot be measured (AmneziaWG: a
// second device with the same key would take the server's session over).
func SpeedRunning(seconds int) int {
	mu.Lock()
	kind, port := running, socksAt
	mu.Unlock()
	if kind == "" || kind == "amneziawg" || port == 0 {
		return -2
	}
	return speedVia(socksTransport(port), time.Duration(seconds)*time.Second)
}

func socksTransport(port int) *http.Transport {
	proxy, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", port))
	return &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
}

// speedVia: KB/s of the bounded download through tr (-1: nothing came).
func speedVia(tr *http.Transport, limit time.Duration) int {
	n, el, err := download(tr, limit, SpeedMaxBytes)
	if n == 0 || err != nil && n < 1024 {
		return -1
	}
	if el < 50*time.Millisecond {
		el = 50 * time.Millisecond
	}
	return int(float64(n) / el.Seconds() / 1000)
}

// download reads at most maxBytes for at most limit after the first byte
// (the connection itself may take up to 8 s more): bytes and the time they took.
func download(tr *http.Transport, limit time.Duration, maxBytes int) (int, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), limit+8*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf(SpeedURL, maxBytes), nil)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	buf := make([]byte, 32<<10)
	n := 0
	var first time.Time
	for n < maxBytes {
		k, err := resp.Body.Read(buf)
		if k > 0 {
			if first.IsZero() {
				first = time.Now()
			}
			n += k
		}
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			if first.IsZero() {
				return 0, 0, err
			}
			return n, time.Since(first), err
		}
		if time.Since(first) >= limit {
			break
		}
	}
	return n, time.Since(first), nil
}

// awgStackTransport: AmneziaWG on a userspace TCP/IP stack (gVisor), so a
// real download goes through it without the VPN. port 0: the port the last
// probe found working (or the server's main one).
func awgStackTransport(serverJSON, user, pass string, port int) (*http.Transport, func(), error) {
	uapi, err := AwgUAPI(serverJSON, user, pass)
	if err != nil {
		return nil, nil, err
	}
	if host := awgHostOf(uapi); host != "" {
		if port <= 0 {
			port = awgPortFor(host)
		}
		if port > 0 {
			uapi = withAwgPort(uapi, host, port)
		}
	}
	src, err := netip.ParseAddr(AwgAddress(user))
	if err != nil {
		return nil, nil, err
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(1024, uint32(awgProbeBig), "")
	if e := s.CreateNIC(1, ep); e != nil {
		s.Close()
		return nil, nil, fmt.Errorf("%v", e)
	}
	a4 := src.As4()
	if e := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(a4).WithPrefix()}, stack.AddressProperties{}); e != nil {
		s.Close()
		return nil, nil, fmt.Errorf("%v", e)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	st := &stackTun{ep: ep, ctx: ctx, cancel: cancel, events: make(chan tun.Event, 1)}
	st.events <- tun.EventUp
	dev := device.NewDevice(st, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	closeFn := func() {
		dev.Close()
		s.Close()
	}
	if err := dev.IpcSet(uapi); err != nil {
		closeFn()
		return nil, nil, err
	}
	if err := dev.Up(); err != nil {
		closeFn()
		return nil, nil, err
	}
	start := time.Now()
	for {
		state, _ := dev.IpcGet()
		if strings.Contains(state, "last_handshake_time_sec=") && !strings.Contains(state, "last_handshake_time_sec=0\n") {
			break
		}
		if time.Since(start) > 8*time.Second {
			closeFn()
			return nil, nil, fmt.Errorf("no handshake")
		}
		time.Sleep(50 * time.Millisecond)
	}
	tr := benchTransport(func(ctx context.Context, ip net.IP, port int) (net.Conn, error) {
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("IPv6 is not carried")
		}
		return gonet.DialContextTCP(ctx, s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte(ip4)),
			Port: uint16(port)}, ipv4.ProtocolNumber)
	})
	return tr, closeFn, nil
}
