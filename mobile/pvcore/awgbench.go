package pvcore

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// AmneziaWG for the test app: a device whose TUN is a userspace TCP/IP stack
// (gVisor), so real HTTP requests and a download go through the tunnel
// without a VPN on the phone.

type stackTun struct {
	ep     *channel.Endpoint
	ctx    context.Context
	cancel context.CancelFunc
	events chan tun.Event
	once   sync.Once
}

func (t *stackTun) File() *os.File { return nil }
func (t *stackTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt := t.ep.ReadContext(t.ctx)
	if pkt == nil {
		return 0, os.ErrClosed
	}
	view := pkt.ToView()
	sizes[0] = copy(bufs[0][offset:], view.AsSlice())
	view.Release()
	pkt.DecRef()
	return 1, nil
}
func (t *stackTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		p := b[offset:]
		if len(p) == 0 || p[0]>>4 != 4 {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), p...))})
		t.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		pkb.DecRef()
	}
	return len(bufs), nil
}
func (t *stackTun) MTU() (int, error)        { return awgProbeBig, nil }
func (t *stackTun) Name() (string, error)    { return "bench", nil }
func (t *stackTun) Events() <-chan tun.Event { return t.events }
func (t *stackTun) BatchSize() int           { return 1 }
func (t *stackTun) Close() error {
	t.once.Do(func() { t.cancel(); close(t.events) })
	return nil
}

func benchAwg(serverJSON, user, pass string, port int, speed time.Duration) benchResult {
	uapi, err := AwgUAPI(serverJSON, user, pass)
	if err != nil {
		return benchResult{Error: err.Error()}
	}
	if host := awgHostOf(uapi); host != "" && port > 0 {
		uapi = withAwgPort(uapi, host, port)
	}
	src, err := netip.ParseAddr(AwgAddress(user))
	if err != nil {
		return benchResult{Error: err.Error()}
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	defer s.Close()
	ep := channel.New(1024, uint32(awgProbeBig), "")
	if e := s.CreateNIC(1, ep); e != nil {
		return benchResult{Error: fmt.Sprint(e)}
	}
	a4 := src.As4()
	if e := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(a4).WithPrefix()}, stack.AddressProperties{}); e != nil {
		return benchResult{Error: fmt.Sprint(e)}
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})

	ctx, cancel := context.WithCancel(context.Background())
	st := &stackTun{ep: ep, ctx: ctx, cancel: cancel, events: make(chan tun.Event, 1)}
	st.events <- tun.EventUp
	dev := device.NewDevice(st, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	if err := dev.IpcSet(uapi); err != nil {
		return benchResult{Error: err.Error()}
	}
	if err := dev.Up(); err != nil {
		return benchResult{Error: err.Error()}
	}
	// the handshake first (its own clear error)
	start := time.Now()
	for {
		state, _ := dev.IpcGet()
		if strings.Contains(state, "last_handshake_time_sec=") && !strings.Contains(state, "last_handshake_time_sec=0\n") {
			break
		}
		if time.Since(start) > 8*time.Second {
			return benchResult{Tries: 3, Error: "no handshake"}
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
	return benchHTTP(tr, speed)
}
