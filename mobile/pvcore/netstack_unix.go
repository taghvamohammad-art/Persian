//go:build !windows

package pvcore

import (
	"fmt"
	"strconv"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/xjasonlyu/tun2socks/v2/core"
	t2slog "github.com/xjasonlyu/tun2socks/v2/log"
	"github.com/xjasonlyu/tun2socks/v2/proxy/socks5"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
)

// The TUN -> SOCKS bridge (tun2socks' stack, set up here instead of with its
// engine package). Its engine closes the TUN descriptor BEFORE the packet
// reader stops; the number is free at once, a socket opened meanwhile (Xray
// is busy dialing) gets it, and the old reader keeps reading from that
// socket: its bytes vanish and that connection, then the tunnel, stalls
// ("connected, no data", most often right after switching protocols).
// Here the reader is stopped and waited for first, and only then is the
// descriptor closed.

type tunDevice struct {
	stack.LinkEndpoint
	fd int
}

func (d *tunDevice) Name() string { return strconv.Itoa(d.fd) }
func (d *tunDevice) Type() string { return "fd" }

var (
	nsStack *stack.Stack
	nsDev   *tunDevice
)

func init() {
	if lvl, err := t2slog.ParseLevel("error"); err == nil {
		if l, err := t2slog.NewLeveled(lvl); err == nil {
			t2slog.SetLogger(l)
		}
	}
}

// startNetstack: called with mu held. On error the descriptor is NOT closed
// (the caller does that).
func startNetstack(fd, mtu, socksPort int) error {
	px, err := socks5.New(fmt.Sprintf("127.0.0.1:%d", socksPort), "", "")
	if err != nil {
		return err
	}
	tunnel.T().SetProxy(px)
	ep, err := fdbased.New(&fdbased.Options{FDs: []int{fd}, MTU: uint32(mtu), EthernetHeader: false})
	if err != nil {
		return fmt.Errorf("tun endpoint: %w", err)
	}
	dev := &tunDevice{LinkEndpoint: ep, fd: fd}
	st, err := core.CreateStack(&core.Config{LinkEndpoint: dev, TransportHandler: tunnel.T()})
	if err != nil {
		dev.Attach(nil)
		return fmt.Errorf("tun stack: %w", err)
	}
	nsStack, nsDev = st, dev
	return nil
}

// stopNetstack: called with mu held.
func stopNetstack() {
	if nsStack != nil {
		nsStack.Close() // removes the NIC: the endpoint's reader is told to stop
		nsStack.Wait()
		nsStack = nil
	}
	if nsDev != nil {
		nsDev.LinkEndpoint.Attach(nil) // no-op if the stack already detached it
		nsDev.LinkEndpoint.Wait()      // the reader has returned...
		unix.Close(nsDev.fd)           // ...so the number can be reused safely
		nsDev = nil
	}
}
