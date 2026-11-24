//go:build windows

package pvcore

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const WinAwgName = "Persian VPN WG"

// StartAwgWindows runs AmneziaWG on its own Wintun adapter and sends the
// whole system through it: the adapter gets the user's tunnel address and
// DNS, two half-default routes win over the real default route, and one
// host route keeps the packets to the server itself on the real network.
func StartAwgWindows(serverJSON, user, pass string) error {
	mu.Lock()
	defer mu.Unlock()
	stopLocked()
	uapi, err := AwgUAPI(serverJSON, user, pass)
	if err != nil {
		return err
	}
	var endpoint netip.Addr
	for _, line := range strings.Split(uapi, "\n") {
		if v, ok := strings.CutPrefix(line, "endpoint="); ok {
			if ap, err := netip.ParseAddrPort(v); err == nil {
				endpoint = ap.Addr()
			}
		}
	}
	if !endpoint.Is4() {
		return fmt.Errorf("awg: server address %v is not IPv4", endpoint)
	}
	// the real default route, before ours exists
	family := winipcfg.AddressFamily(windows.AF_INET)
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return fmt.Errorf("awg: routes: %w", err)
	}
	var via *winipcfg.MibIPforwardRow2
	best := ^uint32(0)
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		metric := r.Metric
		if ipif, err := r.InterfaceLUID.IPInterface(family); err == nil {
			metric += ipif.Metric
		}
		if metric < best {
			best, via = metric, r
		}
	}
	if via == nil {
		return fmt.Errorf("awg: no default route")
	}
	realLUID, gateway := via.InterfaceLUID, via.NextHop.Addr()

	tdev, err := tun.CreateTUN(WinAwgName, 1280)
	if err != nil {
		return fmt.Errorf("awg adapter: %w", err)
	}
	luid := winipcfg.LUID(tdev.(*tun.NativeTun).LUID())
	fail := func(what string, err error) error {
		tdev.Close()
		return fmt.Errorf("awg %s: %w", what, err)
	}
	addr, err := netip.ParseAddr(AwgAddress(user))
	if err != nil {
		return fail("address", err)
	}
	if err := luid.SetIPAddresses([]netip.Prefix{netip.PrefixFrom(addr, 32)}); err != nil {
		return fail("address", err)
	}
	if ipif, err := luid.IPInterface(family); err == nil {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 1
		ipif.NLMTU = 1280
		ipif.Set()
	}
	hostRoute := netip.PrefixFrom(endpoint, 32)
	if err := realLUID.AddRoute(hostRoute, gateway, 0); err != nil && err != windows.ERROR_OBJECT_ALREADY_EXISTS {
		return fail("server route", err)
	}
	cleanup := func() { realLUID.DeleteRoute(hostRoute, gateway) }
	zero := netip.IPv4Unspecified()
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := luid.AddRoute(netip.MustParsePrefix(half), zero, 0); err != nil {
			cleanup()
			return fail("route", err)
		}
	}
	dns := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}
	if err := luid.SetDNS(family, dns, nil); err != nil {
		cleanup()
		return fail("dns", err)
	}
	if err := awgOnLocked(tdev, uapi, awgPortsOf(serverJSON)); err != nil {
		cleanup()
		return err
	}
	extraStop = cleanup
	return nil
}
