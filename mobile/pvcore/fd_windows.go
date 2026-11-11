//go:build windows

package pvcore

import (
	"errors"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// Windows has no TUN descriptors: StartWindows uses Xray's own Wintun inbound.
func closeFd(fd int) {}

func tunFromFd(fd int) (tun.Device, error) {
	return nil, errors.New("not on Windows")
}
