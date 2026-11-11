//go:build !windows

package pvcore

import (
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

func closeFd(fd int) { syscall.Close(fd) }

func tunFromFd(fd int) (tun.Device, error) {
	d, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	return d, err
}
