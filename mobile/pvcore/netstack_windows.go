package pvcore

import "errors"

// Windows uses Xray's own TUN inbound (see windows.go), not this bridge.
func startNetstack(fd, mtu, socksPort int) error {
	return errors.New("not on Windows")
}

func stopNetstack() {}
