//go:build linux

// tuntest: drives the app engine on a real TUN, the way the Android app
// does (CI). Commands on stdin, one per line:
//
//	open NAME        create TUN device NAME (its descriptor becomes "current")
//	start KIND       start KIND (pool | amneziawg | an Xray type) on the current descriptor
//	stop             stop the engine
//	check            the health check the app's watchdog runs
//
// Every command answers one line: "@@ ok ..." or "@@ err ..." (Xray logs go to stdout too).
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"persianvpn/mobile/pvcore"
)

func openTun(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return -1, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func main() {
	entry := flag.String("entry", "", "server entry JSON file")
	user := flag.String("user", "", "username")
	pass := flag.String("pass", "", "password")
	flag.Parse()
	b, err := os.ReadFile(*entry)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	server := string(b)
	var parsed struct {
		Protocols []struct {
			Type string `json:"type"`
		} `json:"protocols"`
	}
	json.Unmarshal(b, &parsed)
	fd := -1
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) == 0 {
			continue
		}
		var err error
		out := ""
		switch f[0] {
		case "open":
			fd, err = openTun(f[1])
			out = fmt.Sprint(fd)
		case "start":
			switch kind := f[1]; kind {
			case "pool":
				var list []map[string]any
				for _, p := range parsed.Protocols {
					if p.Type != "amneziawg" && p.Type != "vless-dns" {
						list = append(list, map[string]any{"server": json.RawMessage(b), "kind": p.Type})
					}
				}
				j, _ := json.Marshal(list)
				err = pvcore.StartXrayPool(string(j), *user, *pass, fd, 1500)
			case "amneziawg":
				err = pvcore.StartAwg(server, *user, *pass, fd)
			default:
				err = pvcore.StartXray(server, kind, *user, *pass, fd, 1500)
			}
		case "stop":
			pvcore.Stop()
		case "check":
			out = fmt.Sprint(pvcore.Check(5000))
		default:
			err = fmt.Errorf("unknown command")
		}
		if err != nil {
			fmt.Println("@@ err", err)
		} else {
			fmt.Println("@@ ok", out)
		}
	}
}
