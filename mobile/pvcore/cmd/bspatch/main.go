// bspatch: the app updater's BSDIFF40 applier on its own (CI cross-check
// against Python bsdiff4, which the release tool uses to make patches).
package main

import (
	"fmt"
	"os"

	"persianvpn/mobile/pvcore"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: bspatch OLD PATCH NEW")
		os.Exit(2)
	}
	if err := pvcore.ApplyBsdiff(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
