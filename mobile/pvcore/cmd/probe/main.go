// probe: tries every protocol of a Linux server like the app does (CI and support).
package main

import (
	"flag"
	"fmt"
	"os"

	"persianvpn/mobile/pvcore"
)

func main() {
	entry := flag.String("entry", "", "server entry JSON file")
	user := flag.String("user", "", "username")
	pass := flag.String("pass", "", "password")
	timeout := flag.Int("timeout", 8000, "milliseconds")
	flag.Parse()
	b, err := os.ReadFile(*entry)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	res := pvcore.Probe(string(b), *user, *pass, *timeout)
	fmt.Println(res)
	fmt.Println("best:", pvcore.Best(res))
}
