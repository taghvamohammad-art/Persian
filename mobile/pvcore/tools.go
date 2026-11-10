//go:build tools

package pvcore

// keeps golang.org/x/mobile in go.mod: gomobile bind needs it
import _ "golang.org/x/mobile/bind"
