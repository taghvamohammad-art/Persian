//go:build tools

package pvcore

// keeps golang.org/x/mobile (and gomobile's own dependencies) in go.mod:
// gomobile bind needs them
import (
	_ "golang.org/x/mobile/bind"
	_ "golang.org/x/mobile/cmd/gobind"
	_ "golang.org/x/mobile/cmd/gomobile"
)
