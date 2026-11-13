package pvcore

import (
	"fmt"
	"testing"
	"time"
)

func TestAwgHealth(t *testing.T) {
	state := func(rx, tx int64) string {
		return fmt.Sprintf("public_key=ab\nlast_handshake_time_sec=%d\nrx_bytes=%d\ntx_bytes=%d\n",
			time.Now().Add(-30*time.Second).Unix(), rx, tx)
	}
	awgRx, awgTx = -1, -1
	if awgHealth(state(1000, 1000)) < 0 {
		t.Fatal("first check with a fresh handshake is healthy")
	}
	if awgHealth(state(50000, 60000)) < 0 {
		t.Fatal("data both ways is healthy")
	}
	if awgHealth(state(50000, 200100)) < 0 {
		t.Fatal("idle (keepalives only) is healthy")
	}
	if awgHealth("last_handshake_time_sec=0\n") >= 0 {
		t.Fatal("no handshake is not healthy")
	}
}
