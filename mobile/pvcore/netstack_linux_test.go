package pvcore

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// After the bridge stops, nothing may read from its old descriptor number:
// a socket that reuses the number must keep all of its data.
func TestNetstackStopFreesDescriptorSafely(t *testing.T) {
	for i := 0; i < 200; i++ {
		tun, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		if err := startNetstack(tun[0], 1500, 1); err != nil {
			mu.Unlock()
			t.Fatal(err)
		}
		mu.Unlock()
		old := tun[0]
		mu.Lock()
		stopNetstack()
		mu.Unlock()
		unix.Close(tun[1])

		// a new descriptor most likely gets the old number
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
		if err != nil {
			t.Fatal(err)
		}
		reader, writer := pair[0], pair[1]
		if pair[1] == old {
			reader, writer = pair[1], pair[0]
		}
		msg := []byte("must arrive")
		if _, err := unix.Write(writer, msg); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		unix.SetNonblock(reader, true)
		deadline := time.Now().Add(time.Second)
		got := false
		for time.Now().Before(deadline) {
			if n, err := unix.Read(reader, buf); err == nil && n == len(msg) {
				got = true
				break
			}
			time.Sleep(time.Millisecond)
		}
		unix.Close(pair[0])
		unix.Close(pair[1])
		if !got {
			t.Fatalf("round %d: data on a reused descriptor (%d) was taken by the stopped bridge", i, old)
		}
	}
}
