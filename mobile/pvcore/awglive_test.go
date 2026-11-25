package pvcore

import (
	"os"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// fakeTun: packets "from the apps" come from in; what the device writes is counted.
type fakeTun struct {
	in      chan []byte
	written int
	events  chan tun.Event
}

func (f *fakeTun) File() *os.File { return nil }
func (f *fakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	p, ok := <-f.in
	if !ok {
		return 0, os.ErrClosed
	}
	sizes[0] = copy(bufs[0][offset:], p)
	return 1, nil
}
func (f *fakeTun) Write(bufs [][]byte, offset int) (int, error) {
	f.written += len(bufs)
	return len(bufs), nil
}
func (f *fakeTun) MTU() (int, error)        { return 1280, nil }
func (f *fakeTun) Name() (string, error)    { return "fake", nil }
func (f *fakeTun) Events() <-chan tun.Event { return f.events }
func (f *fakeTun) BatchSize() int           { return 1 }
func (f *fakeTun) Close() error             { return nil }

func reply(req []byte) []byte {
	r := append([]byte(nil), req...)
	copy(r[12:16], req[16:20])
	copy(r[16:20], req[12:16])
	r[20] = 0 // echo reply
	return r
}

func TestLivePing(t *testing.T) {
	f := &fakeTun{in: make(chan []byte, 4), events: make(chan tun.Event, 1)}
	lt := newLiveTun(f, "25g00001")
	if !lt.src.IsValid() {
		t.Fatal("no tunnel address")
	}
	bufs := [][]byte{make([]byte, 2000)}
	sizes := []int{0}

	// the "device": reads, and answers our pings when answer is set
	answer := make(chan bool, 1)
	answer <- true
	go func() {
		on := true
		for {
			n, err := lt.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			select {
			case on = <-answer:
			default:
			}
			p := append([]byte(nil), bufs[0][:sizes[0]]...)
			if n == 1 && len(p) >= 28 && p[9] == 1 && on {
				lt.Write([][]byte{reply(p)}, 0)
			}
		}
	}()
	stop := make(chan struct{})
	defer close(stop)
	go func() { // the apps keep sending
		for {
			select {
			case <-stop:
				return
			case f.in <- []byte("x"):
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	if r := lt.ping(2 * time.Second); r != pingOK {
		t.Fatalf("answered ping: %v", r)
	}
	if f.written != 0 {
		t.Fatal("our reply reached the system")
	}
	answer <- false
	time.Sleep(60 * time.Millisecond)
	if r := lt.ping(time.Second); r != pingLost {
		t.Fatalf("unanswered ping: %v", r)
	}
}

func TestLivePingIdle(t *testing.T) {
	f := &fakeTun{in: make(chan []byte), events: make(chan tun.Event, 1)}
	lt := newLiveTun(f, "25g00001")
	go func() {
		bufs := [][]byte{make([]byte, 2000)}
		lt.Read(bufs, []int{0}, 0) // blocks: no packets from the apps
	}()
	time.Sleep(50 * time.Millisecond)
	// the reader is blocked inside the inner Read: the ping cannot leave
	if r := lt.ping(300 * time.Millisecond); r != pingNotSent {
		t.Fatalf("idle phone: %v", r)
	}
}
