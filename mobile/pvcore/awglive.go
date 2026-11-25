package pvcore

import (
	"net/netip"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun"
)

// liveTun wraps the running AmneziaWG tunnel's TUN so the health check can
// send a ping through it, next to the apps' traffic, and take the reply out
// before it reaches the system. A network that lets the handshakes through
// but drops or throttles the data shows here: the byte counters alone
// cannot tell such a tunnel from a quiet one.
//
// The ping is handed to the device on its next read, i.e. after the next
// packet of the apps; on an idle phone it may not go out at all, and then
// nothing is concluded.
type liveTun struct {
	tun.Device
	src     netip.Addr
	out     chan []byte
	sent    chan struct{}
	replies chan uint16
	seqMu   sync.Mutex
	seq     uint16
}

type pingResult int

const (
	pingOK      pingResult = iota
	pingLost               // went out, no answer
	pingNotSent            // nothing else was sent meanwhile: no verdict
)

const liveID = 0x7077

func newLiveTun(inner tun.Device, user string) *liveTun {
	src, _ := netip.ParseAddr(AwgAddress(user))
	return &liveTun{Device: inner, src: src, out: make(chan []byte, 4), sent: make(chan struct{}, 4),
		replies: make(chan uint16, 8)}
}

func (t *liveTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case p := <-t.out: // our ping, between two reads of the apps' packets
		sizes[0] = copy(bufs[0][offset:], p)
		select {
		case t.sent <- struct{}{}:
		default:
		}
		return 1, nil
	default:
	}
	return t.Device.Read(bufs, sizes, offset)
}

func (t *liveTun) Write(bufs [][]byte, offset int) (int, error) {
	keep := bufs[:0:0]
	for _, b := range bufs {
		if seq, ok := echoReplySeq(b[offset:], liveID); ok {
			select {
			case t.replies <- seq:
			default:
			}
			continue
		}
		keep = append(keep, b)
	}
	if len(keep) == 0 {
		return len(bufs), nil
	}
	if _, err := t.Device.Write(keep, offset); err != nil {
		return 0, err
	}
	return len(bufs), nil
}

// ping: one full-size echo to the server's tunnel address (it answers
// without the internet).
func (t *liveTun) ping(wait time.Duration) pingResult {
	if !t.src.IsValid() {
		return pingOK
	}
	t.seqMu.Lock()
	t.seq++
	seq := t.seq
	t.seqMu.Unlock()
	for len(t.sent) > 0 {
		<-t.sent
	}
	select {
	case t.out <- echoRequest(t.src, pingTargets[0], liveID, seq, awgProbeBig):
	default:
		return pingNotSent
	}
	deadline := time.After(wait)
	went := false
	for {
		select {
		case <-t.sent:
			went = true
		case got := <-t.replies:
			if got == seq {
				return pingOK
			}
		case <-deadline:
			if !went {
				select {
				case <-t.out: // take it back: it never left
				default:
				}
				return pingNotSent
			}
			return pingLost
		}
	}
}
