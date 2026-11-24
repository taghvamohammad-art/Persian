package pvcore

import (
	"fmt"
	"sync"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/device"
)

// On some networks an AmneziaWG flow works for a minute or two and is then
// cut: the rekey handshake (due every 2 minutes) gets no answer and data
// stops when the old keys expire (3 minutes). The server also answers on a
// range of other UDP ports (redirected to its real one), so when a rekey is
// late the tunnel moves to another pair of ports - a new flow for the
// network - and the handshake goes through there, without the tunnel going
// down. The app's socket is outside the VPN (Android: the app is excluded;
// Windows: a host route to the server), so a new one is too.

// awgRoamAfter: how late a handshake must be before trying another port
// (WireGuard starts the rekey at 120s and retries every 5s).
const awgRoamAfter = 130 * time.Second

// awgRoamEvery: time given to each port before the next.
const awgRoamEvery = 12 * time.Second

// what the roaming did, for the app's test screen
var (
	roamMu   sync.Mutex
	roamPort int
	roamLog  []string
)

func roamNote(port int, msg string) {
	roamMu.Lock()
	defer roamMu.Unlock()
	roamPort = port
	if msg != "" {
		roamLog = append(roamLog, time.Now().Format("15:04:05")+" "+msg)
		if len(roamLog) > 12 {
			roamLog = roamLog[len(roamLog)-12:]
		}
	}
}

func roamState() (int, []string) {
	roamMu.Lock()
	defer roamMu.Unlock()
	return roamPort, append([]string(nil), roamLog...)
}

type awgRoam struct {
	pub   string // peer public key (hex), as in the UAPI
	host  string
	ports []int // the main port first
	cur   int   // index into ports
}

// awgPortsOf: the AmneziaWG main port and its hop ports of a server entry.
func awgPortsOf(serverJSON string) []int {
	s, err := parseServer(serverJSON)
	if err != nil {
		return nil
	}
	p, err := s.protocol("amneziawg")
	if err != nil {
		return nil
	}
	return awgPortList(p.Port, p.Hop)
}

func awgPortList(main int, hop []int) []int {
	out := []int{main}
	if len(hop) != 2 || hop[0] <= 0 || hop[1] < hop[0] || hop[1] > 65535 || hop[1]-hop[0] > 1000 {
		return out
	}
	for x := hop[0]; x <= hop[1]; x++ {
		if x != main {
			out = append(out, x)
		}
	}
	return out
}

func newAwgRoam(uapi string, ports []int) *awgRoam {
	roamMu.Lock()
	roamPort, roamLog = 0, nil
	if len(ports) > 0 {
		roamPort = ports[0]
	}
	roamMu.Unlock()
	if len(ports) < 2 {
		return nil
	}
	r := &awgRoam{ports: ports}
	for _, line := range strings.Split(uapi, "\n") {
		if v, ok := strings.CutPrefix(line, "public_key="); ok {
			r.pub = v
		} else if v, ok := strings.CutPrefix(line, "endpoint="); ok {
			if h, _, err := net.SplitHostPort(v); err == nil {
				r.host = h
			}
		}
	}
	if r.pub == "" || r.host == "" {
		return nil
	}
	return r
}

// next: the port to try after the current one - another hop port at random,
// and the main port again every few tries.
func (r *awgRoam) next(tries int) int {
	if tries%4 == 3 || len(r.ports) == 1 {
		return 0
	}
	i := 1 + rand.Intn(len(r.ports)-1)
	if i == r.cur && len(r.ports) > 2 {
		i = 1 + (i % (len(r.ports) - 1))
	}
	return i
}

func (r *awgRoam) set(dev *device.Device, i int) error {
	r.cur = i
	ep := net.JoinHostPort(r.host, strconv.Itoa(r.ports[i]))
	// a new local port too (listen_port=0 rebinds to a random one): a new
	// flow from both ends, and no clash on the server with the conntrack
	// entry of the old flow (same client port to the main port)
	return dev.IpcSet(fmt.Sprintf("listen_port=0\npublic_key=%s\nupdate_only=true\nendpoint=%s\n", r.pub, ep))
}

func (r *awgRoam) run(dev *device.Device) {
	tries, last := 0, time.Time{}
	for {
		time.Sleep(3 * time.Second)
		mu.Lock()
		alive := awgDev == dev
		mu.Unlock()
		if !alive {
			return
		}
		state, err := dev.IpcGet()
		if err != nil {
			return
		}
		age, ok := handshakeAge(state)
		if !ok || age < awgRoamAfter {
			if tries > 0 && ok {
				roamNote(r.ports[r.cur], fmt.Sprintf("handshake ok on port %d", r.ports[r.cur]))
			}
			tries = 0
			continue
		}
		if time.Since(last) < awgRoamEvery {
			continue
		}
		i := r.next(tries)
		tries++
		last = time.Now()
		if err := r.set(dev, i); err == nil {
			roamNote(r.ports[i], fmt.Sprintf("handshake %ds old, trying port %d", int(age.Seconds()), r.ports[i]))
		}
	}
}

func handshakeAge(state string) (time.Duration, bool) {
	for _, line := range strings.Split(state, "\n") {
		if v, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
			sec, err := strconv.ParseInt(v, 10, 64)
			if err != nil || sec <= 0 {
				return 0, false
			}
			return time.Since(time.Unix(sec, 0)), true
		}
	}
	return 0, false
}
