package pvdiff

import (
	"bytes"
	"math/rand"
	"testing"
)

func mutate(r *rand.Rand, b []byte) []byte {
	out := append([]byte(nil), b...)
	for k := 0; k < 40; k++ {
		if len(out) == 0 {
			break
		}
		i := r.Intn(len(out))
		switch r.Intn(3) {
		case 0: // change a few bytes
			for j := i; j < i+r.Intn(20) && j < len(out); j++ {
				out[j] ^= byte(r.Intn(255) + 1)
			}
		case 1: // insert
			ins := make([]byte, r.Intn(300))
			r.Read(ins)
			out = append(out[:i], append(ins, out[i:]...)...)
		case 2: // delete
			j := i + r.Intn(300)
			if j > len(out) {
				j = len(out)
			}
			out = append(out[:i], out[j:]...)
		}
	}
	return out
}

func TestRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for _, n := range []int{0, 1, 2, 3, 100, 5000, 300000} {
		old := make([]byte, n)
		r.Read(old)
		for i := 0; i < n/3; i++ { // some repetition, like real binaries
			old[i] = old[i%97]
		}
		news := [][]byte{nil, {1}, old}
		if n > 0 {
			news = append(news, mutate(r, old))
		}
		for _, nw := range news {
			d := Diff(old, nw)
			got := Apply(old, d)
			if !bytes.Equal(got, nw) {
				t.Fatalf("n=%d: round trip differs (%d vs %d bytes)", n, len(got), len(nw))
			}
			if n == 300000 && len(nw) > 1000 && len(d.Extra) > len(nw)/10 {
				t.Fatalf("delta too big: %d extra bytes of %d", len(d.Extra), len(nw))
			}
		}
	}
}
