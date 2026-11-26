package pvcore

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// a host sending `rate` bytes per second (0: as fast as it can)
func speedServer(t *testing.T, rate int) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
		w.Header().Set("Content-Length", strconv.Itoa(n))
		chunk := make([]byte, 1024)
		for sent := 0; sent < n; sent += len(chunk) {
			if _, err := w.Write(chunk[:min(len(chunk), n-sent)]); err != nil {
				return
			}
			if rate > 0 {
				w.(http.Flusher).Flush()
				time.Sleep(time.Second * time.Duration(len(chunk)) / time.Duration(rate))
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func withSpeedURL(t *testing.T, srv *httptest.Server) {
	old := SpeedURL
	SpeedURL = srv.URL + "/?bytes=%d"
	t.Cleanup(func() { SpeedURL = old })
}

func TestSpeedFastPathEndsAtTheByteLimit(t *testing.T) {
	withSpeedURL(t, speedServer(t, 0))
	start := time.Now()
	kbps := speedVia(&http.Transport{}, 3*time.Second)
	if kbps < 1000 {
		t.Fatalf("fast path measured %d KB/s", kbps)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("a fast check took %v", time.Since(start))
	}
}

func TestSpeedThrottledPathIsSlowAndBounded(t *testing.T) {
	withSpeedURL(t, speedServer(t, 8_000)) // 8 KB/s, like the filtered server address
	start := time.Now()
	kbps := speedVia(&http.Transport{}, 2*time.Second)
	if kbps < 3 || kbps > 20 {
		t.Fatalf("throttled path measured %d KB/s", kbps)
	}
	if el := time.Since(start); el > 4*time.Second {
		t.Fatalf("the check ran %v, past its limit", el)
	}
}

func TestSpeedNothingComesIsMinusOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	withSpeedURL(t, srv)
	if kbps := speedVia(&http.Transport{}, time.Second); kbps != -1 {
		t.Fatalf("got %d", kbps)
	}
}

func TestSpeedRunningWithoutXray(t *testing.T) {
	if got := SpeedRunning(1); got != -2 {
		t.Fatalf("nothing running: %d", got)
	}
}
