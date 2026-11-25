package pvcore

import (
	"strings"
	"testing"
)

func TestAwgPortList(t *testing.T) {
	if got := awgPortList(5000, nil); len(got) != 1 || got[0] != 5000 {
		t.Fatalf("no hop: %v", got)
	}
	got := awgPortList(5000, []int{6000, 6003})
	if len(got) != 5 || got[0] != 5000 || got[4] != 6003 {
		t.Fatalf("hop: %v", got)
	}
	if got := awgPortList(5000, []int{6000, 99999}); len(got) != 1 {
		t.Fatalf("bad hop accepted: %v", got)
	}
}

func TestAwgRoamFromUAPI(t *testing.T) {
	uapi := "private_key=aa\npublic_key=bb\nendpoint=1.2.3.4:5000\n"
	if newAwgRoam(uapi, []int{5000}) != nil {
		t.Fatal("roam without hop ports")
	}
	r := newAwgRoam(uapi, awgPortList(5000, []int{6000, 6009}))
	if r == nil || r.pub != "bb" || r.host != "1.2.3.4" {
		t.Fatalf("roam: %+v", r)
	}
	for tries := 0; tries < 40; tries++ {
		i := r.next(tries)
		if tries%4 == 3 && i != 0 {
			t.Fatalf("try %d should go back to the main port", tries)
		}
		if tries%4 != 3 && (i < 1 || i >= len(r.ports)) {
			t.Fatalf("try %d: index %d", tries, i)
		}
		r.cur = i
	}
}

func TestServerEntryHop(t *testing.T) {
	js := `{"name":"a","host":"1.2.3.4","type":"linux","protocols":[{"type":"amneziawg","port":5000,"hop":[6000,6001]}]}`
	if got := awgPortsOf(js); len(got) != 3 || got[0] != 5000 {
		t.Fatalf("ports: %v", got)
	}
}

func TestAwgStartPort(t *testing.T) {
	uapi := "private_key=aa\npublic_key=bb\nendpoint=1.2.3.4:5000\nallowed_ip=0.0.0.0/0\n"
	if awgHostOf(uapi) != "1.2.3.4" {
		t.Fatal("host")
	}
	if got := withAwgPort(uapi, "1.2.3.4", 6001); !strings.Contains(got, "endpoint=1.2.3.4:6001\nallowed_ip") {
		t.Fatalf("port: %q", got)
	}
	setAwgPort("1.2.3.4", 6001)
	defer setAwgPort("1.2.3.4", 0)
	if !strings.Contains(awgStartUAPI(uapi), "endpoint=1.2.3.4:6001") {
		t.Fatal("start not on the probed port")
	}
	r := newAwgRoam(uapi, awgPortList(5000, []int{6000, 6003}))
	if r.ports[r.cur] != 6001 {
		t.Fatalf("roam starts at %d", r.ports[r.cur])
	}
}
