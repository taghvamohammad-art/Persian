// libpvdiff.so: pvdiff.Diff for Python (ctypes) on the phone.
//
//	char *PvDiff(const char *old, long long oldLen, const char *new, long long newLen, long long *outLen)
//
// returns one malloc'ed buffer, little-endian:
// [n int64][n control numbers int64][diff length int64][diff][extra length int64][extra]
// to be released with PvFree.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"unsafe"

	"persianvpn/pvdiff"
)

func view(p *C.char, n C.longlong) []byte {
	if n <= 0 || p == nil {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(p)), int(n))
}

//export PvDiff
func PvDiff(old *C.char, oldLen C.longlong, nw *C.char, newLen C.longlong, outLen *C.longlong) *C.char {
	o, n := view(old, oldLen), view(nw, newLen)
	d := pvdiff.Diff(o, n)
	if !bytes.Equal(pvdiff.Apply(o, d), n) { // never hand out a wrong delta
		*outLen = 0
		return nil
	}
	size := 8 + 8*len(d.Ctrl) + 8 + len(d.Diff) + 8 + len(d.Extra)
	p := C.malloc(C.size_t(size))
	if p == nil {
		*outLen = 0
		return nil
	}
	buf := unsafe.Slice((*byte)(p), size)
	at := 0
	put := func(v int64) {
		binary.LittleEndian.PutUint64(buf[at:], uint64(v))
		at += 8
	}
	put(int64(len(d.Ctrl)))
	for _, v := range d.Ctrl {
		put(v)
	}
	put(int64(len(d.Diff)))
	at += copy(buf[at:], d.Diff)
	put(int64(len(d.Extra)))
	copy(buf[at:], d.Extra)
	*outLen = C.longlong(size)
	return (*C.char)(p)
}

//export PvFree
func PvFree(p *C.char) {
	C.free(unsafe.Pointer(p))
}

func main() {}
