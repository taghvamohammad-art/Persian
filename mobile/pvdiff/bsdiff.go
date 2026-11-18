// Package pvdiff makes bsdiff deltas (the BSDIFF40 algorithm of Colin
// Percival's bsdiff 4.3, the one Python's bsdiff4 uses) for the phone
// version of the release tool, where bsdiff4 is not available. It returns
// the three raw streams; the caller (tools/release_tool/apkdelta.py)
// compresses them and writes the BSDIFF40 file, so APK updates published
// from the phone are as small as those from Windows.
//
// The suffix array comes from Go's own index/suffixarray code (sais.go),
// with 32-bit entries: about 5 bytes of memory per byte of the old file.
package pvdiff

import "bytes"

// Delta: control triples (add, copy, seek) and the diff / extra streams.
type Delta struct {
	Ctrl  []int64
	Diff  []byte
	Extra []byte
}

func suffixArray(old []byte) []int32 {
	sa := make([]int32, len(old))
	if len(old) > 0 {
		text_32(old, sa)
	}
	return sa
}

func matchlen(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// search: the longest match of target in old, through the suffix array.
func search(sa []int32, old, target []byte) (pos, n int) {
	st, en := 0, len(sa)-1
	for en-st >= 2 {
		x := st + (en-st)/2
		suf := old[sa[x]:]
		m := len(suf)
		if len(target) < m {
			m = len(target)
		}
		if bytes.Compare(suf[:m], target[:m]) < 0 {
			st = x
		} else {
			en = x
		}
	}
	x := matchlen(old[sa[st]:], target)
	y := matchlen(old[sa[en]:], target)
	if x > y {
		return int(sa[st]), x
	}
	return int(sa[en]), y
}

// Diff computes the delta from old to new.
func Diff(old, new []byte) Delta {
	var d Delta
	oldsize, newsize := len(old), len(new)
	if oldsize == 0 {
		if newsize > 0 {
			d.Ctrl = []int64{0, int64(newsize), 0}
			d.Extra = append([]byte(nil), new...)
		}
		return d
	}
	sa := suffixArray(old)
	d.Diff = make([]byte, 0, newsize/4)
	d.Extra = make([]byte, 0, newsize/16)

	var scan, length, pos, lastscan, lastpos, lastoffset int
	for scan < newsize {
		oldscore := 0
		scan += length
		scsc := scan
		for ; scan < newsize; scan++ {
			pos, length = search(sa, old, new[scan:])
			for ; scsc < scan+length; scsc++ {
				if scsc+lastoffset < oldsize && old[scsc+lastoffset] == new[scsc] {
					oldscore++
				}
			}
			if (length == oldscore && length != 0) || length > oldscore+8 {
				break
			}
			if scan+lastoffset < oldsize && old[scan+lastoffset] == new[scan] {
				oldscore--
			}
		}
		if length != oldscore || scan == newsize {
			s, sf, lenf := 0, 0, 0
			for i := 0; lastscan+i < scan && lastpos+i < oldsize; {
				if old[lastpos+i] == new[lastscan+i] {
					s++
				}
				i++
				if s*2-i > sf*2-lenf {
					sf, lenf = s, i
				}
			}
			lenb := 0
			if scan < newsize {
				s, sb := 0, 0
				for i := 1; scan >= lastscan+i && pos >= i; i++ {
					if old[pos-i] == new[scan-i] {
						s++
					}
					if s*2-i > sb*2-lenb {
						sb, lenb = s, i
					}
				}
			}
			if lastscan+lenf > scan-lenb {
				overlap := (lastscan + lenf) - (scan - lenb)
				s, ss, lens := 0, 0, 0
				for i := 0; i < overlap; i++ {
					if new[lastscan+lenf-overlap+i] == old[lastpos+lenf-overlap+i] {
						s++
					}
					if new[scan-lenb+i] == old[pos-lenb+i] {
						s--
					}
					if s > ss {
						ss, lens = s, i+1
					}
				}
				lenf += lens - overlap
				lenb -= lens
			}
			for i := 0; i < lenf; i++ {
				d.Diff = append(d.Diff, new[lastscan+i]-old[lastpos+i])
			}
			extra := (scan - lenb) - (lastscan + lenf)
			d.Extra = append(d.Extra, new[lastscan+lenf:lastscan+lenf+extra]...)
			d.Ctrl = append(d.Ctrl, int64(lenf), int64(extra), int64((pos-lenb)-(lastpos+lenf)))
			lastscan, lastpos, lastoffset = scan-lenb, pos-lenb, pos-scan
		}
	}
	return d
}

// Apply rebuilds new from old and a delta (tests).
func Apply(old []byte, d Delta) []byte {
	var out []byte
	op, di, ei := 0, 0, 0
	for i := 0; i+2 < len(d.Ctrl); i += 3 {
		add, cp, seek := int(d.Ctrl[i]), int(d.Ctrl[i+1]), int(d.Ctrl[i+2])
		for j := 0; j < add; j++ {
			var o byte
			if op+j >= 0 && op+j < len(old) {
				o = old[op+j]
			}
			out = append(out, d.Diff[di+j]+o)
		}
		di += add
		op += add
		out = append(out, d.Extra[ei:ei+cp]...)
		ei += cp
		op += seek
	}
	return out
}
