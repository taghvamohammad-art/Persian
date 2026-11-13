package pvcore

import (
	"bufio"
	"compress/bzip2"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// ApplyBsdiff rebuilds a file from the old one and a BSDIFF40 patch (the
// format of bsdiff / Python bsdiff4) — used for app updates: only the bytes
// that changed travel. Streams: the old file is read where needed, the new
// one is written in order, so memory use stays small. The caller checks the
// result against the signed SHA-256.
func ApplyBsdiff(oldPath, patchPath, outPath string) error {
	pf, err := os.Open(patchPath)
	if err != nil {
		return err
	}
	defer pf.Close()
	var hdr [32]byte
	if _, err := io.ReadFull(pf, hdr[:]); err != nil {
		return fmt.Errorf("patch header: %w", err)
	}
	if string(hdr[:8]) != "BSDIFF40" {
		return errors.New("not a BSDIFF40 patch")
	}
	ctrlLen, diffLen, newSize := offtin(hdr[8:16]), offtin(hdr[16:24]), offtin(hdr[24:32])
	st, err := pf.Stat()
	if err != nil {
		return err
	}
	if ctrlLen < 0 || diffLen < 0 || newSize < 0 || 32+ctrlLen+diffLen > st.Size() || newSize > 1<<31 {
		return errors.New("bad patch header")
	}
	section := func(off, n int64) io.Reader {
		return bzip2.NewReader(bufio.NewReaderSize(io.NewSectionReader(pf, off, n), 64*1024))
	}
	ctrl := section(32, ctrlLen)
	diff := section(32+ctrlLen, diffLen)
	extra := section(32+ctrlLen+diffLen, st.Size()-32-ctrlLen-diffLen)

	old, err := os.Open(oldPath)
	if err != nil {
		return err
	}
	defer old.Close()
	ost, err := old.Stat()
	if err != nil {
		return err
	}
	oldSize := ost.Size()

	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(out, 256*1024)
	fail := func(e error) error {
		out.Close()
		os.Remove(outPath)
		return e
	}

	buf := make([]byte, 64*1024)
	obuf := make([]byte, 64*1024)
	var newPos, oldPos int64
	var c [24]byte
	for newPos < newSize {
		if _, err := io.ReadFull(ctrl, c[:]); err != nil {
			return fail(fmt.Errorf("patch control: %w", err))
		}
		x, y, z := offtin(c[0:8]), offtin(c[8:16]), offtin(c[16:24])
		if x < 0 || y < 0 || newPos+x+y > newSize {
			return fail(errors.New("bad patch control"))
		}
		// x bytes: old + diff
		for left := x; left > 0; {
			n := int64(len(buf))
			if n > left {
				n = left
			}
			if _, err := io.ReadFull(diff, buf[:n]); err != nil {
				return fail(fmt.Errorf("patch diff: %w", err))
			}
			// the old bytes at oldPos..oldPos+n (zero outside the old file)
			for i := range obuf[:n] {
				obuf[i] = 0
			}
			lo, hi := oldPos, oldPos+n
			if lo < 0 {
				lo = 0
			}
			if hi > oldSize {
				hi = oldSize
			}
			if hi > lo {
				if _, err := old.ReadAt(obuf[lo-oldPos:hi-oldPos], lo); err != nil && err != io.EOF {
					return fail(err)
				}
			}
			for i := int64(0); i < n; i++ {
				buf[i] += obuf[i]
			}
			if _, err := w.Write(buf[:n]); err != nil {
				return fail(err)
			}
			left -= n
			oldPos += n
			newPos += n
		}
		// y bytes: new data
		if _, err := io.CopyN(w, extra, y); err != nil {
			return fail(fmt.Errorf("patch extra: %w", err))
		}
		newPos += y
		oldPos += z
	}
	if err := w.Flush(); err != nil {
		return fail(err)
	}
	return out.Close()
}

// offtin: bsdiff's sign-magnitude little-endian int64.
func offtin(b []byte) int64 {
	v := int64(binary.LittleEndian.Uint64(b) & (1<<63 - 1))
	if b[7]&0x80 != 0 {
		v = -v
	}
	return v
}
