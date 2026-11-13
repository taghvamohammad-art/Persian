package pvcore

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// testdata: a BSDIFF40 patch with diff, extra and backward seeks
// (made by tools/release_tool's test encoder).
func TestApplyBsdiff(t *testing.T) {
	out := filepath.Join(t.TempDir(), "new")
	if err := ApplyBsdiff("testdata/bsdiff.old", "testdata/bsdiff.patch", out); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	want, _ := os.ReadFile("testdata/bsdiff.new")
	if !bytes.Equal(got, want) {
		t.Fatalf("rebuilt file differs (%d vs %d bytes)", len(got), len(want))
	}
	bad := filepath.Join(t.TempDir(), "bad")
	if err := ApplyBsdiff("testdata/bsdiff.old", "testdata/bsdiff.new", bad); err == nil {
		t.Fatal("a file that is not a patch must be refused")
	}
	if _, err := os.Stat(bad); err == nil {
		t.Fatal("no output after a failure")
	}
}
