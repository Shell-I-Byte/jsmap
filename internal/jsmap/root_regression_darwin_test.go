//go:build darwin

package jsmap

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestDarwinPinnedRootAndAncestor(t *testing.T) {
	d := t.TempDir()
	root := filepath.Join(d, "root")
	other := filepath.Join(d, "other")
	for _, p := range []string{root, other} {
		if e := os.MkdirAll(filepath.Join(p, "nested"), 0700); e != nil {
			t.Fatal(e)
		}
	}
	os.WriteFile(filepath.Join(root, "nested", "a.js"), []byte("original"), 0600)
	os.WriteFile(filepath.Join(other, "nested", "a.js"), []byte("foreign"), 0600)
	st, _ := os.Stat(root)
	r, e := openScanRoot(root, st)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if e = os.Rename(root, root+"-moved"); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(other, root); e != nil {
		t.Fatal(e)
	}
	f, e := openSourceInRoot(r, root, "nested/a.js")
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(f)
	f.Close()
	if e != nil || string(b) != "original" {
		t.Fatalf("root changed: %q %v", b, e)
	}
	os.Symlink(other, filepath.Join(root+"-moved", "alias"))
	if f, e := openSourceInRoot(r, root, "alias/nested/a.js"); e == nil {
		f.Close()
		t.Fatal("accepted ancestor symlink")
	}
}

func TestDarwinRootAncestorRejected(t *testing.T) {
	d := t.TempDir()
	os.MkdirAll(filepath.Join(d, "real", "nested"), 0700)
	os.Symlink(filepath.Join(d, "real"), filepath.Join(d, "alias"))
	expected, _ := os.Stat(filepath.Join(d, "real", "nested"))
	r, e := openScanRoot(filepath.Join(d, "alias", "nested"), expected)
	if e == nil {
		r.Close()
		t.Fatal("accepted root ancestor symlink")
	}
}
