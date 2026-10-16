//go:build linux

package jsmap

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfinedRootOpenRejectsParentSymlinkAndTraversal(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	outside := filepath.Join(parent, "out")
	for _, p := range []string{filepath.Join(root, "safe"), outside} {
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	safe := filepath.Join(root, "safe", "a.js")
	external := filepath.Join(outside, "a.js")
	if err := os.WriteFile(safe, []byte("fetch('/safe')"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(external, []byte("fetch('/outside')"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "redirect")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := openScanRoot(root, info)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	file, err := openSourceInRoot(pinned, root, "safe/a.js")
	if err != nil {
		t.Fatalf("legitimate file rejected: %v", err)
	}
	data, err := io.ReadAll(file)
	file.Close()
	if err != nil || string(data) != "fetch('/safe')" {
		t.Fatalf("wrong safe bytes: %q %v", data, err)
	}
	for _, rel := range []string{"redirect/a.js", "safe/../redirect/a.js", "../out/a.js", "/a.js", ".", ""} {
		f, err := openSourceInRoot(pinned, root, rel)
		if f != nil {
			f.Close()
		}
		if err == nil {
			t.Fatalf("unexpected source open for %q", rel)
		}
	}
	// Rename the selected root away and place a symlink at its old path.
	// The original root descriptor must remain bound to the original data.
	renamed := filepath.Join(parent, "moved")
	if err := os.Rename(root, renamed); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, root); err != nil {
		t.Fatal(err)
	}
	pinnedFile, err := openSourceInRoot(pinned, root, "safe/a.js")
	if err != nil {
		t.Fatalf("lost original root descriptor: %v", err)
	}
	content, err := io.ReadAll(pinnedFile)
	pinnedFile.Close()
	if err != nil || !strings.Contains(string(content), "'/safe'") {
		t.Fatalf("wrong root content %q %v", content, err)
	}
	newInfo, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := openScanRoot(root, newInfo); err == nil {
		f.Close()
		t.Fatal("symlink root accepted")
	}
}
