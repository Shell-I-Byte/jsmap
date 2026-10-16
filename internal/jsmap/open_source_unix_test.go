//go:build linux || darwin

package jsmap

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestOpenSourceCannotBlockOnFIFOOrFollowSymlink(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "normal.js")
	fifo := filepath.Join(root, "named-pipe.js")
	link := filepath.Join(root, "symlink.js")
	if err := os.WriteFile(regular, []byte("fetch('/safe')"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, link} {
		// An O_NONBLOCK open must return without a FIFO writer. A bounded
		// wait ensures a future regression fails the test rather than hanging CI.
		result := make(chan error, 1)
		go func(input string) {
			f, err := openSource(input)
			if err == nil {
				defer f.Close()
				var info os.FileInfo
				info, err = f.Stat()
				if err == nil && info.Mode().IsRegular() {
					err = fmt.Errorf("opened nonregular input as regular file")
				}
				if err == nil && input == link {
					err = fmt.Errorf("opened symlink")
				}
			}
			result <- err
		}(path)
		select {
		case err := <-result:
			if err != nil && (err.Error() == "opened symlink" || err.Error() == "opened nonregular input as regular file") {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatalf("openSource blocked on %s", path)
		}
	}
	f, err := openSource(regular)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("regular file not readable: %v", err)
	}
}
