//go:build linux

package jsmap

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// openScanRoot pins the selected root directory object across name changes.
// The original root pathname itself cannot be replaced with a symlink during
// validation without failing the expected-identity check.
func openScanRoot(path string, expected os.FileInfo) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	root := os.NewFile(uintptr(fd), path)
	info, err := root.Stat()
	if err != nil || !info.IsDir() || !os.SameFile(info, expected) {
		root.Close()
		return nil, errors.New("root changed")
	}
	return root, nil
}

// openSourceInRoot resolves every relative component against a fixed root
// directory descriptor. In particular, O_NOFOLLOW is needed on *each* parent
// directory: merely protecting the final file does not stop symlink swaps.
// A concurrently renamed directory already opened via a descriptor and Linux
// bind mounts are outside this limited defense (see docs/LIMITATIONS.md).
func openSourceInRoot(root *os.File, _ string, rel string) (*os.File, error) {
	if rel == "" || filepath.IsAbs(rel) || rel == "." || filepath.Clean(rel) != rel {
		return nil, errors.New("invalid relative source")
	}
	parts := strings.Split(rel, string(os.PathSeparator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, errors.New("invalid relative source")
		}
	}
	rootFD := int(root.Fd())
	current := rootFD
	for _, part := range parts[:len(parts)-1] {
		next, err := syscall.Openat(current, part, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if current != rootFD {
			syscall.Close(current)
		}
		if err != nil {
			return nil, err
		}
		current = next
	}
	leaf, err := syscall.Openat(current, parts[len(parts)-1], syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if current != rootFD {
		syscall.Close(current)
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(leaf), rel), nil
}
