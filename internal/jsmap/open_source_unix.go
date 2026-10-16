//go:build linux || darwin

package jsmap

import (
	"os"
	"syscall"
)

// openSource opens the last path component without following a symlink or
// blocking on a FIFO swapped into place after directory traversal. The caller
// must still verify regular file type and identity through the descriptor.
// This does not protect against hostile changes to ancestor directories.
func openSource(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
