//go:build !linux && !darwin

package jsmap

import "os"

// On platforms without this Unix nonblocking open path, the fallback does not
// offer the same FIFO/symlink-swap protections. Release gating must test a
// platform-specific hardened implementation before claiming full parity.
func openSource(path string) (*os.File, error) { return os.Open(path) }
