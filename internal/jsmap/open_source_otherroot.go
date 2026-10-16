//go:build !linux && !darwin

package jsmap

import (
	"errors"
	"os"
	"path/filepath"
)

// Non-Linux filesystem races remain a release blocker; this root handle
// checks object identity but source open is still pathname based.
func openScanRoot(path string, expected os.FileInfo) (*os.File, error) {
	fh, err := openSource(path)
	if err != nil {
		return nil, err
	}
	actual, err := fh.Stat()
	if err != nil || !actual.IsDir() || !os.SameFile(expected, actual) {
		fh.Close()
		return nil, errors.New("root changed")
	}
	return fh, nil
}
func openSourceInRoot(_ *os.File, root, rel string) (*os.File, error) {
	return openSource(filepath.Join(root, rel))
}
