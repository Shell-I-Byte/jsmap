package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shell-I-Byte/jsmap/internal/jsmap"
)

func TestCLI(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.js"), []byte(`fetch('/api?password=SECRET')`), 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if code := run([]string{"--root", root}, &out, &stderr); code != 0 {
		t.Fatalf("code %d: %s", code, stderr.String())
	}
	var report map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "SECRET") || report["schema_version"] != "jsmap.result/v1" {
		t.Fatal("JSON privacy/schema violation")
	}
	out.Reset()
	stderr.Reset()
	if code := run([]string{"--version"}, &out, &stderr); code != 0 || strings.TrimSpace(out.String()) != jsmap.Version {
		t.Fatalf("version: %s", out.String())
	}
}
func TestNoLogInjection(t *testing.T) {
	input := "--bogus\nFORGED-CI-OK\x1b[31m"
	for _, args := range [][]string{{input}, {"--root", "/nonexistent\nFAKE-LOG"}, {"--root"}} {
		var out, errOut bytes.Buffer
		code := run(args, &out, &errOut)
		if code == 0 {
			t.Fatal("invalid CLI accepted")
		}
		if strings.Contains(errOut.String(), "FORGED") || strings.Contains(errOut.String(), "FAKE-LOG") || strings.Contains(errOut.String(), "\x1b") {
			t.Fatalf("injection via stderr: %q", errOut.String())
		}
		if out.Len() != 0 {
			t.Fatalf("unexpected stdout: %q", out.String())
		}
	}
}

func TestHelpExitCodeAndSafeOutput(t *testing.T) {
	for _, help := range []string{"-h", "-help", "--help"} {
		var out, errOut bytes.Buffer
		code := run([]string{help}, &out, &errOut)
		if code != 0 || !strings.Contains(out.String(), "Usage: jsmap") || errOut.Len() != 0 {
			t.Fatalf("help %q: code=%d stdout=%q stderr=%q", help, code, out.String(), errOut.String())
		}
	}
	var out, errOut bytes.Buffer
	code := run([]string{"--unsupported\nLOG-FORGED"}, &out, &errOut)
	if code != 2 || out.Len() != 0 || strings.Contains(errOut.String(), "LOG-FORGED") {
		t.Fatalf("invalid CLI accepted or reflected: code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}
