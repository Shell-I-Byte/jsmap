package jsmap

import (
	"path/filepath"
	"testing"
)

// Annex B HTML-like comments in classic scripts must not become URL evidence.
func TestClassicHTMLLikeCommentsNeverBecomeEndpointEvidence(t *testing.T) {
	cases := []struct{ name, source string }{
		{"opening_at_line_start", "<!-- fetch('/fabricated-open');\nfetch('/real');\n"},
		{"opening_after_statement", "const a = 1; <!-- fetch('/fabricated-inline');\nfetch('/real');\n"},
		{"closing_at_line_start", "--> fetch('/fabricated-close');\nfetch('/real');\n"},
		{"closing_after_indentation", "\t--> fetch('/fabricated-indented');\nfetch('/real');\n"},
		{"ordinary_comments_control", "// fetch('/fabricated-line');\nfetch('/real');\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, dir, "sample.js", tc.source)
			r, err := Scan(dir)
			if err != nil {
				t.Fatal(err)
			}
			if r.FilesScanned != 1 || len(r.Findings) != 1 || r.Findings[0].Endpoint != "/real" || r.Findings[0].Path != filepath.Base("sample.js") {
				t.Fatalf("comment fabricated evidence: %+v", r)
			}
		})
	}
}

func TestHTMLCloseMarkerIsNotAlwaysComment(t *testing.T) {
	// A --> in the middle of a line must not consume the rest of the line.
	// The parser remains heuristic: this is a lexical boundary guard.
	dir := t.TempDir()
	write(t, dir, "sample.js", "let a = 3; a-- > fetch('/real');\n")
	r, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].Endpoint != "/real" {
		t.Fatalf("ordinary tokens wrongly swallowed by comment rule: %+v", r)
	}
}
