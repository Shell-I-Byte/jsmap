package jsmap

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// Property access is not a bare fetch/axios API reference: arbitrary objects
// can define these method names without performing network activity.
func TestUnknownPropertyCalleesDoNotFabricateEndpoints(t *testing.T) {
	cases := []struct {
		name, source string
		want         []string
	}{
		{"object_fetch", `const obj = {fetch(x){return x}}; obj.fetch('/fake'); fetch('/real');`, []string{"/real"}},
		{"object_axios", `const obj = {axios: {get(x){return x}}}; obj.axios.get('/fake'); axios.get('/real');`, []string{"/real"}},
		{"nested_fetch", `const obj = {inner:{fetch(x){return x}}}; obj.inner.fetch('/fake'); fetch('/real');`, []string{"/real"}},
		{"nested_global_name", `const obj = {window: {fetch(x){return x}}}; obj.window.fetch('/fake'); window.fetch('/real');`, []string{"/real"}},
		{"optional_fetch", `const obj = {fetch(x){return x}}; obj?.fetch('/fake'); fetch('/real');`, []string{"/real"}},
		{"global_fetch", `window.fetch('/window'); self.fetch('/self'); globalThis.fetch('/global'); fetch('/bare');`, []string{"/window", "/self", "/global", "/bare"}},
		{"global_axios", `window.axios.get('/window'); globalThis.axios.post('/global'); axios.get('/bare');`, []string{"/window", "/global", "/bare"}},
		{"nested_global_axios", `const obj={window:{axios:{get(x){return x}}}}; obj.window.axios.get('/fake'); window.axios.get('/real');`, []string{"/real"}},
		{"bracket_qualifier", `const obj={x:[{fetch(x){return x}}]}; obj.x[0].fetch('/fake'); fetch('/real');`, []string{"/real"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := sha256.Sum256([]byte(tc.source))
			results, err := analyze([]byte(tc.source), "property.js", hex.EncodeToString(h[:]))
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != len(tc.want) {
				t.Fatalf("got %d endpoint candidates, want %d: %+v", len(results), len(tc.want), results)
			}
			for i, finding := range results {
				if finding.Endpoint != tc.want[i] {
					t.Errorf("at %d got %q want %q", i, finding.Endpoint, tc.want[i])
				}
				if finding.Confidence != "inferred" {
					t.Errorf("confidence escalated: %s", finding.Confidence)
				}
				if finding.ByteOffset < 0 || finding.ByteOffset >= len(tc.source) || !strings.HasPrefix(tc.source[finding.ByteOffset:], "'") {
					t.Errorf("invalid source byte offset: %d", finding.ByteOffset)
				}
			}
		})
	}
}
