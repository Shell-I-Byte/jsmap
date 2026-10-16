package jsmap

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// Private identifiers belong to a class, not the global fetch/axios APIs.
// Literal URL arguments to them must not be emitted as endpoint candidates.
func TestPrivateMemberCalleesCannotFabricateEvidence(t *testing.T) {
	src := `class Client {
 #fetch(url) { return url; }
 #axios = {get(url) { return url; }};
 run() {
  this.#fetch('/private-fetch');
  this.#axios.get('/private-axios');
  fetch('/actual-fetch');
  axios.get('/actual-axios');
  window.fetch('/actual-global');
 }
}`
	digest := sha256.Sum256([]byte(src))
	findings, err := analyze([]byte(src), "synthetic.js", hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/actual-fetch", "/actual-axios", "/actual-global"}
	if len(findings) != len(want) {
		t.Fatalf("got %+v; want %v", findings, want)
	}
	for i, f := range findings {
		if f.Endpoint != want[i] || f.Confidence != "inferred" {
			t.Fatalf("finding[%d]=%+v; want %s inferred", i, f, want[i])
		}
		if !strings.HasPrefix(src[f.ByteOffset:], "'") {
			t.Fatalf("invalid original source byte offset: %d", f.ByteOffset)
		}
	}
}
