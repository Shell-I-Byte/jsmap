package jsmap

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

func write(t *testing.T, root, name, src string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(src), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestPositiveAndRedaction(t *testing.T) {
	root := t.TempDir()
	write(t, root, "z.js", `fetch('/api/v1/users?api_key=SECRET#frag'); axios.post("https://bob:password@example.com/v2/check?auth=TOPSECRET");`)
	write(t, root, "a/b.mjs", `fetch("https://[::1]:8443/v1"); axios.get('./relative/path'); fetch("https://bücher.example/v1"); fetch("/hex\x2froute");`)
	r, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if r.Schema != Schema || r.Version != Version || r.FilesScanned != 2 {
		t.Fatalf("metadata: %#v", r)
	}
	if len(r.Findings) != 6 {
		t.Fatalf("found %d want 6: %+v", len(r.Findings), r.Findings)
	}
	for _, f := range r.Findings {
		if f.Confidence != "inferred" || len(f.SHA256) != 64 || strings.Contains(f.Endpoint, "SECRET") || strings.Contains(f.Endpoint, "password") || strings.Contains(f.Endpoint, "#") {
			t.Fatalf("unsafe finding: %+v", f)
		}
	}
	if r.Findings[4].Endpoint != "/api/v1/users" || !r.Findings[4].QueryRedacted {
		t.Fatalf("query leakage: %#v", r.Findings[4])
	}
	if r.Findings[5].Endpoint != "https://example.com/v2/check" || !r.Findings[5].UserinfoRedacted || !r.Findings[5].QueryRedacted {
		t.Fatalf("userinfo leakage: %#v", r.Findings[5])
	}
	if r.Findings[0].Path != "a/b.mjs" {
		t.Fatalf("ordering: %+v", r.Findings)
	}
	if r.Findings[4].ByteOffset >= r.Findings[5].ByteOffset {
		t.Fatal("expected ascending offsets")
	}
}

func TestIgnoreNonliteralAndComments(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.js", `// fetch('/fake')
/* axios.get('/fake2') */
const s = "fetch('/fake3')";
const template = `+"`fetch('/fake4')`"+`;
fetch('/concatenated/' + value);
fetch(variable);
fetch('javascript:alert(1)');
fetch('mailto:a@b');
fetch('http://[broken');
fetch('no-slash');
fetch('/good', {method:'GET'});
axios.delete('../relative');
`)
	r, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 2 || r.Findings[0].Endpoint != "/good" || r.Findings[1].Endpoint != "../relative" {
		t.Fatalf("false positives: %+v", r.Findings)
	}
}

func TestEscapeParsingAndBoundary(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.js", `fetch("\\u002fnot-decoded"); fetch("\x2fhex"); fetch("\u002funicode"); fetch("/newline\ninvalid"); fetch('/safe?x=secret');`)
	r, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 3 {
		t.Fatalf("findings: %+v", r.Findings)
	}
	if r.Findings[0].Endpoint != "/hex" || r.Findings[1].Endpoint != "/unicode" || r.Findings[2].Endpoint != "/safe" {
		t.Fatalf("wrong escape handling: %+v", r.Findings)
	}
}

func TestDeterminismAndSchemaJSON(t *testing.T) {
	root := t.TempDir()
	write(t, root, "b.cjs", `fetch('/b');`)
	write(t, root, "a.mjs", `fetch('/a');`)
	first, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	bytes, _ := json.Marshal(first)
	for i := 0; i < 10; i++ {
		next, err := Scan(root)
		if err != nil {
			t.Fatal(err)
		}
		other, _ := json.Marshal(next)
		if !reflect.DeepEqual(first, next) || string(bytes) != string(other) {
			t.Fatal("non-deterministic JSON")
		}
	}
	if first.Findings[0].Path != "a.mjs" {
		t.Fatalf("order: %+v", first.Findings)
	}
}

func TestRejectSymlinksAndInvalidRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	write(t, outside, "secret.js", `fetch('/SECRET');`)
	if err := os.Symlink(filepath.Join(outside, "secret.js"), filepath.Join(root, "ignored.js")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "ignored-directory")); err != nil {
		t.Fatal(err)
	}
	write(t, root, "local.js", `fetch('/allowed');`)
	r, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if r.FilesScanned != 1 || len(r.Findings) != 1 || r.Findings[0].Endpoint != "/allowed" {
		t.Fatalf("symlink traversal: %+v", r)
	}
	link := filepath.Join(t.TempDir(), "linked-root")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(link); !errors.Is(err, ErrInvalidRoot) {
		t.Fatalf("symlink root must be rejected: %v", err)
	}
	if _, err := Scan(filepath.Join(root, "missing")); !errors.Is(err, ErrInvalidRoot) {
		t.Fatal("missing root accepted")
	}
}

func TestSizeAndCountLimits(t *testing.T) {
	root := t.TempDir()
	write(t, root, "huge.js", strings.Repeat("x", int(MaxFileBytes)+1))
	if _, err := Scan(root); !errors.Is(err, ErrLimit) {
		t.Fatalf("size: %v", err)
	}
	root = t.TempDir()
	// Count check is exercised with real filesystem entries.
	for i := 0; i <= MaxFiles; i++ {
		name := filepath.Join(root, fmtName(i)+".js")
		if err := os.WriteFile(name, []byte(""), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Scan(root); !errors.Is(err, ErrLimit) {
		t.Fatalf("count: %v", err)
	}
}
func fmtName(i int) string { return strconv.Itoa(i) }

func TestInvalidUTF8(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "bad.js"), []byte{0xff, 0x00}, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(root); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func TestEmptyAndUnknownExtensions(t *testing.T) {
	root := t.TempDir()
	write(t, root, "ignore.txt", `fetch('/invisible')`)
	r, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if r.FilesScanned != 0 || r.Findings == nil || len(r.Findings) != 0 {
		t.Fatalf("empty: %+v", r)
	}
}

func TestConcurrentReaders(t *testing.T) {
	root := t.TempDir()
	write(t, root, "src.js", `fetch('/hello'); axios.post('/world')`)
	baseline, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			current, err := Scan(root)
			if err != nil {
				errs <- err
				return
			}
			if !reflect.DeepEqual(baseline, current) {
				errs <- errors.New("concurrent result mismatch")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestMaxFindingsAndTokenLimit(t *testing.T) {
	root := t.TempDir()
	write(t, root, "bulk.js", strings.Repeat("fetch('/a');", MaxFindings+1))
	if _, err := Scan(root); !errors.Is(err, ErrLimit) {
		t.Fatalf("findings cap: %v", err)
	}
	root = t.TempDir()
	write(t, root, "tokens.js", strings.Repeat("+", maxTokens+1))
	if _, err := Scan(root); !errors.Is(err, ErrLimit) {
		t.Fatalf("token cap: %v", err)
	}
}

func FuzzAnalyzeNoPanic(f *testing.F) {
	for _, s := range []string{`fetch('/safe')`, `fetch(\u0033)`, `/*`, `"unterminated`, "\x00\xff", "fetch(`"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if int64(len(s)) > MaxFileBytes {
			t.Skip()
		}
		if !utf8.ValidString(s) {
			t.Skip()
		}
		_, _ = analyze([]byte(s), "synthetic.js", strings.Repeat("0", 64))
	})
}

func TestRegexLiteralCannotFabricateEndpoint(t *testing.T) {
	root := t.TempDir()
	source := `const pattern = /fetch("https:\x2f\x2fexample.test\x2fphantom")/;
const bracket = /[\/]fetch("https:\x2f\x2fexample.test\x2fsecond")/i;
const method = () => /axios.get("https:\x2f\x2fexample.test\x2fthird")/;
const fraction = 16 / 4 / 2;
fetch("/real"); axios.post("/real-too");`
	write(t, root, "test.js", source)
	result, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 2 || result.Findings[0].Endpoint != "/real" || result.Findings[1].Endpoint != "/real-too" {
		t.Fatalf("regex source created false endpoint evidence: %+v", result.Findings)
	}
}

// JS identifiers may start with Unicode ID_Start code points, and ID_Continue
// may include combining marks and ZWNJ. The ASCII suffix of such a name must
// never be treated as the global fetch/axios identifier.
func TestUnicodeIdentifierCannotFabricateEndpoint(t *testing.T) {
	root := t.TempDir()
	write(t, root, "unicode.js", `const πfetch = (u) => u;
πfetch('/phantom-one');
const πaxios = {get(u) { return u; }};
πaxios.get('/phantom-two');
const ℘fetch = (u) => u;
℘fetch('/phantom-three');
const π`+"\u200c"+`fetch = (u) => u;
π`+"\u200c"+`fetch('/phantom-four');
fetch('/real'); axios.get('/also-real');`)
	r, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 2 || r.Findings[0].Endpoint != "/real" || r.Findings[1].Endpoint != "/also-real" {
		t.Fatalf("Unicode identifier caused false evidence: %+v", r.Findings)
	}
}
