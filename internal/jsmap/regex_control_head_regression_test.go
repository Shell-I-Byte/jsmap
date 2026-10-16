package jsmap

import (
	"strings"
	"testing"
)

// Valid classic ECMAScript control-flow statement bodies may begin with a
// RegExp literal even when the preceding token is ')'. RegExp contents are
// never evidence that a network call actually exists.
func TestControlHeadRegexCannotFabricateEndpoint(t *testing.T) {
	cases := []struct{ name, script string }{
		{"if", `let yes=true; if (yes) /fetch("https:\x2f\x2fphantom.test\x2fif")/.test('x'); fetch('/real');`},
		{"nested_if", `let yes=true; if ((yes)) /axios.get("https:\x2f\x2fphantom.test\x2fnested")/.test('x'); fetch('/real');`},
		{"while", `while (false) /fetch("https:\x2f\x2fphantom.test\x2fwhile")/.test('x'); fetch('/real');`},
		{"for", `for (;false;) /fetch("https:\x2f\x2fphantom.test\x2ffor")/.test('x'); fetch('/real');`},
		{"with", `with ({yes:true}) /axios.post("https:\x2f\x2fphantom.test\x2fwith")/.test('x'); fetch('/real');`},
		{"else", `if (false) {} else /fetch("https:\x2f\x2fphantom.test\x2felse")/.test('x'); fetch('/real');`},
		{"do", `do /fetch("https:\x2f\x2fphantom.test\x2fdo")/.test('x'); while(false); fetch('/real');`},
		{"divide_control", `let x=10; if (true) x = x / 2; fetch('/real');`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := analyze([]byte(tc.script), "synthetic.js", strings.Repeat("0", 64))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].Endpoint != "/real" {
				t.Fatalf("false inferred endpoint from valid classic JS control flow: %+v", got)
			}
		})
	}
}
