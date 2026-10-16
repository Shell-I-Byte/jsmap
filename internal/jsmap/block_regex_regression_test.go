package jsmap

import (
	"strings"
	"testing"
)

func TestBlockTerminatorRegexCannotFabricateEndpoint(t *testing.T) {
	cases := map[string]string{
		"if_block":        `if (true) {} /fetch("\x2fphantom")/.test('x'); fetch('/real');`,
		"nested_if_block": `if (true) { if (true) {} } /axios.get("\x2fphantom")/.test('x'); fetch('/real');`,
		"while_block":     `while(false) {} /fetch("\x2fphantom")/.test('x'); fetch('/real');`,
		"for_block":       `for(;false;) {} /fetch("\x2fphantom")/.test('x'); fetch('/real');`,
		"else_block":      `if(false) {} else {} /fetch("\x2fphantom")/.test('x'); fetch('/real');`,
		"finally_block":   `try {} finally {} /fetch("\x2fphantom")/.test('x'); fetch('/real');`,
		"object_division": `const ratio = {value:10} / fetch('/real');`,
		"arrow_division":  `const ratio = (()=>{return 10}) / fetch('/real');`,
	}
	for name, js := range cases {
		t.Run(name, func(t *testing.T) {
			findings, err := analyze([]byte(js), "synthetic.js", strings.Repeat("a", 64))
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 || findings[0].Endpoint != "/real" {
				t.Fatalf("unexpected endpoint evidence: %+v", findings)
			}
		})
	}
}
