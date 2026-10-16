package jsmap

import "testing"

func TestDeclarationAndBranchTerminatorRegexDoesNotFabricateEvidence(t *testing.T) {
	cases := map[string]string{
		"function_declaration":         `function f() {} /fetch("\x2fphantom")/.test("x"); fetch('/real');`,
		"function_after_semicolon":     `const n=2; function f(x){return x;} /axios.get("\x2fphantom")/.test("x"); fetch('/real');`,
		"async_function_declaration":   `async function f(){} /fetch("\x2fphantom")/.test("x"); fetch('/real');`,
		"class_declaration":            `class Foo {} /fetch("\x2fphantom")/.test("x"); fetch('/real');`,
		"switch_block":                 `switch(1){case 1:break;} /fetch("\x2fphantom")/.test("x"); fetch('/real');`,
		"catch_parameter_block":        `try {} catch(err) {} /fetch("\x2fphantom")/.test("x"); fetch('/real');`,
		"function_expression_division": `const ratio = function f() {return 10;} / fetch('/real');`,
		"class_expression_division":    `const ratio = class Foo {} / fetch('/real');`,
		"object_division":              `const ratio = ({x:1}) / fetch('/real');`,
		"arrow_division":               `const ratio = (()=>{return 10}) / fetch('/real');`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := analyze([]byte(src), "input.js", "synthetic")
			if err != nil {
				t.Fatal(err)
			}
			if len(r) != 1 || r[0].Endpoint != "/real" || r[0].Confidence != "inferred" {
				t.Fatalf("false-positive or missing real call: %+v", r)
			}
		})
	}
}
