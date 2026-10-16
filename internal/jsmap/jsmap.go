// Package jsmap identifies literal URL references in explicitly provided local JavaScript files.
// It never executes JavaScript, opens network connections, or asserts that a route exists.
package jsmap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const Version = "v0.1.0-rc12"
const Schema = "jsmap.result/v1"
const MaxFileBytes int64 = 2 << 20
const MaxFiles = 1000
const MaxFindings = 10000
const maxTokens = 120000

var ErrInvalidRoot = errors.New("root must be a readable real directory (not a symlink)")
var ErrLimit = errors.New("input exceeds configured safety limit")

// Finding is an inferred reference to a potential endpoint, never proof of a live route.
type Finding struct {
	Path             string `json:"path"`
	SHA256           string `json:"source_sha256"`
	ByteOffset       int    `json:"byte_offset"`
	Call             string `json:"call"`
	Endpoint         string `json:"endpoint"`
	QueryRedacted    bool   `json:"query_redacted"`
	UserinfoRedacted bool   `json:"userinfo_redacted"`
	Confidence       string `json:"confidence"`
}

type Report struct {
	Schema       string    `json:"schema_version"`
	Version      string    `json:"tool_version"`
	Scope        string    `json:"scope"`
	FilesScanned int       `json:"files_scanned"`
	Findings     []Finding `json:"findings"`
}

// Scan reads only .js, .mjs and .cjs regular files from the specified root.
// Symlinks are skipped, never traversed; changed inode metadata fails closed.
func Scan(root string) (Report, error) {
	r := Report{Schema: Schema, Version: Version, Scope: "local-files-only", Findings: make([]Finding, 0)}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return r, ErrInvalidRoot
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return r, ErrInvalidRoot
	}
	// Anchor all source opens to the original directory, not to mutable ancestor
	// pathname components. On Linux, nested paths are opened component-by-
	// component with O_DIRECTORY|O_NOFOLLOW to prevent symlink-swap escapes.
	rootFD, err := openScanRoot(absolute, rootInfo)
	if err != nil {
		return r, ErrInvalidRoot
	}
	defer rootFD.Close()
	var paths []string
	err = filepath.WalkDir(absolute, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("directory traversal failed: %w", walkErr)
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".js" && ext != ".mjs" && ext != ".cjs" {
			return nil
		}
		if len(paths) >= MaxFiles {
			return ErrLimit
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return r, err
	}
	sort.Strings(paths)
	for _, path := range paths {
		before, err := os.Lstat(path)
		if err != nil || !before.Mode().IsRegular() {
			return r, fmt.Errorf("source unavailable or changed")
		}
		if before.Size() > MaxFileBytes {
			return r, ErrLimit
		}
		rel, err := filepath.Rel(absolute, path)
		if err != nil || !utf8.ValidString(rel) || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return r, fmt.Errorf("path escaped root")
		}
		fh, err := openSourceInRoot(rootFD, absolute, rel)
		if err != nil {
			return r, fmt.Errorf("source unreadable")
		}
		after, serr := fh.Stat()
		if serr != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
			fh.Close()
			return r, fmt.Errorf("source changed during read")
		}
		bytes, err := io.ReadAll(io.LimitReader(fh, MaxFileBytes+1))
		cerr := fh.Close()
		if err != nil || cerr != nil {
			return r, fmt.Errorf("source read failed")
		}
		if int64(len(bytes)) > MaxFileBytes {
			return r, ErrLimit
		}
		if !utf8.Valid(bytes) {
			return r, fmt.Errorf("source is not UTF-8")
		}
		digest := sha256.Sum256(bytes)
		matches, err := analyze(bytes, filepath.ToSlash(rel), hex.EncodeToString(digest[:]))
		if err != nil {
			return r, err
		}
		if len(matches) > MaxFindings-len(r.Findings) {
			return r, ErrLimit
		}
		r.Findings = append(r.Findings, matches...)
		r.FilesScanned++
	}
	return r, nil
}

type token struct {
	kind, value string
	pos         int
	valid       bool
}

func identifierStart(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b == '_' || b == '$'
}
func identifierNext(b byte) bool { return identifierStart(b) || b >= '0' && b <= '9' }

// ECMAScript IdentifierName uses Unicode ID_Start and ID_Continue (plus $, _,
// ZWNJ, and ZWJ). Recognize whole Unicode identifiers instead of exposing an
// ASCII suffix such as fetch in πfetch as a separate callable identifier.
// Unicode-escaped identifiers remain intentionally unsupported (false negative).
func identifierStartRune(r rune) bool {
	return r == '$' || r == '_' || unicode.IsLetter(r) || unicode.In(r, unicode.Nl, unicode.Other_ID_Start)
}
func identifierNextRune(r rune) bool {
	return identifierStartRune(r) || r == '\u200c' || r == '\u200d' || unicode.In(r, unicode.Nd, unicode.Mn, unicode.Mc, unicode.Pc, unicode.Other_ID_Continue)
}

// mayStartRegex intentionally handles only unambiguous expression-start positions.
// This remains a conservative lexer, not a JavaScript parser: when uncertain,
// it must not turn the source text of a regular expression into endpoint evidence.
// A RegExp literal is also permitted immediately after a statement-control
// head such as `if (condition) /re/.test(value)`. A plain call expression's
// closing ')' does *not* create such a position (`value() / 2`). Follow the
// matched parentheses back to their control keyword, without interpreting
// arbitrary JavaScript expressions as a complete parser would.
func followsControlHead(previous []token) bool {
	if len(previous) == 0 || !tokenIs(previous[len(previous)-1], "symbol", ")") {
		return false
	}
	depth := 0
	for i := len(previous) - 1; i >= 0; i-- {
		switch {
		case tokenIs(previous[i], "symbol", ")"):
			depth++
		case tokenIs(previous[i], "symbol", "("):
			depth--
			if depth == 0 {
				if i == 0 || previous[i-1].kind != "id" {
					return false
				}
				if i >= 2 && tokenIs(previous[i-2], "symbol", ".") {
					return false // a property called `if` is not an if-statement
				}
				switch previous[i-1].value {
				case "if", "while", "for", "with", "switch", "catch":
					return true
				}
				return false
			}
		}
	}
	return false
}

// followsDeclarationBlock recognizes a narrow set of completed named function
// and class *declarations*. A function/class expression used as the numerator
// of a division expression must not be mistaken for a RegExp statement start.
// No general-purpose ECMAScript parse is claimed; ambiguous constructs remain
// inferred and require human verification.
func followsDeclarationBlock(head []token) bool {
	declarationStart := func(index int) bool {
		// Exports and async declarations can prefix a declaration, but a value
		// expression such as "const x = async function(){} / fetch('/real')"
		// must still be treated as division rather than a regular expression.
		for index >= 0 && head[index].kind == "id" {
			switch head[index].value {
			case "async", "export", "default":
				index--
				continue
			}
			break
		}
		if index < 0 {
			return true
		}
		t := head[index]
		return t.kind == "symbol" && (t.value == ";" || t.value == "{" || t.value == "}")
	}

	// function f() {}, async function f() {}, function* f() {}
	if len(head) > 0 && tokenIs(head[len(head)-1], "symbol", ")") {
		depth := 0
		for i := len(head) - 1; i >= 0; i-- {
			switch {
			case tokenIs(head[i], "symbol", ")"):
				depth++
			case tokenIs(head[i], "symbol", "("):
				depth--
				if depth == 0 {
					j := i - 1
					if j >= 0 && head[j].kind == "id" {
						j--
					} // optional function name
					if j >= 0 && tokenIs(head[j], "symbol", "*") {
						j--
					}
					return j >= 0 && tokenIs(head[j], "id", "function") && declarationStart(j-1)
				}
			}
		}
	}
	// class Foo {} (a deliberately narrow named-declaration case).
	if len(head) >= 2 && head[len(head)-1].kind == "id" &&
		tokenIs(head[len(head)-2], "id", "class") {
		return declarationStart(len(head) - 3)
	}
	return false
}

// followsStatementBlock conservatively recognizes a finished control-flow
// statement block. After `if (cond) {}` a following `/pattern/` can begin an
// expression statement; treating its contents as calls fabricates evidence.
// A plain object literal or arrow-function body is deliberately *not* a
// statement block here: `({x: 1}) / fetch("/real")` is division and still calls
// fetch. This is a targeted lexical rule, not an ECMAScript parser.
func followsStatementBlock(previous []token) bool {
	if len(previous) == 0 || !tokenIs(previous[len(previous)-1], "symbol", "}") {
		return false
	}
	depth := 0
	for i := len(previous) - 1; i >= 0; i-- {
		switch {
		case tokenIs(previous[i], "symbol", "}"):
			depth++
		case tokenIs(previous[i], "symbol", "{"):
			depth--
			if depth == 0 {
				head := previous[:i]
				if followsControlHead(head) || followsDeclarationBlock(head) {
					return true
				}
				if len(head) == 0 {
					return false
				}
				last := head[len(head)-1]
				if last.kind == "id" && (len(head) == 1 || !tokenIs(head[len(head)-2], "symbol", ".")) {
					switch last.value {
					case "else", "do", "try", "finally", "catch":
						return true
					}
				}
				return false
			}
		}
	}
	return false
}

func mayStartRegex(previous []token) bool {
	if len(previous) == 0 {
		return true
	}
	t := previous[len(previous)-1]
	if t.kind == "id" {
		switch t.value {
		case "return", "throw", "case", "delete", "void", "typeof", "yield", "await", "in", "of", "instanceof", "else", "do":
			return true
		}
	}
	if tokenIs(t, "symbol", ")") {
		return followsControlHead(previous)
	}
	if tokenIs(t, "symbol", "}") {
		return followsStatementBlock(previous)
	}
	if t.kind != "symbol" {
		return false
	}
	switch t.value {
	case "=", "(", "[", "{", ":", ",", ";", "!", "?", "&", "|", "^", "~", "+", "-", "*", "%", "<", ">":
		return true
	}
	return false
}

// skipRegex consumes a syntactic /body/flags candidate, including escaped
// slashes and slash characters inside character classes. If no closing slash
// exists on this line, the caller falls back to conservative ordinary tokens.
func skipRegex(src []byte, start int) (int, bool) {
	if start >= len(src) || src[start] != '/' {
		return start, false
	}
	inClass, escaped := false, false
	for i := start + 1; i < len(src); i++ {
		c := src[i]
		if c == '\n' || c == '\r' {
			return start, false
		}
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '[' && !inClass {
			inClass = true
			continue
		}
		if c == ']' && inClass {
			inClass = false
			continue
		}
		if c == '/' && !inClass {
			i++
			for i < len(src) && identifierNext(src[i]) {
				i++
			}
			return i, true
		}
	}
	return start, false
}

// htmlCloseCommentAtLineStart recognizes the legacy Annex B HTML close
// comment only after a line terminator and optional ASCII whitespace.
// A --> in the middle of an expression (a-- > b) must not be skipped.
func htmlCloseCommentAtLineStart(src []byte, start int) bool {
	for j := start - 1; j >= 0; j-- {
		switch src[j] {
		case '\n', '\r':
			return true
		case ' ', '\t', '\v', '\f':
			continue
		default:
			return false
		}
	}
	return true
}

func lex(src []byte) ([]token, error) {
	out := make([]token, 0)
	add := func(t token) error {
		if len(out) >= maxTokens {
			return ErrLimit
		}
		out = append(out, t)
		return nil
	}
	for i := 0; i < len(src); {
		b := src[i]
		if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
			i++
			continue
		}
		// ECMAScript Annex B (classic scripts): HTML-like line comments must
		// not become inferred endpoint evidence. This is a conservative
		// suppression even for modules, whose HTML comments are invalid JS.
		if bytes.HasPrefix(src[i:], []byte("<!--")) ||
			(bytes.HasPrefix(src[i:], []byte("-->")) && htmlCloseCommentAtLineStart(src, i)) {
			for i < len(src) && src[i] != '\n' && src[i] != '\r' {
				i++
			}
			continue
		}
		if b == '/' && i+1 < len(src) && src[i+1] == '/' {
			i += 2
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		}
		if b == '/' && i+1 < len(src) && src[i+1] == '*' {
			i += 2
			end := bytes.Index(src[i:], []byte("*/"))
			if end < 0 {
				break
			}
			i += end + 2
			continue
		}
		if b == '/' && mayStartRegex(out) {
			if next, ok := skipRegex(src, i); ok {
				i = next
				continue
			}
		}
		if b == '`' { // Do not infer anything from templates, including ${...} expressions.
			i++
			for i < len(src) {
				if src[i] == '\\' {
					i += 2
					continue
				}
				if src[i] == '`' {
					i++
					break
				}
				i++
			}
			continue
		}
		if b == '\'' || b == '"' {
			val, next, ok := jsString(src, i)
			if err := add(token{kind: "str", value: val, pos: i, valid: ok}); err != nil {
				return nil, err
			}
			i = next
			continue
		}
		if r, size := utf8.DecodeRune(src[i:]); identifierStartRune(r) {
			start := i
			i += size
			for i < len(src) {
				next, nextSize := utf8.DecodeRune(src[i:])
				if !identifierNextRune(next) {
					break
				}
				i += nextSize
			}
			if err := add(token{kind: "id", value: string(src[start:i]), pos: start, valid: true}); err != nil {
				return nil, err
			}
			continue
		}
		if err := add(token{kind: "symbol", value: string(b), pos: i, valid: true}); err != nil {
			return nil, err
		}
		i++
	}
	return out, nil
}

// jsString parses conservative ECMAScript quoted strings. Unsupported escapes invalidate
// the token rather than creating an incorrect endpoint. JS is not evaluated.
func jsString(src []byte, start int) (string, int, bool) {
	quote := src[start]
	var b strings.Builder
	valid := true
	for i := start + 1; i < len(src); {
		c := src[i]
		if c == quote {
			return b.String(), i + 1, valid
		}
		if c == '\n' || c == '\r' {
			return "", i, false
		}
		if c != '\\' {
			b.WriteByte(c)
			i++
			continue
		}
		if i+1 >= len(src) {
			return "", len(src), false
		}
		e := src[i+1]
		i += 2
		switch e {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'v':
			b.WriteByte('\v')
		case '0':
			b.WriteByte(0)
		case '\\', '\'', '"':
			b.WriteByte(e)
		case '\n': // line continuation is valid
		case '\r':
			if i < len(src) && src[i] == '\n' {
				i++
			}
		case 'x', 'u':
			digits := 2
			if e == 'u' {
				digits = 4
			}
			if i+digits > len(src) {
				return "", len(src), false
			}
			v, err := strconv.ParseUint(string(src[i:i+digits]), 16, 32)
			if err != nil {
				valid = false
				i += digits
				continue
			}
			i += digits
			if v >= 0xd800 && v <= 0xdfff {
				valid = false
				continue
			} // surrogate pairs intentionally unsupported
			b.WriteRune(rune(v))
		default:
			valid = false // do not silently invent an endpoint
		}
	}
	return "", len(src), false
}

// endpoint redacts query/fragment/userinfo but does not claim to remove secrets
// embedded in path segments or hostnames.
func endpoint(raw string) (string, bool, bool, bool) {
	if raw == "" || len(raw) > 8192 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\r\n\t\x00") {
		return "", false, false, false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false, false, false
	}
	if u.Opaque != "" {
		return "", false, false, false
	}
	// The Go URL parser can accept bracketed DNS names, IPv4 addresses,
	// IPvFuture identifiers, or IPv6 zone IDs in an HTTP authority. A browser
	// fetch URL cannot use these as a bracketed host (WHATWG URL host parser).
	// Never emit a syntactically impossible URL as inferred endpoint evidence.
	// Ordinary relative paths with brackets are unaffected.
	if strings.HasPrefix(u.Host, "[") {
		addr, err := netip.ParseAddr(u.Hostname())
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return "", false, false, false
		}
	} else if strings.ContainsAny(u.Host, "[]") {
		return "", false, false, false
	}
	switch strings.ToLower(u.Scheme) {
	case "":
		if u.Host != "" { // protocol-relative URL
			if !strings.HasPrefix(raw, "//") {
				return "", false, false, false
			}
		} else if !(strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../") || strings.Contains(raw, "/")) {
			return "", false, false, false
		}
	case "http", "https":
		if u.Host == "" {
			return "", false, false, false
		}
	default:
		return "", false, false, false
	}
	// Userinfo may contain credentials; never print it.
	hadUserinfo := u.User != nil
	u.User = nil
	query := u.RawQuery != "" || u.ForceQuery
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	// Drop unnecessary percent encoded variants as they are not needed for evidence.
	result := u.String()
	if result == "" || result == "/" || result == "./" || result == "../" {
		return "", false, false, false
	}
	return result, query, hadUserinfo, true
}

func tokenIs(t token, kind, val string) bool { return t.kind == kind && t.value == val && t.valid }

// recognizedAPICallee accepts bare calls and simple global-object references.
// An arbitrary object's .fetch or .axios property may have unrelated semantics:
// reporting it as the browser fetch/axios API fabricates endpoint evidence.
// Complex member chains and optional-chained property roots are intentionally
// omitted, not guessed. This remains inferred lexical evidence, not dataflow.
func recognizedAPICallee(toks []token, i int) bool {
	// ECMAScript private member names are introduced by #. A call through
	// this.#fetch or this.#axios is not the global fetch/axios API.
	// Ignore this narrow grammar form rather than invent inferred evidence.
	if i > 0 && tokenIs(toks[i-1], "symbol", "#") {
		return false
	}
	if i == 0 || !tokenIs(toks[i-1], "symbol", ".") {
		return true
	}
	if i < 2 || toks[i-2].kind != "id" {
		return false
	}
	switch toks[i-2].value {
	case "window", "self", "globalThis":
		return i == 2 || !tokenIs(toks[i-3], "symbol", ".")
	}
	return false
}

func analyze(src []byte, rel, digest string) ([]Finding, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	result := make([]Finding, 0)
	for i := 0; i < len(toks); i++ {
		call := ""
		start := -1
		if tokenIs(toks[i], "id", "fetch") && recognizedAPICallee(toks, i) && i+2 < len(toks) && tokenIs(toks[i+1], "symbol", "(") {
			call = "fetch"
			start = i + 2
		}
		if tokenIs(toks[i], "id", "axios") && recognizedAPICallee(toks, i) && i+4 < len(toks) && tokenIs(toks[i+1], "symbol", ".") && toks[i+2].kind == "id" && tokenIs(toks[i+3], "symbol", "(") {
			switch toks[i+2].value {
			case "get", "post", "put", "patch", "delete", "head", "options":
				call = "axios." + toks[i+2].value
				start = i + 4
			}
		}
		if start < 0 || start >= len(toks) || toks[start].kind != "str" || !toks[start].valid {
			continue
		}
		// A concatenation/template does NOT justify claiming the string is a whole URL.
		if start+1 >= len(toks) || !(tokenIs(toks[start+1], "symbol", ")") || tokenIs(toks[start+1], "symbol", ",")) {
			continue
		}
		ep, q, auth, ok := endpoint(toks[start].value)
		if !ok {
			continue
		}
		result = append(result, Finding{Path: rel, SHA256: digest, ByteOffset: toks[start].pos, Call: call, Endpoint: ep, QueryRedacted: q, UserinfoRedacted: auth, Confidence: "inferred"})
	}
	return result, nil
}
