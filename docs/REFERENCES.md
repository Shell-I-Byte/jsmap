> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Primary design references (reviewed 2026-10-09)

- Go release history and support policy: https://go.dev/doc/devel/release — Go 1.26.9 and 1.27.2 published on 2026-10-08; local Go 1.23.2 is no longer supported.
- IETF RFC 3986: https://www.rfc-editor.org/info/rfc3986/ — absolute and relative URI references, scheme/host/query/fragment component semantics. JSMap performs conservative URI-reference validation and explicitly removes query/userinfo/fragment from emitted endpoints.
- OWASP Noir project: https://owasp.org/projects/noir — source-code endpoint inventory as defensive attack-surface context; JSMap is much narrower and cannot claim AST completeness.
- Go race detector documentation: https://go.dev/doc/articles/race_detector — use `go test -race`, which was run for this RC on Linux with Go 1.23.2.

External sources serve as design guidance only; they are not evidence of this package having passed CI or supported-toolchain testing.

- ECMAScript 2024 Lexical Grammar (IdentifierStart/IdentifierPart Unicode ID_Start, ID_Continue, ZWNJ/ZWJ): https://tc39.es/ecma262/2024/multipage/ecmascript-language-lexical-grammar.html
- Go Unicode tables: https://pkg.go.dev/unicode
- Go release history (supported versions): https://go.dev/doc/devel/release

- ECMAScript Annex B B.1.1 HTML-like comments (non-Module): https://tc39.es/ecma262/2024/multipage/additional-ecmascript-features-for-web-browsers.html#sec-html-like-comments

- ECMA-262 2025 §12: lexical goals distinguish InputElementRegExp and InputElementDiv; https://tc39.es/ecma262/2025/multipage/ecmascript-language-lexical-grammar.html (checked 2026-10-13).
- Go official release history: https://go.dev/doc/devel/release (checked 2026-10-13); Go 1.26.9 / 1.27.2 released 2026-10-08.
- govulncheck v1.9.0 https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck (published 2026-10-11); configured but NOT locally executed.

- ECMA-262 (2026), Property Accessors and MemberExpression evaluation: https://tc39.es/ecma262/2026/multipage/ecmascript-language-expressions.html — distinct member-expression receiver from a bare identifier; accessed 2026-10-13.
- OWASP Attack Surface Detector: https://owasp.org/projects/attack-surface-detector — offline endpoint inference requires source context and does not prove a live route; accessed 2026-10-13.

- Linux `openat2(2)` manual: https://man7.org/linux/man-pages/man2/openat2.2.html (O_NOFOLLOW applies only to final component; `RESOLVE_NO_SYMLINKS` includes ancestors; openat2-specific modes are not claimed implemented by RC10).
- Go traversal-resistant file APIs and residual mount point threats: https://go.dev/blog/osroot (Go 1.24+; RC10 does not use os.Root because local build was Go 1.23.2).
- Go release support: https://go.dev/doc/devel/release (1.26.9 and 1.27.2 current as of 2026-10-14).

- WHATWG URL Standard, https://url.spec.whatwg.org/ — host parsing, bracketed IPv6 format, and unsupported IPv6 zone IDs (checked 2026-10-15).
- Go `net/netip.ParseAddr`, https://pkg.go.dev/net/netip — strict IPv4/IPv6 address parsing.
