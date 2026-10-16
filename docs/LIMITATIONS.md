> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Known limitations

- No complete ECMAScript AST. Ambiguous regex-vs-division positions, JSX, minified bundles, JS template interpolation, nested expressions, dynamic path construction, `.open()` and many framework-specific calls are not supported.
- `fetch()` and `axios.<verb>()` lexical matches can be shadowed/redefined by application code, so **all** results are `inferred`.
- May include a path with embedded secret segments and a host with sensitive subdomain names despite stripping query/fragment/userinfo. Review reports before disclosure.
- Input enumeration is local only; cannot fetch remote files, source maps or follow links.
- Unicode surrogate pairs in JS `\\u` escape sequences are conservatively omitted; some otherwise valid strings will be missed.
- CLI does not support cancellation via API, streaming output, watch mode, multi-root scans, per-file incremental state or a future graph adapter yet.
- Native macOS/Windows and supported-toolchain tests not performed in this local session. No CI workflow has been observed as green.
- The `github.com/Shell-I-Byte/jsmap` module name is intentionally provisional until a real independent repository is assigned.

- Regex syntax is only recognized at conservative expression-start positions. An ambiguous JavaScript construct may be ignored or misclassified. No full ECMAScript lexical grammar or AST oracle has been run.

- Unicode source-code identifiers are grouped with the Go standard library Unicode property tables to avoid false positives from ASCII suffixes. ECMAScript Unicode-escaped identifier spellings (`\\u0066etch`, for example) are not decoded; this may miss real calls, by design. No full ECMAScript parser compliance claim.

RC4: final-component swaps to FIFOs cannot hang the Unix open call. Root and ancestor directory replacement remain outside the hardened guarantee; non-Unix open fallback is not equivalent. Supported Go CI and analyzer gates have not executed.

RC5: Annex B HTML comments are suppressed conservatively (including in .mjs, where Annex B syntax is invalid). The heuristic lexer is not a full AST, and combinations involving multiline comments before an HTML-close marker are not fully specified/tested.

RC6: Syntactically valid classic JavaScript may start a regular-expression statement body after an `if/while/for/with` control head or `else`/`do`. These recognized forms are now suppressed as non-endpoint source text, with synthetic Node syntax-oracle tests. Other ambiguous grammar contexts may still create false positives; reports remain `inferred`.

RC7: Recognizes `if/while/for` and `else/finally` control-flow block termination followed by RegExp expression statements. This is a limited lexical false-evidence defense; JavaScript statement blocks after bare `{}`, function/class declarations, switch clauses and other ECMAScript contexts may still be misclassified. Findings remain `inferred` and need human verification.

RC8: Node-valid completed named function/class declarations, `switch` and parameterized `catch` blocks are now recognized as RegExp-statement boundaries in the targeted regression corpus. The lexer is still not a complete ECMAScript parser: bare labeled blocks, complex class `extends`, escaped identifier spellings, ASI subtleties, nested templates, and JS module grammar may still lead to false inferred evidence or omissions. All evidence remains `inferred`; do not use findings as confirmed observations.


**RC9 inference limits:** The conservative call-target filter omits unknown property-member calls to avoid fabricated web API evidence. Nested, computed and optional-chained global properties can be false negatives. A local variable can still shadow the bare `fetch`, `axios`, `window`, `self` or `globalThis` name, so no emitted candidate proves an actual network operation. No complete ECMAScript AST, symbol resolution or runtime evaluation is provided.

**RC10 root confinement:** A reproduced Linux RC9 intermediate-directory symlink race could expose out-of-root source bytes. RC10 anchors the selected root directory descriptor and rejects any symlink in individual source path components using Linux `openat(O_NOFOLLOW|O_DIRECTORY)`. Existing directories may still be renamed after a directory descriptor is opened, and the current `filepath.WalkDir` enumeration is not itself descriptor-contained; it may observe names outside scope during an adversarial rename/symlink race, although the new file-content opener rejects the synthetic out-of-root reads. Linux bind mounts, hard links and mutable same-inode contents remain additional limits. macOS/Windows maintain non-equivalent path-based source opens. Run only against trusted local trees, and do not promote RC10 to stable v1 solely because this specific race is fixed.

**RC11 class-private calls:** `this.#fetch(...)` and `this.#axios.method(...)` are suppressed as non-global network API calls. A different syntactically valid class-private or computed/optional-chain form may still be misclassified by the conservative lexer. No complete ECMAScript parser, symbol resolution or live endpoint verification is claimed.

**RC12 URL grammar:** The bracketed HTTP(S) and protocol-relative authority check is a targeted false-evidence fix, not a full WHATWG parser. Other accepted URLs may still fail in a particular browser (e.g., host encodings, invalid port ranges or special URL canonicalization). All results are `inferred` and require verification.
