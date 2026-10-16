> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Threat model and non-goals

**Assets:** source files and potentially sensitive URLs. **Trust boundary:** arbitrary local JavaScript content, filenames and command-line flags are untrusted; the chosen root belongs to the authorized user. **Threats addressed:** symlink traversal, read-size/token/result resource exhaustion, stdout/stderr control-sequence injection, accidental query/userinfo leakage, malformed URL claims, non-deterministic output and byte-offset provenance confusion.

**Controls:** skip symlinks, verify opened inode against prior lstat, strict byte/file/token/findings caps, reject invalid UTF-8, sanitised fixed CLI errors, deterministic ordering, userinfo/query/fragment removal, confidence=`inferred`, no outbound network. `go test -race` and synthetic controls are included.

**Residual threats:** TOCTOU races remain possible against a hostile process concurrently mutating **the same inode** or directory tree; the SHA-256 identifies the bytes read but is not an external trust anchor. Hard links and symlinks in root *ancestor* components are not prohibited. Source paths or route path segments can themselves contain secrets; JSON is NOT safe to publish automatically. Lexical heuristics may report a call that is not a reachable endpoint and may miss many JS syntaxes. JS regex/template tokenization is incomplete; no AST/dataflow/minification deobfuscation. Go 1.23.2 used for local tests is EOL. Staticcheck/govulncheck/new Go/native OS tests are outstanding release gates.

**Explicit non-goals:** no active scanning, no endpoint validation, no exploit execution, no source code fetch from remote origins, no identity attribution, no AI inference promoted to evidence.

## RC2 threat update: fabricating false findings from regex literals
Without regex context, an untrusted source string like `/fetch("https:\x2f\x2fexample.test")/` could be emitted as an inferred endpoint. RC2 skips recognized regex literals and tests a positive real fetch beside the regex. Ambiguous grammar remains a bounded-known limitation: AI, adapters, and end-users must never promote inferred findings to observed facts without separate human verification.

## RC4 threat update: locally swapped FIFO
A locally hostile process could exchange an in-root regular file for a FIFO after Lstat and before an open, causing the CLI to block indefinitely. Native Linux reproduction confirmed 9/120 timed-out subprocesses against RC3. Unix RC4 uses `O_NONBLOCK|O_NOFOLLOW` for the final component followed by `fstat`/identity checks. This does **not** confine mutable ancestor directory components; the root must remain in a trusted and non-adversarial filesystem tree. Windows and other-platform fallback remains weaker and is not certified.


**RC9 evidence-boundary repair:** An attacker-controlled source file could label arbitrary local object methods `fetch`/`axios` and cause false network endpoint inferences in RC8. RC9 filters unknown property receivers and retains narrowly recognized bare/global call patterns; source provenance and `inferred` status remain mandatory. Shadowing and advanced member-expression resolution remain residual threats.

## RC10 synthetic ancestor symlink-swap threat

RC9 could be tricked into opening an out-of-root source file after path-based traversal by exchanging a child directory with a symlink. In local synthetic tests the output contained source SHA-256 values of the external fixture. Linux RC10 addresses this specific **content-reading** flaw with pinned root/relative `openat` directory descriptors and per-component `O_NOFOLLOW`; malicious concurrent swaps now fail without partial JSON or yield only inside-root source data in the tested cases. This does **not** attest that the path-name directory enumeration is atomic, prevent directory renames after FD open, stop hardlinks or root-controlled bind mounts, or certify portable macOS/Windows file access. The safe operational requirement remains a trusted directory tree; do not scan directories writable by an adversarial local process. ProofGraph adapters and AI must not treat these candidates as confirmed evidence.
