> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Architecture

CLI `cmd/jsmap` parses arguments without reflecting untrusted values and writes a single JSON report to stdout. Library `internal/jsmap` enumerates local files using `filepath.WalkDir`, rejects symlinks and oversized inputs, reads source data with inode identity verification, computes SHA-256 and lexes local JavaScript text. A conservative pattern matcher infers `fetch`/`axios.<verb>` calls with a **complete static first string argument**, checks HTTP(S)/relative URL syntax through Go `net/url`, strips query and userinfo, and returns deterministic findings in lexical path/byte order.

Data flow: local authorized tree → bounded regular-file read → UTF-8 check → SHA-256 → conservative lexer → static-call match → URL redaction → sorted, versioned JSON. No network interfaces; no code evaluation; no subprocess except user-initiated build/tests.

Bounded memory is limited per file (2 MiB source, 120k lexical tokens, 10k findings total); processing up to 1000 files can still use significant CPU and RAM. The CLI is single threaded. No persistent state. Re-run on identical source bytes produces identical JSON (verified by tests).

## Regex ambiguity guard (RC2)
A minimal regex-literal skip runs before quoted-string tokenization when the prior token is a known JavaScript expression starter. It respects escape sequences and character classes. Division expressions remain lexed normally. This conservative heuristic reduces false evidence but is not an ECMAScript parser; a full parser-oracle test remains open.

### RC10 Linux trust boundary

On Linux `Scan` pins the selected root with a no-follow directory FD, checks it against the previously observed inode and opens every intermediate child relative to that descriptor with `openat(O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK)`. The final file is opened with `openat(O_NONBLOCK|O_NOFOLLOW)` and matched to its `lstat` inode. Valid roots work as before, while raced-to-symlink files cause a generic error and no partial JSON. File discovery still uses path-based `WalkDir` and must not be confused with a fully atomic, descriptor-contained directory enumeration. Other OS fallbacks remain unqualified.
