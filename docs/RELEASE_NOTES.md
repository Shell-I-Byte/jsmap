> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

## JSMap v0.1.0-rc12 — audit 204 (2026-10-15)
BUG-JM-204-001: offline JS endpoint inference incorrectly accepted malformed HTTP(S) and protocol-relative bracketed authorities that the WHATWG URL host parser cannot interpret for browser fetch requests. RED against unmodified RC11: six negative Go subtests failed and the CLI emitted five false inferred candidates. RC12 checks valid IPv6-only brackets without zones via net/netip; positives preserve valid IPv6, IPv4-mapped IPv6, ordinary hosts, URL paths, query redaction, source hash and byte offsets. The schema jsmap.result/v1 is unchanged, and all findings stay `inferred`. Regression: TestBracketedHTTPAuthorityValidation and tests/authority_cli_probes.py in pinned CI. No supported Go/native CI/analyzer/publisher provenance success claimed.

## JSMap v0.1.0-rc11 — audit 191 (2026-10-15)
BUG-JM-191-001 corrected a demonstrated false endpoint finding from ECMAScript `#fetch`/`#axios` class-private member calls. Original RC10 emitted candidates for private no-network methods. Patched RC11 preserves genuine bare and simple global calls; Node syntax check, Go RED→GREEN, independent CLI positive/negative/deterministic/hash/offset controls and post-seal source tests provide local proof. No evidence schema change (`jsmap.result/v1`); every emitted finding remains `inferred`. No native macOS/Windows/Linux ARM64 runtime results or supported Go/analyzer/CI outcomes are claimed. Module identity and publisher provenance remain OPEN.

## JSMap v0.1.0-rc10 — audit 165 (2026-10-14)
Linux ancestor symlink-swap containment repair (BUG-JM-165-001). Original RC9 confirmed reading 235 synthetic out-of-root source findings / 600 scans. After rooted relative component opens, no out-of-root source content findings in 600 baseline stress cases or 300 independent CLI cases. Go unit coverage exercises legitimate nested files, symlink parent denial, path traversal denial, and source root inode pinning across path replacement. No schema change (`jsmap.result/v1`). Remaining open: movable directory races, directory enumeration snapshots, hardlink/mount escape, native macOS/Windows fallback, supported Go, Staticcheck/Govulncheck, canonical module ID, publisher provenance, GitHub CI results. No GitHub publication. Retain old reports as potentially contaminated when scanned roots were adversarially mutable.

## JSMap v0.1.0-rc9 — run 150 (2026-10-13)

FIX BUG-JM-150-001: RC8 treated arbitrary `object.fetch('/...')` and `object.axios.get('/...')` member calls as network endpoint evidence, even when valid local JS defined those methods as inert return functions. After false-positive reproduction on the unmodified RC8 binary (7/9 Go cases RED; independent CLI RED), RC9 conservatively accepts bare calls and only simple browser-global `window`/`self`/`globalThis` accessors. Arbitrary and nested owners no longer yield endpoint candidates; verified syntactic examples retain genuine bare and simple global references. New property-call CLI test and nine Go fixtures cover positives, negatives, hashes, offsets and JSON determinism. The contract `jsmap.result/v1` stays unchanged and confidence remains `inferred`. This is not a full dataflow parser; shadowed globals and other lexing limitations remain. Local Linux Go1.23.2 only; supported Go/security analyzers/native OS and publisher identity still require evidence. No network scan or GitHub push.

## JSMap v0.1.0-rc8 — run 138 (2026-10-13)

One confirmed medium false-inference bug fixed. Valid ECMAScript `/fetch("\x2fphantom")/` statements immediately after named function/class declarations or `switch`/`catch` blocks are suppressed, not reported as endpoint calls. Tests include Node v22 syntax checks, positive real `fetch('/real')`, and division expression falsifications. Original RC7 reproduced 6/10 failures. `jsmap.result/v1` stays unchanged and all evidence confidence is `inferred`. Local Linux runtime only. Supported Go/security analyzers/native platforms remain BLOCKED/UNTESTED. No network scan or GitHub publication.

## JSMap v0.1.0-rc7 — run 117 (2026-10-12)
Fixes false endpoint inference inside valid RegExp literals following `if/while/for/with` conditions and `else`/`do` statement beginnings. RC5 failed seven out of eight targeted Go regressions; classic JavaScript syntax was independently accepted by Node v22. The repaired heuristic recognizes matching control-head parentheses while keeping ordinary `/` division separate. This is not a full ECMAScript parser. Reports remain local, offline, hash-provenanced, and `inferred`. Supported Go/CI/static security analyzers and native other-platform evidence remain blocked or untested; v1 is not certified. No GitHub publication.

## JSMap v0.1.0-rc5 — run 105 (2026-10-11)
Fixes Annex B HTML-like comment false positives in local JS source. The prior rc4 fabricated endpoint references from comment-only `fetch()` strings; `<!--` and line-initial `-->` now discard line text conservatively. Regression tests use valid Node.js classic scripts as an independent grammar oracle. Output contract `jsmap.result/v1` remains unchanged. All findings remain inferred, not verified routes. Supported Go/security-analyzer/native CI and ancestor filesystem-race gates remain open; no stable v1 claim.

# JSMap v0.1.0-rc3 — run 075 (2026-10-10)

- FIX BUG-JM-075-001: a valid Unicode-prefixed identifier (`πfetch`, `℘fetch`, `πaxios`) was incorrectly split into a non-ASCII prefix and the ASCII function name, inventing candidate endpoint findings. Reproduced against sealed RC2; new Go regression RED → GREEN and independent CLI controls.
- The lexer now consumes ECMAScript Unicode ID_Start/ID_Continue approximations as full identifier tokens, including Unicode combining marks and U+200C/U+200D continuation. Source hashes and original UTF-8 byte offsets remain attached.
- Evidence schema `jsmap.result/v1` unchanged. All findings remain inferred and offline. No third-party targets scanned.
- Supported Go/analyzer/native platform gates and final repository/module identity remain blocked or untested; no stable v1 claim and no GitHub publication.
- Full ECMAScript lexing, escaped identifier names, shadowed fetch calls and AST completeness remain out of scope.

# JSMap v0.1.0-rc2 — run 066 (2026-10-10)

- FIX BUG-JM-066-001: regular-expression source text with fetch()/axios-like fragments no longer fabricates findings when regex literal begins at recognized expression-start positions. Reproduced independently against rc1; new Go and CLI tests added.
- FIX BUG-JM-066-002: `-h`, `-help`, `--help` return safe help and exit code 0 (not invalid arguments/2). Unknown options still return exit 2 without reflecting attacker-controlled flags.
- CI checkout/setup-go pinned by verified full commit references; supported toolchain, staticcheck, govulncheck and native macOS/Windows **not executed** in this local release round.
- Unchanged `jsmap.result/v1` schema; zero external targets or network probing.
- Known unresolved: provisional Go module import path `github.com/Shell-I-Byte/jsmap`, incomplete ECMAScript grammar oracle and filesystem mutation race; all release blockers remain open.
- No stable v1 publication or GitHub push.

## JSMap v0.1.0-rc4 — run 091 (2026-10-11)
RC4: targeted availability fix for local FIFO replacement between lstat and open, with regression coverage and sealed-source reconstruction. No schema change. Release blocked pending supported-toolchain/security-analyzer/native CI and complete path-confinement review.
RC4 build evidence: `-trimpath -buildvcs=false` is the canonical comparable binary mode. Default Git binaries may contain VCS metadata; this expected mismatch was verified and corrected in the reproducibility procedure.

## RC7 — validated local remediation (2026-10-12)
Fix false endpoint evidence following closing control-flow braces. Independent Node v22 parser oracle and positive/division negative controls; no schema changes. Local Linux runtime tested under Go 1.23.2 only; native supported Go and CI remain blocked.
