> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Evidence format `jsmap.result/v1`

Each `finding` is independent local-source evidence: `path` (root-relative slash-separated), `source_sha256` (hex SHA-256 of read file bytes), `byte_offset` (0-based byte position of the argument's opening quote in original UTF-8 source), `call` (matched lexical call family), `endpoint` (redacted URI reference), redaction flags, and `confidence` (`inferred` only). `scope` is always `local-files-only`. Empty result arrays remain `[]`.

The hash is a content digest not a signature. There are no timestamps, absolute source paths, random IDs, network observation, remote confirmation, user identity, replay guarantees against changing files, or fabricated AI conclusions.

Schema evolution: additive optional fields require compatibility analysis; breaking field/semantic changes require `jsmap.result/v2` and an explicit migration. Do not silently change `byte_offset`, redaction or confidence semantics. A future ProofGraph adapter maps these to typed `inferred` nodes/edges with provenance, without granting new authorization. No shared mutable IR library is linked.

RC2 does not modify `jsmap.result/v1`. Regex literal source text is not evidence of a fetch invocation; only locally inferred literal-call candidates are included. Source-byte SHA-256 and byte offsets remain required; all findings remain `inferred`.
