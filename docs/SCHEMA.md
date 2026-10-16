> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# JSON schema

See `schema/result.schema.json`. Use a local JSON Schema draft 2020-12 validator to independently validate reports; current Go tests only verify the fields/JSON serialization and separate independent CLI probes enforce expected outputs. An independent validator library is not bundled to keep the binary offline/stdlib-only.
