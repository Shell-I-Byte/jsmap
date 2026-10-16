> Current public release and Mac validation status: [README](../README.md) and [MACOS_QUALIFICATION.md](MACOS_QUALIFICATION.md). Historical run references in this technical document do not describe the current publication status.

# Scope / authorization policy

JSMap accepts **only** a manually specified local root directory of JavaScript files. The operator is responsible for documenting their right to inspect those files. JSMap never expands scope through HTTP redirects, source maps, network links or inferred endpoints. No command runs against the extracted endpoints. Generated findings are hypotheses for later authorized manual review only.

Never use extracted routes to access third-party systems without explicit written authorization. If a downstream ProofGraph adapter exists, it MUST preserve these boundaries: `inferred` findings cannot become `confirmed` or `observed` without independently recorded authorized verification.
