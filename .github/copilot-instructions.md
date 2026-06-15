# Copilot Instructions for QWED

Read and follow [QWED_RULES.md](../QWED_RULES.md) for every suggestion.

Additional repository-specific rules:

- Do not suggest fallback execution paths.
- Do not suggest graceful degradation that continues past failed verification.
- Do not suggest retries that weaken enforcement.
- Do not trust model output as proof of correctness.
- Do not use scoring, confidence thresholds, or heuristics for decisions.
- Do not suggest `eval` / `exec` / `parse_expr` outside approved wrappers.
- Prefer fail-closed behavior over convenience or availability.
- Treat unresolved vulnerabilities as still critical — new layers are additive.

If a suggestion conflicts with QWED enforcement rules, the suggestion must be
rejected.
