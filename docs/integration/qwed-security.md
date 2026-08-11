# QWED Security Integration Contract v1.0

This contract defines how the QWED Security GitHub App / GitHub Action must consume
QWED Verification Context v1.0 documents.

## Output envelope

QWED Security surfaces should render this envelope:

```json
{
  "verification_context": { },
  "verdict": "VERIFIED | UNVERIFIABLE | BLOCKED",
  "admission": "ADMIT | DENY",
  "proof_ref": "sha256:<64-hex> or null",
  "resolved": true
}
```

`verification_context` MUST be a schema-valid Verification Context v1.0 document.

## Fail-closed rules

- Gate execution/shipping **exclusively** on `admission == "ADMIT"`.
- `VERIFIED` requires a resolvable `proof_ref`. If `proof_ref` is missing,
  malformed, or does not resolve, treat the result as fail-closed and `DENY`.
- `UNVERIFIABLE` and `BLOCKED` MUST always map to `DENY`.
- Schema validation failure MUST fail closed.
- Canonical encoding failure MUST fail closed.
- Never expose `UNVERIFIABLE` or `BLOCKED` as `ADMIT`.

## QWED verification surfaces

- API:
  - `POST /verification-context/from-diagnostic`
  - `POST /verification-context/validate`
  - `POST /verification-context/resolve`
- Python SDK:
  - `QWEDClient.create_verification_context_from_diagnostic(...)`
  - `QWEDClient.validate_verification_context(...)`
  - `QWEDClient.resolve_verification_context(...)`
- CLI:
  - `qwed context validate <file>`
  - `qwed context resolve <file>`
  - `qwed context from-diagnostic --diagnostic-file <file> --query <query> --verifier <verifier>`

## Conformance expectations for other language SDKs

Other SDKs MUST:

1. Validate Verification Context documents against the v1.0 JSON Schema.
2. Derive and resolve `proof_ref` using the normative canonical encoding.
3. Reject unpaired UTF-16 surrogates, non-string object keys, non-finite numbers,
   and integers that do not round-trip through IEEE-754 doubles.
4. Fail closed on any validation or resolution error.
5. Never admit execution/shipping unless `admission == "ADMIT"`.
