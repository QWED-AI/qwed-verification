# QWED Security Integration Contract v1.0

This contract defines how the QWED Security GitHub App / GitHub Action must consume
QWED Verification Context documents: v1.0, and v1.1, which a QWED server
returns signed (see [spec v1.1](../../spec/v1.1/verification-context.md)).

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

`verification_context` MUST be a schema-valid Verification Context document
(v1.0, or v1.1 with its `attestation`).

## Fail-closed rules

- Gate execution/shipping **exclusively** on `admission == "ADMIT"`.
- `VERIFIED` requires a resolvable `proof_ref`. If `proof_ref` is missing,
  malformed, or does not resolve, treat the result as fail-closed and `DENY`.
- `UNVERIFIABLE` and `BLOCKED` MUST always map to `DENY`.
- Schema validation failure MUST fail closed.
- Canonical encoding failure MUST fail closed.
- Never expose `UNVERIFIABLE` or `BLOCKED` as `ADMIT`.
- A resolvable `proof_ref` does not show who issued a document: anyone can
  compute one. Trust an `ADMIT` only from a v1.1 document whose
  `attestation` verifies against the issuing server's JWKS and signs this
  document; a document without one, or whose attestation fails, MUST be
  treated as `DENY`.

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
  - `qwed context validate [--jwks-file <jwks> | --server <url>] <file>`
  - `qwed context resolve [--jwks-file <jwks> | --server <url>] <file>`
  - `qwed context from-diagnostic --diagnostic-file <file> --query <query> --verifier <verifier>`

`POST /verification-context/from-diagnostic` records a diagnostic the caller
supplies; it does not vouch for it. The document's verdict is the
diagnostic's status (a `VERIFIED` one needs an attestation token that binds
the status, `proof_ref` and query, or the document is `BLOCKED`). The
caller's message and developer fields are kept under
`developer_fields.caller_supplied` and decide nothing. The admission is
`DENY` unless that token also signs `ADMIT` (`qwed.admission`), the server's
own admission of the verdict: then the document is `ADMIT`. Every document
it returns is v1.1, signed by the server (`attestation`).

`QWEDClient.validate_verification_context(...)` and
`QWEDClient.resolve_verification_context(...)` verify that attestation
against the server's JWKS before asking the server, by default: a document
with none is `{"valid": false, "error": "attestation_required"}` (or
`"resolved": false`), and one whose attestation does not verify or is not
this document's is `"attestation_invalid"`. Keys that cannot be fetched raise
`KeysUnavailableError`. Pass `require_attestation=False` to check the schema
or `proof_ref` alone.

`POST /verification-context/validate` and `/resolve` check the attestation
the same way by default, with the server's own key; send
`"require_attestation": false` to skip it. `qwed context validate` and
`qwed context resolve` check it with the keys of `--jwks-file` or `--server`;
a signed document with neither is `attestation_keys_required`, and
`--no-require-attestation` skips the check.

## Conformance expectations for other language SDKs

Other SDKs MUST:

1. Validate Verification Context documents against the JSON Schema of their
   `spec_version` (v1.0 or v1.1).
2. Derive and resolve `proof_ref` using the normative canonical encoding.
3. Reject unpaired UTF-16 surrogates, non-string object keys, non-finite numbers,
   and integers that do not round-trip through IEEE-754 doubles.
4. Fail closed on any validation or resolution error.
5. Never admit execution/shipping unless `admission == "ADMIT"`.
6. Verify a v1.1 document's `attestation` as spec v1.1 §4 describes before
   trusting its admission.
