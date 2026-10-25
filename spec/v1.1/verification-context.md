# QWED Verification Context Specification v1.1

**Version:** 1.1 (Draft)
**Status:** Draft, pending review
**Extends:** [v1.0](../v1.0/verification-context.md)
**Machine-readable schema:** [`schemas/verification-context.schema.json`](schemas/verification-context.schema.json)

---

## 1. What v1.1 adds

v1.1 is v1.0 plus one field: `attestation`, the signature of the server that
issued the document. Everything else in v1.0 (the verified object, the four
context layers, `proof_ref` and its canonical encoding, the verdict, the
admission, conformance) is normative for v1.1 unchanged. This is an additive
change, so the minor version is bumped (see the versioning policy in
[`../README.md`](../README.md)).

A v1.0 document's `proof_ref` is an **unkeyed** commitment: anyone can compute
it, so anyone can build a document, an `ADMIT` one included, whose `proof_ref`
resolves. It shows the document is internally consistent, not who issued it.
`attestation` is what shows that.

## 2. The `attestation` field

A v1.1 document MUST carry `attestation`, a compact JWS (a JWT) with:

- **Header:** `alg` `ES256`, `typ` `qwed-context+jwt`, and `kid` naming the
  issuer's signing key. The `typ` separates it from a verdict's attestation
  (`qwed-attestation+jwt`): neither is accepted as the other.
- **Claims:** `iss` (the issuer), `sub` (the document hash), `iat`, `exp`,
  `jti`, and `qwed`:

  | Claim | Value |
  |-------|-------|
  | `qwed.version` | `"1.1"` |
  | `qwed.document_hash` | the document hash (§3) |
  | `qwed.verdict` | the document's `verdict` |
  | `qwed.admission` | the document's `context.decision.admission` |
  | `qwed.proof_ref` | the document's `context.evidence.proof_ref` (`null` unless `VERIFIED`) |

A v1.0 document MUST NOT carry `attestation`, and a v1.1 document without it
is invalid. A document that cannot be signed (a library building one
locally, with no issuer key) is a v1.0 document.

## 3. The document hash

The document hash is `"sha256:"` followed by the lowercase hex SHA-256 of the
canonical encoding (v1.0 §3.3) of the **whole document except
`attestation`**. It therefore binds the formal statement and formalization,
the complete Verification Context (verifier and version, evidence,
`proof_ref`, admission), the verdict and `spec_version`. Changing any of them
changes the hash.

## 4. Verifying a document

A consumer verifies a v1.1 document by checking, in order:

1. The signature, with an ES256 P-256 key from the issuer's JWKS
   (`GET /.well-known/jwks.json` on a QWED server), and that the verified
   header's `kid` names that key and its `typ` is `qwed-context+jwt`.
2. The issuer, and that the token has not expired (nor is used before any
   `nbf`). The token lasts as long as a verdict's attestation
   (`QWED_ATTESTATION_TTL_SECONDS`, 24 hours by default): an expired document
   is obtained again, not trusted.
3. That `qwed.document_hash` is the hash of this document (§3), and that
   `qwed.verdict`, `qwed.admission` and `qwed.proof_ref` are this document's.

Only then is the document the issuer's. A consumer that gates on
`admission == "ADMIT"` (v1.0 §5) SHOULD require a verified attestation, as
the QWED Python SDK's `validate_verification_context` and
`resolve_verification_context` do by default.

## 5. What the attestation does not do

The attestation inherits the limits of v1.0 §6 (Root of Trust). It
authenticates the document **relative to the issuer's key**. It does not
validate the formal statement, strengthen the proof, change the verdict or
imply admission: a signed `DENY` document is still `DENY`. It does not
replace schema validation or `proof_ref` resolution, which a consumer still
performs. The issuer self-attests; an independent witness remains an open
question (ADR-005).

## 6. Conformance

An implementation conforms to v1.1 if it conforms to v1.0, with
[`schemas/verification-context.schema.json`](schemas/verification-context.schema.json)
in place of the v1.0 schema for v1.1 documents, and:

1. Every v1.1 document it emits carries an `attestation` as in §2, over the
   hash in §3.
2. When it verifies a v1.1 document, it performs every check in §4 and fails
   closed on any failure.
3. It never accepts a verdict's attestation as a document's, nor the reverse.
