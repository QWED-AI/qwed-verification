# QWED Specifications

Normative specifications for the QWED verification protocol. These documents
define *what verification is* — the vocabulary and contracts every QWED engine,
SDK, API, CLI, and client speaks.

The ontology is frozen by the [Architecture Decision Records](../docs/adr/README.md);
the specifications here make it precise and machine-readable.

## Versions

| Version | Document | Status |
|---------|----------|--------|
| [v1.0](v1.0/verification-context.md) | Verification Context | Draft |
| [v1.1](v1.1/verification-context.md) | Verification Context, signed by its issuer | Draft |

## Verification Context v1.0

The **Verification Context** is the atomic record of a QWED verification: the
object of verification plus the context required to interpret, reproduce, and
trust it.

- **Prose specification:** [`v1.0/verification-context.md`](v1.0/verification-context.md)
- **Machine-readable schema:** [`v1.0/schemas/verification-context.schema.json`](v1.0/schemas/verification-context.schema.json)
- **Conformance tests:** [`../tests/test_verification_context_spec.py`](../tests/test_verification_context_spec.py)

## Verification Context v1.1

v1.1 adds `attestation`: the issuing server's ES256 signature over the whole
document, which a v1.0 `proof_ref` (an unkeyed commitment anyone can
compute) cannot show. A QWED server returns v1.1 documents.

- **Prose specification:** [`v1.1/verification-context.md`](v1.1/verification-context.md)
- **Machine-readable schema:** [`v1.1/schemas/verification-context.schema.json`](v1.1/schemas/verification-context.schema.json)
- **Tests:** [`../tests/test_issue_319_vc_authenticity.py`](../tests/test_issue_319_vc_authenticity.py)

### Core vocabulary

- **Verified Object** — the formal statement being evaluated.
- **Verification Context** — interpretation + proof + evidence + decision.
- **Verdict** — `VERIFIED` / `UNVERIFIABLE` / `BLOCKED`.
- **Admission** — `ADMIT` / `DENY` (truth ≠ admission).
- **proof_ref** — an evidence commitment, not a mathematical proof.
- **Formalization** — the NL→formal mapping; exposed but never verified.

## Versioning policy

- Specifications are versioned (`v1.0`, `v1.1`, …). Breaking changes bump the
  major version; additive changes bump the minor version.
- Each version is immutable once released. New versions live in a new directory
  (`v1.1/`, `v2.0/`, …).
- Conformance is defined per version in the specification's Conformance section.
