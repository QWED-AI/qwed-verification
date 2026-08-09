# ADR-005: Root of Trust

**Status:** Proposed (open question — not yet decided)

## Context

QWED currently **self-attests**: each app process signs verdicts with its own
private key and verifies them with the derived public key. This is circular trust —
*"trust QWED because QWED signed it."*

**Deployed topology caveat (not a supported configuration):** the checked Kubernetes
deployment runs **multiple replicas**, and each `AttestationService` process creates
its **own in-memory ephemeral signing key**; no shared signing-key material or
replica key-resolution mechanism is provided. An attestation issued by one replica
therefore **fails verification on another replica**, so ordinary load balancing can
nondeterministically reject valid attestations. This multi-replica, per-process-key
topology is **not treated as supported** until signing keys are shared/persisted or
verifiers can resolve authenticated replica keys.

The category-defining question is:

> **What is the root of trust?**

This is the same question software supply-chain security had to answer (PKI →
Certificate Authorities → Sigstore / Fulcio / Cosign / Rekor). No system ships a
transparency log on day one, so self-attestation is an acceptable *stage* — but the
architecture must not be painted into a corner.

## Current decision (interim)

> **Self-attestation now, but designed transparency-log-ready.**

- Attestation is self-signed. The self-signature authenticates **only the canonical
  attestation bytes relative to the configured key.** It does **not** establish
  independent trust, validate the formal statement, reduce the verifier trusted
  computing base, increase proof strength, change the `VERIFIED` verdict, or imply
  admission.
- The attestation format and trust model MUST be designed so an **external witness /
  transparency log can be added later without a breaking change** (i.e. attestations
  are *externally witnessable*).
- Multi-replica deployments require **shared or persisted signing keys** (or
  authenticated replica-key resolution) before self-attestation is meaningful across
  replicas; until then, multi-replica attestation is unsupported.

## Open questions (to be resolved in a future ADR)

- **Who witnesses attestations?** A transparency log? A federation? A third-party
  notary?
- **What is the trust anchor** an enterprise can independently check?
- **How are attestations made independently verifiable** without trusting QWED's key
  custody?

## Why this matters

For enterprise adoption, a buyer must be able to verify a QWED attestation
**independently**, without trusting QWED. Self-attestation cannot provide that. The
direction of travel (sigstore / certificate-transparency model) is clear; the
specific scheme is a strategy decision deferred to a later ADR.

## Constraint adopted now

Do not make any design decision that prevents later adding an external trust anchor.

**Attestation envelope.** Attestations MUST use a **versioned, canonical payload**
that binds, at minimum: the formal statement, the complete Verification Context
(per [ADR-002](ADR-002-verification-context.md)), verifier + version, evidence,
`proof_ref`, verdict, admission, key identity, and freshness (issued-at / expiry /
nonce). The payload is canonicalized so the signature is reproducible. This binding
prevents a future external witness from reinterpreting or replaying an attestation.

**Witness semantics.** A transparency log adds an **inclusion proof** (the
attestation was recorded); it does **not** co-sign the payload. A **co-signature**
(a second signature over the same canonical payload by an independent key) is a
distinct, stronger guarantee. The two must not be conflated.

## Consequences

- Self-attestation is explicitly a stage, not the end state.
- The root-of-trust question is tracked, not buried.
- Future trust-anchor work is additive, not breaking.
