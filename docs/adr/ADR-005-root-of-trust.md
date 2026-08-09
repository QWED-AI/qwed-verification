# ADR-005: Root of Trust

**Status:** Proposed (open question — not yet decided)

## Context

QWED currently **self-attests**: the app signs verdicts with its own private key and
verifies them with the derived public key (single-node). This is circular trust —
*"trust QWED because QWED signed it."*

The category-defining question is:

> **What is the root of trust?**

This is the same question software supply-chain security had to answer (PKI →
Certificate Authorities → Sigstore / Fulcio / Cosign / Rekor). No system ships a
transparency log on day one, so self-attestation is an acceptable *stage* — but the
architecture must not be painted into a corner.

## Current decision (interim)

> **Self-attestation now, but designed transparency-log-ready.**

- Attestation is self-signed for the current single-node deployment.
- The attestation format and trust model MUST be designed so an **external witness /
  transparency log can be added later without a breaking change** (i.e. attestations
  are *externally witnessable*).

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
Attestations must remain **co-signable / appendable to a log**.

## Consequences

- Self-attestation is explicitly a stage, not the end state.
- The root-of-trust question is tracked, not buried.
- Future trust-anchor work is additive, not breaking.
