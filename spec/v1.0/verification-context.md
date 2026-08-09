# QWED Verification Context Specification

**Version:** 1.0 (Draft)
**Status:** Draft — pending review
**Derived from:** ADR-001..005
**Machine-readable schema:** [`schemas/verification-context.schema.json`](schemas/verification-context.schema.json)

---

## 1. Overview

This specification defines the **Verification Context** — the atomic record of a
QWED verification. It standardizes *what is being verified*, *what it means*, *how
it was proven*, *on what evidence*, and *what decision followed*, so that every
QWED engine, SDK, API, CLI, and client speaks one protocol.

A Verification Context document is a single JSON object conforming to the JSON
Schema in [`schemas/verification-context.schema.json`](schemas/verification-context.schema.json).

### Design goals

- **One protocol.** Every verification surface emits the same shape.
- **Fail-closed.** Anything not proven is `UNVERIFIABLE` or `BLOCKED`, never
  `VERIFIED`.
- **Truth ≠ admission.** A proven verdict and a safe-to-run decision are separate.
- **Honesty.** QWED never claims to have verified intent; it verifies a formal
  statement and shows you exactly what was proven.

---

## 2. The Verified Object

> **The Verified Object is the formal statement being evaluated.**
> *(ADR-001)*

The object of verification is a **formal statement** — e.g. `∀x. x + 0 = x` or
`x² − 4 = 0`. It is captured in `object.formal_statement`.

### The theory is required interpretation context

A formal statement is only *meaningful* relative to a theory/interpretation.
`x² = 4` over the reals, over integers mod 5, and over bitvectors are different
propositions. Therefore the theory/logic/dialect belongs in the **Interpretation**
layer of the context (see §3.1), not in the object. The object is the statement;
the theory is what gives it meaning.

### Prover independence is semantic, not textual

Changing the prover does not change the semantic proposition **when both provers
encode the same proposition under equivalent theories and encodings** (e.g. Lean
vs Coq proving the same theorem). A different logic, axiom set, or formal encoding
can change the proposition, so the formal encoding and Verification Context remain
necessary to interpret and reproduce the object.

### The formalization is exposed but never verified

QWED never claims *"we verified your intent."* It claims *"we verified THIS formal
statement."* The mapping from natural language to the formal statement (the
**formalization**) is surfaced in `object.formalization` for confirmation but is
**never itself verified** (`object.formalization.verified` is always `false`).
*(ADR-004)*

---

## 3. The Verification Context

> **The Verification Context is all information required to correctly interpret,
> reproduce, and trust a verification.** *(ADR-002)*

It has four layers, captured in `context`:

| Layer | Field | Contents | Role |
|-------|-------|----------|------|
| Interpretation | `context.interpretation` | theory / logic / dialect / algebra domain | Gives the object meaning |
| Proof | `context.proof` | verifier + version + config + theory scope + trusted deps | How the object was discharged; sets proof strength |
| Evidence | `context.evidence` | evidence + `proof_ref` | What was checked; evidence integrity |
| Decision | `context.decision` | admission | The safe-to-run outcome |

### 3.1 Interpretation layer

`context.interpretation` records the theory / logic / dialect / algebra domain the
statement is interpreted under. It is **required to interpret** the object. Each
engine exposes only the interpretation it needs:

- Theorem prover → theory, logic
- SQL → dialect, parser version
- Code → language, policy version
- Symbolic math → algebra domain

### 3.2 Proof layer

`context.proof` records the discharge. **The verifier is the trusted computing
base (TCB).** A proof discharged by SymPy (large TCB) is a different-strength
guarantee than one checked by Lean/Coq (small trusted kernel). Declaring the
verifier declares how much to trust the proof.

The Proof layer records the full trust boundary:

- `verifier` + `verifier_version` — the exact engine and release.
- `configuration` — solver flags, timeouts, resource limits.
- `theory_scope` — the logic / axiom set the discharge is relative to.
- `trusted_dependencies` — libraries/components inside the TCB.
- `outcome_treatment` — how `unknown`/`timeout`/`error` outcomes are treated.
  These are **never** `VERIFIED`; they resolve to `UNVERIFIABLE` or `BLOCKED`
  (fail-closed). Soundness/determinism claims apply **only** to supported
  configurations that produce a definitive proof outcome.

### 3.3 Evidence layer and `proof_ref`

`context.evidence.evidence` is the retained evidence. `context.evidence.proof_ref`
is the **evidence commitment**.

> **`proof_ref`** is an immutable commitment to the verification evidence. It
> provides **evidence integrity and reproducibility**. It is **not itself the
> mathematical proof.** *(ADR-002)*

**What it binds.** `proof_ref` commits to the formal statement together with the
complete Verification Context — interpretation, proof, evidence, and decision —
**with the `proof_ref` field itself excluded** (see below). Changing any bound
field changes the commitment.

**How it is computed.**

- **Bound payload (normative):** the JSON object
  `{"formal_statement": <object.formal_statement>, "context": <context>}`, with
  `context.evidence.proof_ref` **removed** before serialization. Note
  `object.formalization` is deliberately **not** part of the bound payload — the
  commitment binds the formal statement, not how it was derived. The commitment
  cannot include itself: hashing a payload that contains the stored digest would
  require a SHA-256 fixed point, which is not a normal content-addressed hash.
  Producers and resolvers MUST both use this exact payload definition.
- **Canonical encoding (normative, v1.0):** the bound payload is serialized as
  JSON with **all** of the following, so any two implementations derive identical
  bytes:
  - UTF-8 representation, **no** ASCII-escaping of non-ASCII characters
    (`ensure_ascii=False`).
  - Object keys MUST be strings; non-string keys are rejected. Keys are sorted
    by their UTF-16 big-endian byte representation (UTF-16 code-unit order), not
    by Unicode code-point order.
  - Strings MUST NOT contain unpaired UTF-16 surrogates (U+D800..U+DFFF); such
    values cannot be encoded as UTF-8 and MUST be rejected.
  - Compact separators with no whitespace: `","` between items and `":"` between
    key and value (`separators=(",", ":")`).
  - **Canonical numbers (normative):** every number is an IEEE-754 double and is
    serialized per **RFC 8785 §3.2.2** (ECMAScript `Number::toString`): the
    shortest decimal form that round-trips the double, with fixed-point notation
    for exponents in `[-6, 21]` and exponential notation otherwise (e.g.
    `1e-6` → `0.000001`, `1e-7` → `1e-7`, `1e21` → `1e+21`). This makes `1`
    and `1.0` commit identically and normalizes negative zero (`-0.0`) to `0`.
    1. **Reject non-finite values.** `NaN`, `+Infinity`, and `-Infinity` are not
      permitted in the bound payload; producers MUST fail-closed rather than
      serialize them.
    2. **Reject integers that are not exactly representable as IEEE-754
      doubles.** An integer value MUST be rejected if converting it to a double
      and back changes its value; arbitrary-precision integer serialization is
      not permitted.
    Producers MUST NOT emit `NaN`/`Infinity` (fail-closed instead). Note that
    Python's `json.dumps` does **not** implement this number form (it emits
    `1e-07` / `1e-06`); implementations MUST use an RFC 8785-compatible number
    serializer.
  - No ambient/non-deterministic fields (wall-clock time, memory addresses,
    randomness) in the bound payload.
  The canonical encoding is RFC 8785 (JSON Canonicalization Scheme): UTF-8,
  UTF-16 big-endian sorted object keys, no insignificant whitespace, and the
  number form above.
- **Commitment algorithm:** SHA-256 of the canonical encoding bytes, expressed as
  `sha256:<64-lowercase-hex>`.

This is the **single canonical commitment** for the Verification Context protocol:
producers and resolvers MUST use this exact bound payload + encoding + algorithm.
It is distinct from any engine-internal evidence hashing (e.g. a
`compute_proof_ref` over evidence alone); a Verification Context `proof_ref`
always commits to the whole bound payload defined above.

**Resolution and failure semantics.**

- A consumer **resolves** `proof_ref` by removing `context.evidence.proof_ref`,
  re-deriving the commitment from the supplied formal statement + remaining
  Verification Context + evidence using the canonical encoding above, and comparing
  it to the stored value.
- A resolver MUST reject a mismatch **before** any `ADMIT` decision.
- A resolver MUST treat any failure while deriving the canonical encoding
  (unencodable number, unpaired surrogate, or non-string key) as failed
  resolution. Schema validation alone is not sufficient to accept a `VERIFIED`
  record; the stored `proof_ref` MUST resolve.
- **Missing, malformed, or mismatched** evidence/commitment is treated as
  **unverified (fail-closed)** — never as verified. A `proof_ref` that cannot be
  resolved confers no authority.

---

## 4. Verdict

> The verdict is the truth judgment. *(ADR-001, ADR-002)*

`verdict` is one of:

| Verdict | Meaning | `proof_ref` |
|---------|---------|-------------|
| `VERIFIED` | The claim was checked and proven. | **non-null** (`sha256:<64-hex>`) |
| `UNVERIFIABLE` | Not proven (fail-closed). | `null` |
| `BLOCKED` | Verification could not be attempted/completed (fail-closed). | `null` |

**Invariants** (enforced by the schema):

- `verdict == VERIFIED` ⟹ `context.evidence.proof_ref` is present and matches
  `^sha256:[a-f0-9]{64}$`.
- `verdict ∈ {UNVERIFIABLE, BLOCKED}` ⟹ `context.evidence.proof_ref` is `null`.

A `VERIFIED` verdict is a **truth guarantee**, not an admission guarantee (see §5).

---

## 5. Admission (Truth ≠ Admission)

> **`VERIFIED` is a truth guarantee, not an admission guarantee. Admission is a
> separate decision.** *(ADR-003)*

`context.decision.admission` is one of `ADMIT` / `DENY`. It is the safe-to-run /
safe-to-ship decision, computed from the verdict plus policy.

**VERIFIED-as-unsafe.** A proven-unsafe artifact is `VERIFIED` (we *proved* it is
unsafe) with admission `DENY`. This is the critical case a conflated model gets
wrong.

**Gating.** Execution and shipping consumers gate **exclusively** on
`admission == "ADMIT"`. `is_valid` contributes to the admission decision but is
**not** an alternative authorization gate — a valid statement can still be denied
by policy.

| Verdict | Truth | Admission (typical) |
|---------|-------|---------------------|
| `VERIFIED`, valid | proven safe | `ADMIT` |
| `VERIFIED`, unsafe | proven unsafe | **`DENY`** |
| `UNVERIFIABLE` | not proven | `DENY` (fail-closed) |
| `BLOCKED` | verification failed | `DENY` (fail-closed) |

---

## 6. Root of Trust

> **What is the root of trust?** *(ADR-005)*

QWED currently **self-attests**: each app process signs verdicts with its own
private key. This is circular trust and an interim stage.

**Self-signature limits.** The self-signature authenticates **only the canonical
attestation bytes relative to the configured key.** It does **not** establish
independent trust, validate the formal statement, reduce the verifier TCB, increase
proof strength, change the `VERIFIED` verdict, or imply admission.

**Attestation envelope.** Attestations MUST use a **versioned, canonical payload**
binding, at minimum: the formal statement, the complete Verification Context,
verifier + version, evidence, `proof_ref`, verdict, admission, key identity, and
freshness (issued-at / expiry / nonce). This binding prevents a future external
witness from reinterpreting or replaying an attestation.

**Witness semantics.** A transparency log adds an **inclusion proof** (the
attestation was recorded); it does **not** co-sign the payload. A **co-signature**
(a second signature over the same canonical payload by an independent key) is a
distinct, stronger guarantee. The two must not be conflated.

**Multi-replica caveat.** Multi-replica deployments require shared or persisted
signing keys (or authenticated replica-key resolution) before self-attestation is
meaningful across replicas; until then, multi-replica attestation is unsupported.

The root of trust (who witnesses attestations, the independent trust anchor) is an
**open question** resolved in a future ADR.

---

## 7. Conformance

An implementation **conforms** to this specification if:

1. It emits Verification Context documents that validate against
   [`schemas/verification-context.schema.json`](schemas/verification-context.schema.json).
2. It upholds the verdict invariants (§4): `VERIFIED` ⟹ non-null `proof_ref`;
   `UNVERIFIABLE`/`BLOCKED` ⟹ `null` `proof_ref`.
3. It treats `proof_ref` as an evidence commitment, not a proof of truth (§3.3).
4. It separates truth from admission (§5) and gates execution on
   `admission == "ADMIT"` only.
5. It exposes the formalization but never marks it verified (§2, ADR-004).
6. It treats `unknown`/`timeout`/`error` outcomes as fail-closed (§3.2).

---

## 8. Example documents

See [`schemas/verification-context.schema.json`](schemas/verification-context.schema.json)
for the normative schema and the conformance test suite
(`tests/test_verification_context_spec.py`) for valid and invalid examples.

---

## Appendix: Mapping to ADRs

| Section | ADR |
|---------|-----|
| §2 The Verified Object | ADR-001 |
| §3 Verification Context, `proof_ref` | ADR-002 |
| §5 Admission | ADR-003 |
| §2 Formalization | ADR-004 |
| §6 Root of Trust | ADR-005 |
