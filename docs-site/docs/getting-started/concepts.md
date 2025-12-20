---
sidebar_position: 3
---

# Core Concepts

Understand the philosophy behind QWED.

## The Trust Model

QWED is built on a fundamental insight:

> **LLMs are probabilistic translators, not reasoning engines.**

```
┌─────────────────────────────────────────────────────────────┐
│                    QWED TRUST MODEL                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐        ┌─────────────┐        ┌─────────┐ │
│  │   USER      │        │     LLM     │        │  QWED   │ │
│  │  (Trusted)  │───────▶│ (Untrusted) │───────▶│(Trusted)│ │
│  └─────────────┘        └─────────────┘        └─────────┘ │
│        │                      │                     │      │
│     Query                Probabilistic          Verified   │
│                            Output               Result     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Key Principles

### 1. Determinism over Probability

QWED uses **symbolic engines** (Z3, SymPy) that provide mathematical guarantees:

| Engine | Technology | Guarantee |
|--------|------------|-----------|
| Math | SymPy | Algebraic correctness |
| Logic | Z3 | SAT/UNSAT proof |
| Code | AST | Pattern matching |
| SQL | Parser | Syntax validity |

### 2. Verification, Not Generation

QWED doesn't generate answers—it verifies them:

```python
# ❌ Wrong approach (generation)
answer = llm.ask("What is 2+2?")  # Might hallucinate

# ✅ QWED approach (verification)
answer = llm.ask("What is 2+2?")
verified = qwed.verify(answer)  # Deterministic check
```

### 3. Transparent Proofs

Every verification produces a verifiable proof:

```python
result = client.verify("x^2 - 1 = (x-1)(x+1)")
print(result.proof)
# {
#   "type": "algebraic_identity",
#   "steps": [...],
#   "hash": "sha256:abc123..."
# }
```

## Verification Statuses

| Status | Meaning |
|--------|---------|
| `VERIFIED` | Claim is correct, proof generated |
| `FAILED` | Claim is incorrect |
| `CORRECTED` | Claim was wrong, correction provided |
| `BLOCKED` | Security violation detected |
| `ERROR` | Verification engine failed |

## Attestations

QWED can produce **cryptographic attestations** (signed JWTs) that prove a verification occurred:

```python
result = client.verify("2+2=4", include_attestation=True)
print(result.attestation)
# eyJhbGciOiJFUzI1NiIs...
```

Attestations can be:
- Embedded in documents
- Stored on blockchain
- Verified by third parties

## Agent Verification

For AI agents, QWED provides **pre-execution verification**:

```python
# Agent wants to execute SQL
decision = agent_service.verify_action({
    "type": "execute_sql",
    "query": "DELETE FROM users"
})

if decision == "APPROVED":
    execute(query)
elif decision == "DENIED":
    abort("Dangerous query blocked")
```

## Next Steps

- [Verification Engines](/docs/engines/overview)
- [Attestation Spec](/docs/specs/attestation)
- [Agent Spec](/docs/specs/agent)
