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

## How Translation Works

This is the key to understanding QWED. Let's walk through a real example:

### Example: Verifying a Mathematical Claim

**User asks:** *"Is it true that the sum of interior angles in a triangle equals 180 degrees?"*

```
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 1: Natural Language Query                                     │
│  ────────────────────────────────────────────────────────────────── │
│  "Is it true that the sum of interior angles in a triangle          │
│   equals 180 degrees?"                                               │
└────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 2: LLM Translation (Untrusted)                                │
│  ────────────────────────────────────────────────────────────────── │
│  LLM converts to QWED-Logic DSL:                                    │
│                                                                     │
│  (EQ (PLUS angle_a angle_b angle_c) 180)                           │
│                                                                     │
│  ⚠️ This translation MIGHT be wrong - LLM is not trusted!          │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 3: QWED Verification (Deterministic)                          │
│  ────────────────────────────────────────────────────────────────── │
│  Z3 Solver: Given angle_a + angle_b + angle_c = 180                 │
│             Is this satisfiable? → YES (SAT)                        │
│             Model: {angle_a: 60, angle_b: 60, angle_c: 60}          │
│                                                                     │
│  ✅ Mathematically proven. Deterministic. Repeatable.               │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 4: Response                                                   │
│  ────────────────────────────────────────────────────────────────── │
│  {                                                                  │
│    "verified": true,                                                │
│    "status": "SAT",                                                 │
│    "model": {"angle_a": 60, "angle_b": 60, "angle_c": 60},          │
│    "proof": "Sum of angles = 60 + 60 + 60 = 180 ✓"                  │
│  }                                                                  │
└─────────────────────────────────────────────────────────────────────┘
```

### Translation Examples

| Natural Language | QWED-Logic DSL | Engine |
|------------------|----------------|--------|
| "x is greater than 5" | `(GT x 5)` | Z3 |
| "Is 2+2 equal to 5?" | `(EQ (PLUS 2 2) 5)` | SymPy |
| "x squared plus y squared = 25" | `(EQ (PLUS (POW x 2) (POW y 2)) 25)` | Z3 |
| "If raining, take umbrella" | `(IMPLIES raining umbrella)` | Z3 |

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

