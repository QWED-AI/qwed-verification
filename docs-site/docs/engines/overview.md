---
sidebar_position: 1
---

# Verification Engines

QWED provides 8 specialized verification engines.

## Engine Overview

| Engine | Type | Technology | Use Case |
|--------|------|------------|----------|
| **Math** | Deterministic | SymPy | Arithmetic, algebra, calculus |
| **Logic** | Deterministic | Z3 SMT | Logical constraints, SAT |
| **Code** | Deterministic | AST | Security vulnerabilities |
| **SQL** | Deterministic | SQLGlot | Query validation |
| **Stats** | Deterministic | SciPy | Statistical calculations |
| **Fact** | LLM-assisted | NLP | Factual claims |
| **Image** | LLM-assisted | Vision | Image content |
| **Reasoning** | LLM-assisted | CoT | Complex reasoning |

## Deterministic vs LLM-Assisted

### Deterministic Engines (No LLM Required)

These engines use symbolic computation and are 100% reproducible:

```python
# Math - uses SymPy
result = client.verify_math("x^2 - 1 = (x-1)(x+1)")
# Always returns the same answer

# Logic - uses Z3
result = client.verify_logic("(AND (GT x 5) (LT y 10))")
# Provably SAT or UNSAT
```

### LLM-Assisted Engines

These engines use LLMs for understanding but verify with deterministic checks:

```python
# Fact - NLI model + entailment
result = client.verify_fact(
    claim="Paris is in France",
    context="Paris is the capital of France."
)

# Reasoning - CoT decomposition + symbolic verification
result = client.verify("If all A are B, and all B are C, are all A C?")
```

## Engine Selection

QWED auto-detects the appropriate engine:

| Content Pattern | Detected Engine |
|----------------|-----------------|
| `2+2=4`, `sqrt(16)` | Math |
| `(AND ...)`, `(GT x 5)` | Logic |
| `SELECT`, `INSERT` | SQL |
| ` ```python ` , `import` | Code |
| Free text claims | Fact |

Or specify explicitly:

```python
result = client.verify("some query", type="math")
```

## Engine Details

- [Math Engine](/docs/engines/math)
- [Logic Engine](/docs/engines/logic)
- [Code Engine](/docs/engines/code)
- [SQL Engine](/docs/engines/sql)
- [Fact Engine](/docs/engines/fact)
- [Stats Engine](/docs/engines/stats)
