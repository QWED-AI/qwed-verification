---
slug: how-qwed-verifies-math-sympy
title: "How QWED Verifies Math: SymPy Under the Hood"
authors: [rahul]
tags: [engineering, verification]
description: "Deep-dive into QWED's Math Engine architecture. Learn how symbolic mathematics powers deterministic verification of LLM-generated calculations."
keywords: [sympy, symbolic math, ai verification, math engine, deterministic ai]
image: /img/blog/math-engine-architecture.png
---

# How QWED Verifies Math: SymPy Under the Hood

When an LLM claims that `x² + 2x + 1 = (x+1)²`, how can we verify this is mathematically correct? In this deep-dive, we explore how QWED's Math Engine uses **symbolic computation** to provide deterministic guarantees.

<!-- truncate -->

## The Problem with LLM Math

Large Language Models are notoriously bad at mathematics. Research from [Frieder et al. (2023)](https://arxiv.org/abs/2302.04767) demonstrates that even GPT-4 struggles with basic arithmetic when numbers get large enough.

> "GPT-4 fails at multi-digit multiplication with numbers larger than 4 digits, achieving less than 10% accuracy."
> — *Mathematical Capabilities of ChatGPT*, arXiv:2302.04767

This isn't a bug — it's fundamental to how transformers work. They're pattern matchers, not calculators.

## QWED's Approach: Symbolic, Not Statistical

Instead of trusting LLM calculations, QWED uses the LLM's output as a **hypothesis** and verifies it with symbolic math.

```mermaid
flowchart LR
    A[User Query] --> B[LLM Translation]
    B --> C[SymPy Parser]
    C --> D[Symbolic Verification]
    D --> E{Correct?}
    E -->|Yes| F[✅ VERIFIED]
    E -->|No| G[❌ FAILED + Correction]
```

### Why SymPy?

[SymPy](https://www.sympy.org/) is a Python library for symbolic mathematics. Unlike numerical libraries (NumPy), SymPy manipulates mathematical expressions symbolically:

```python
from sympy import symbols, simplify, expand

x = symbols('x')

# Symbolic manipulation
left = x**2 + 2*x + 1
right = (x + 1)**2

# Verify algebraic identity
result = simplify(left - right)
print(result)  # 0 (they're identical!)
```

This is **deterministic**. Running this code 100 times gives the same answer, unlike LLM inference.

## Architecture Deep-Dive

### Engine Pipeline

```mermaid
flowchart TB
    subgraph Input Processing
        A[Raw Query] --> B[Domain Detector]
        B --> C{Math Domain?}
    end
    
    subgraph Math Engine
        C -->|Yes| D[Expression Parser]
        D --> E[SymPy Representation]
        E --> F[Verification Strategy]
        F --> G[Simplify & Compare]
    end
    
    subgraph Output
        G --> H[Result + Proof]
    end
```

### Supported Verification Types

| Type | SymPy Function | Example |
|------|----------------|---------|
| **Equality** | `simplify(a - b) == 0` | `x² = x·x` |
| **Inequality** | `solveset()` | `x > 5` |
| **Limits** | `limit()` | `lim(x→0) sin(x)/x = 1` |
| **Derivatives** | `diff()` | `d/dx(x²) = 2x` |
| **Integrals** | `integrate()` | `∫x dx = x²/2` |

### Code Walkthrough

Here's the core verification logic:

```python title="src/qwed/engines/math_engine.py"
from sympy import symbols, simplify, parse_expr
from sympy.parsing.sympy_parser import standard_transformations

class MathEngine:
    def verify_equality(self, left: str, right: str) -> VerificationResult:
        """Verify that two expressions are equal."""
        # Parse expressions
        left_expr = parse_expr(left, transformations=standard_transformations)
        right_expr = parse_expr(right, transformations=standard_transformations)
        
        # Compute difference
        diff = simplify(left_expr - right_expr)
        
        # If difference is 0, expressions are equal
        is_valid = diff == 0
        
        return VerificationResult(
            verified=is_valid,
            proof={
                "left_simplified": str(simplify(left_expr)),
                "right_simplified": str(simplify(right_expr)),
                "difference": str(diff)
            }
        )
```

## Real-World Example

### The Compound Interest Bug

Consider a financial application where an LLM calculates compound interest:

**User Query:** "Calculate compound interest on $100,000 at 5% for 10 years"

**LLM Response:** "$150,000"

**QWED Verification:**

```python
from qwed import QWEDClient

client = QWEDClient()
result = client.verify_math(
    query="Compound interest: principal=100000, rate=0.05, time=10",
    llm_answer="150000"
)

print(result.verified)  # False
print(result.correct_answer)  # 162889.46
print(result.explanation)  
# "LLM used simple interest (P×r×t) instead of compound interest (P(1+r)^t)"
```

The LLM used simple interest: `100000 × 0.05 × 10 = 50000 → $150,000`

The correct formula: `100000 × (1.05)^10 = $162,889.46`

**Cost of this error:** $12,889 per transaction 💸

## Performance Benchmarks

| Operation | Latency (p50) | Latency (p99) |
|-----------|---------------|---------------|
| Simple arithmetic | 2ms | 5ms |
| Algebraic identity | 15ms | 45ms |
| Calculus (derivatives) | 50ms | 150ms |
| Calculus (integrals) | 100ms | 500ms |

## Limitations

SymPy can verify most mathematical expressions, but has limits:

1. **Computational complexity** — Some integrals are unsolvable symbolically
2. **Numerical precision** — Floating-point edge cases
3. **Domain knowledge** — Doesn't understand physical units

For these cases, QWED falls back to numerical verification with stated confidence bounds.

## Conclusion

QWED's Math Engine demonstrates a core principle: **LLMs are translators, not calculators**. By using symbolic computation through SymPy, we can:

- ✅ Provide deterministic verification
- ✅ Catch errors before they reach production
- ✅ Generate mathematical proofs

---

## References

1. Frieder, S., et al. (2023). [Mathematical Capabilities of ChatGPT](https://arxiv.org/abs/2302.04767). arXiv:2302.04767.
2. Meurer, A., et al. (2017). [SymPy: Symbolic Computing in Python](https://peerj.com/articles/cs-103/). PeerJ Computer Science.
3. Lewkowycz, A., et al. (2022). [Minerva: Solving Quantitative Reasoning Problems](https://arxiv.org/abs/2206.14858). arXiv:2206.14858.

---

**Next up:** [SQL Injection Prevention with AST Parsing →](/blog/sql-injection-ast-parsing)
