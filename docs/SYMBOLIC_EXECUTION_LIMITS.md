# Symbolic Execution Limits in QWED

> **TL;DR:** CrossHair symbolic execution has real-world limitations. QWED addresses these with bounded model checking, depth limits, and graceful fallbacks.

## The Path Explosion Problem

Symbolic execution explores all possible execution paths. This works great for small code, but real-world code has:

| Challenge | Example | Impact |
|-----------|---------|--------|
| **Deep loops** | `for i in range(1000)` | 1000+ paths to explore |
| **Recursion** | `fibonacci(n)` | Exponential path growth |
| **Complex conditionals** | Nested if/else chains | 2^n paths |
| **Data structures** | Dict/list operations | Unbounded state space |

## When CrossHair Works

| Code Type | Works Well? | Example |
|-----------|-------------|---------|
| Pure functions | ✅ Yes | `def add(a, b): return a + b` |
| Simple validation | ✅ Yes | `def is_positive(x): return x > 0` |
| Bounded loops | ✅ Yes | `for i in range(10)` |
| LLM-generated utilities | ✅ Yes | Most generated code is simple |

## When CrossHair Fails

| Code Type | Works? | Why |
|-----------|--------|-----|
| Deep recursion (n > 50) | ❌ No | Path explosion |
| Unbounded loops | ❌ No | Infinite paths |
| External I/O | ❌ No | Non-deterministic |
| Complex frameworks | ❌ No | Too much state |

## QWED's Bounded Model Checking Solution

We implemented depth limits to prevent path explosion:

```python
from qwed_new.core.symbolic_verifier import SymbolicVerifier

verifier = SymbolicVerifier(
    max_loop_iterations=100,  # Bound loops
    max_recursion_depth=50,   # Bound recursion
    timeout_seconds=30        # Hard timeout
)

result = verifier.verify_code(code)

if result["status"] == "TIMEOUT":
    # Fallback to static analysis
    print("Symbolic execution timed out, using AST analysis")
```

## Configuration Guide

### Conservative (Fast, Less Coverage)
```python
config = {
    "max_loop_iterations": 10,
    "max_recursion_depth": 10,
    "timeout_seconds": 5
}
```

### Balanced (Default)
```python
config = {
    "max_loop_iterations": 100,
    "max_recursion_depth": 50,
    "timeout_seconds": 30
}
```

### Thorough (Slow, More Coverage)
```python
config = {
    "max_loop_iterations": 1000,
    "max_recursion_depth": 100,
    "timeout_seconds": 300
}
```

## Fallback Strategy

When symbolic execution fails, QWED falls back to:

```
1. Symbolic Execution (CrossHair)
   ↓ timeout/failure
2. Static Analysis (AST)
   ↓ insufficient
3. Type Checking (mypy patterns)
   ↓ still need more
4. Manual Review Flag
```

## Honest Benchmarks

We tested CrossHair on different code types:

| Code Type | Lines | Loops | Result | Time |
|-----------|-------|-------|--------|------|
| Simple math | 5 | 0 | ✅ Verified | 0.2s |
| String utils | 15 | 1 | ✅ Verified | 1.2s |
| Data validation | 30 | 3 | ✅ Verified | 5.8s |
| Complex parser | 100 | 10 | ⏱️ Timeout | 30s |
| Framework code | 500+ | Many | ❌ Not suitable | - |

## Best Practices

### DO Use Symbolic Execution For:
- ✅ LLM-generated utility functions
- ✅ Mathematical calculations
- ✅ Validation logic
- ✅ Simple transformations
- ✅ Code with clear contracts

### DON'T Use Symbolic Execution For:
- ❌ Entire applications
- ❌ Code with external dependencies
- ❌ Deep recursion algorithms
- ❌ Real-time systems
- ❌ Code with I/O operations

## API Reference

```python
from qwed_new.core.symbolic_verifier import SymbolicVerifier

# Create verifier with custom limits
verifier = SymbolicVerifier(
    max_loop_iterations=100,
    max_recursion_depth=50,
    timeout_seconds=30
)

# Check if code is verifiable before executing
budget = verifier.get_verification_budget(code)
if budget["estimated_time_seconds"] > 60:
    print("Code too complex for symbolic execution")

# Verify with fallback
result = verifier.verify_code(
    code=code,
    fallback_to_ast=True  # Use AST if symbolic fails
)
```

## Summary

| Question | Answer |
|----------|--------|
| Does symbolic execution work on all code? | **No.** Limited by path explosion. |
| How does QWED handle this? | **Bounded model checking + fallbacks.** |
| What's the typical code size limit? | **~50-100 lines of simple code.** |
| When should I use it? | **LLM-generated utilities and validation.** |

---

*"My guess would be that technique falls apart at depths required in real world coding environments."*

— Reddit criticism. **We agree.** That's why we have bounds and fallbacks.
