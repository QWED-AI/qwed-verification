---
sidebar_position: 5
---

# QWED-Logic DSL Reference

Quick reference for the QWED-Logic Domain Specific Language.

## Overview

QWED-Logic is an S-expression based DSL for expressing logical constraints. It's verified by the Z3 SMT solver for mathematical correctness.

```lisp
(AND (GT x 5) (LT y 10))
```

> **Why S-expressions?** They're unambiguous, easy to parse, and map directly to Z3 constraints.

---

## Basic Syntax

```
(OPERATOR arg1 arg2 ...)
```

All expressions are enclosed in parentheses. The operator comes first, followed by arguments.

---

## Logical Operators

| Operator | Meaning | Example |
|----------|---------|---------|
| `AND` | Logical AND | `(AND a b c)` |
| `OR` | Logical OR | `(OR a b)` |
| `NOT` | Logical NOT | `(NOT a)` |
| `IMPLIES` | Implication (a → b) | `(IMPLIES a b)` |
| `IFF` | Biconditional (a ↔ b) | `(IFF a b)` |
| `XOR` | Exclusive OR | `(XOR a b)` |

### Examples

```lisp
# Both conditions must be true
(AND (GT x 0) (LT x 100))

# At least one must be true
(OR (EQ status "active") (EQ status "pending"))

# If raining, then umbrella
(IMPLIES raining has_umbrella)
```

---

## Comparison Operators

| Operator | Meaning | Example |
|----------|---------|---------|
| `EQ` | Equal (=) | `(EQ x 5)` |
| `NE` | Not equal (≠) | `(NE x 0)` |
| `GT` | Greater than (>) | `(GT x 5)` |
| `LT` | Less than (<) | `(LT x 10)` |
| `GE` | Greater or equal (≥) | `(GE x 0)` |
| `LE` | Less or equal (≤) | `(LE x 100)` |

### Examples

```lisp
# x is between 0 and 100 (exclusive)
(AND (GT x 0) (LT x 100))

# x equals y
(EQ x y)

# Price is at least $10
(GE price 10)
```

---

## Arithmetic Operators

| Operator | Meaning | Example |
|----------|---------|---------|
| `PLUS` | Addition (+) | `(PLUS x y)` |
| `MINUS` | Subtraction (-) | `(MINUS x y)` |
| `TIMES` | Multiplication (*) | `(TIMES x y)` |
| `DIV` | Division (/) | `(DIV x y)` |
| `MOD` | Modulo (%) | `(MOD x 2)` |
| `POW` | Power (^) | `(POW x 2)` |
| `ABS` | Absolute value | `(ABS x)` |

### Examples

```lisp
# Check if x + y = 10
(EQ (PLUS x y) 10)

# x squared equals 16
(EQ (POW x 2) 16)

# Even number check
(EQ (MOD x 2) 0)
```

---

## Quantifiers

| Operator | Meaning | Example |
|----------|---------|---------|
| `FORALL` | For all (∀) | `(FORALL (x) (GT x 0))` |
| `EXISTS` | There exists (∃) | `(EXISTS (x) (EQ x 5))` |

### Examples

```lisp
# All elements are positive
(FORALL (x) (GT x 0))

# There exists a solution
(EXISTS (x y) (AND (EQ (PLUS x y) 10) (GT x 0) (GT y 0)))
```

---

## Special Types

### Boolean Literals

```lisp
TRUE
FALSE
```

### Integer Constraints

```lisp
(INT x)          # x is an integer
(NAT x)          # x is a natural number (≥ 0)
(POS x)          # x is positive (> 0)
```

### Array/List Operations

```lisp
(LEN arr)              # Length of array
(GET arr i)            # Get element at index i
(SET arr i val)        # Set element at index i
(SUM arr)              # Sum of all elements
```

---

## Complete Examples

### Example 1: Age Validation

```lisp
# User must be 18-65 years old
(AND 
  (GE age 18) 
  (LE age 65)
)
```

**Python:**
```python
result = client.verify_logic("(AND (GE age 18) (LE age 65))")
# SAT with model: {age: 30}
```

### Example 2: Budget Constraint

```lisp
# Total spending must not exceed budget
(LE 
  (PLUS food transport entertainment) 
  budget
)
```

### Example 3: Password Rules

```lisp
# Password must be 8-20 chars with at least 1 uppercase
(AND
  (GE (LEN password) 8)
  (LE (LEN password) 20)
  (GT uppercase_count 0)
)
```

### Example 4: Scheduling Constraint

```lisp
# Meetings can't overlap
(OR
  (LE meeting1_end meeting2_start)
  (LE meeting2_end meeting1_start)
)
```

### Example 5: Quadratic Equation

```lisp
# x² - 5x + 6 = 0 has solutions
(EXISTS (x)
  (EQ (PLUS (POW x 2) (TIMES -5 x) 6) 0)
)
```

---

## Verification Results

| Status | Meaning | Model |
|--------|---------|-------|
| `SAT` | Satisfiable — solution exists | `{x: 6, y: 4}` |
| `UNSAT` | Unsatisfiable — no solution | `null` |
| `UNKNOWN` | Solver timeout or undecidable | `null` |

### Reading Results

```python
result = client.verify_logic("(AND (GT x 5) (LT x 10))")

print(result.status)   # "SAT"
print(result.model)    # {"x": 6}
print(result.verified) # True
```

---

## API Usage

### Python

```python
from qwed import QWEDClient

client = QWEDClient(api_key="qwed_your_key")

# Simple constraint
result = client.verify_logic("(GT x 5)")

# Complex constraint
result = client.verify_logic("""
  (AND 
    (GE x 0) 
    (LE x 100)
    (EQ (MOD x 7) 0)
  )
""")

if result.status == "SAT":
    print(f"Solution: x = {result.model['x']}")
```

### CLI

```bash
# Verify a constraint
qwed verify-logic "(AND (GT x 5) (LT x 10))"

# From file
echo "(EQ (PLUS x y) 10)" > constraint.dsl
qwed verify-logic -f constraint.dsl
```

### HTTP API

```bash
curl -X POST https://api.qwedai.com/v1/verify/logic \
  -H "Authorization: Bearer qwed_your_key" \
  -H "Content-Type: application/json" \
  -d '{
    "expression": "(AND (GT x 5) (LT y 10))",
    "format": "dsl"
  }'
```

---

## Common Patterns

### Range Check
```lisp
(AND (GE x min) (LE x max))
```

### Non-Empty String
```lisp
(GT (LEN str) 0)
```

### Mutual Exclusion
```lisp
(NOT (AND a b))     # a and b can't both be true
```

### At Most One
```lisp
(LE (PLUS (IF a 1 0) (IF b 1 0) (IF c 1 0)) 1)
```

### Exactly One
```lisp
(EQ (PLUS (IF a 1 0) (IF b 1 0) (IF c 1 0)) 1)
```

---

## Error Handling

| Error | Cause | Fix |
|-------|-------|-----|
| `PARSE_ERROR` | Invalid syntax | Check parentheses matching |
| `UNKNOWN_OPERATOR` | Typo in operator | Use valid operator names |
| `TYPE_ERROR` | Incompatible types | Check operand types |
| `TIMEOUT` | Constraint too complex | Simplify or set longer timeout |

---

## Grammar (EBNF)

```ebnf
expression     = atom | compound
compound       = "(" operator expression* ")"
atom           = variable | number | boolean | string
operator       = "AND" | "OR" | "NOT" | "IMPLIES" | "IFF" | "XOR"
               | "EQ" | "NE" | "GT" | "LT" | "GE" | "LE"
               | "PLUS" | "MINUS" | "TIMES" | "DIV" | "MOD" | "POW"
               | "FORALL" | "EXISTS" | "LEN" | "GET" | "SET"
variable       = [a-zA-Z_][a-zA-Z0-9_]*
number         = [-]?[0-9]+("."[0-9]+)?
boolean        = "TRUE" | "FALSE"
string         = "\"" [^\"]* "\""
```

---

## Full Specification

See [QWED-Logic DSL Specification](/docs/specs/qwed-spec#7-qwed-logic-dsl) for the complete formal grammar.
