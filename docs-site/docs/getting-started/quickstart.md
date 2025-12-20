---
sidebar_position: 2
---

# Quick Start

Learn QWED basics in 5 minutes.

## 1. Basic Verification

```python
from qwed_sdk import QWEDClient

client = QWEDClient(api_key="qwed_your_key")

# Verify a math claim
result = client.verify("What is 15% of 200?")
print(result.verified)  # True
print(result.status)    # "VERIFIED"
```

## 2. Math Verification

Verify mathematical expressions with 100% accuracy:

```python
# Check equations
result = client.verify_math("x**2 + 2*x + 1 = (x+1)**2")
print(result.verified)  # True (identity verified)

# Catch errors
result = client.verify_math("2 + 2 = 5")
print(result.verified)  # False
print(result.message)   # "Not equal: difference is 1"
```

## 3. Logic Verification

Verify logical constraints using Z3 SAT solver:

```python
# QWED-Logic DSL
result = client.verify_logic("(AND (GT x 5) (LT y 10))")
print(result.status)  # "SAT"
print(result.model)   # {"x": 6, "y": 9}

# Unsatisfiable constraints
result = client.verify_logic("(AND (GT x 10) (LT x 5))")
print(result.status)  # "UNSAT"
```

## 4. Code Security

Check code for vulnerabilities:

```python
dangerous_code = """
import os
os.system('rm -rf /')
"""

result = client.verify_code(dangerous_code, language="python")
print(result.verified)  # False
print(result.status)    # "BLOCKED"
for vuln in result.vulnerabilities:
    print(f"- {vuln.severity}: {vuln.message}")
```

## 5. SQL Validation

Validate SQL queries:

```python
result = client.verify_sql(
    query="SELECT * FROM users WHERE id = 1",
    schema="CREATE TABLE users (id INT, name TEXT)"
)
print(result.verified)  # True

# Detect injection
result = client.verify_sql("SELECT * FROM users; DROP TABLE users; --")
print(result.status)  # "BLOCKED"
```

## 6. Batch Verification

Verify multiple claims at once:

```python
from qwed_sdk import VerificationType

results = client.verify_batch([
    {"query": "2+2=4", "type": VerificationType.MATH},
    {"query": "3*3=9", "type": VerificationType.MATH},
    {"query": "(AND (GT x 5))", "type": VerificationType.LOGIC},
])

print(f"Success rate: {results.summary.success_rate}%")
```

## 7. CLI Usage

```bash
# Verify from command line
qwed verify "Is 2+2=5?"

# Verify logic
qwed verify-logic "(AND (GT x 5) (LT y 10))"

# Verify code file
qwed verify-code -f script.py

# Batch from file
qwed batch -f queries.json
```

## Next Steps

- [Core Concepts](/docs/getting-started/concepts)
- [Verification Engines](/docs/engines/overview)
- [SDK Reference](/docs/sdks/overview)
