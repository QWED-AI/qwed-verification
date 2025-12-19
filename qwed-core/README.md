# QWED Core

> Minimal, embeddable verification library implementing the QWED Protocol

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)

## Overview

`qwed-core` is the **reference implementation** of the QWED Protocol. It provides:
- Deterministic verification engines (Math, Logic, Code, SQL)
- Zero external service dependencies
- Embeddable in any Python application
- Minimal footprint (~500KB)

## Installation

```bash
pip install qwed-core
```

Or install from source:
```bash
cd qwed-core
pip install -e .
```

## Quick Start

```python
from qwed_core import verify, verify_math, verify_logic, verify_code

# Math verification
result = verify_math("x**2 + 2*x + 1 = (x+1)**2")
print(result.verified)  # True

# Logic verification (QWED-DSL)
result = verify_logic("(AND (GT x 5) (LT y 10))")
print(result.status)  # SAT

# Code security check
result = verify_code("import os; os.system('rm -rf /')", language="python")
print(result.verified)  # False - dangerous code!

# Natural language (requires LLM)
result = verify("What is 15% of 200?", llm_provider=my_llm)
```

## Engines

| Engine | Standalone | LLM Required | Technology |
|--------|------------|--------------|------------|
| Math | ✅ | Optional | SymPy |
| Logic | ✅ | Optional | Z3 |
| Code | ✅ | No | AST |
| SQL | ✅ | No | SQLGlot |
| Fact | ❌ | Yes | NLP |
| Stats | ❌ | Yes | Pandas |

## API Reference

### `verify_math(expression: str) -> VerificationResult`

Verify mathematical expressions or identities.

```python
result = verify_math("2 + 2 = 4")
result = verify_math("sin(pi/2) = 1")
result = verify_math("x**2 - 1 = (x-1)*(x+1)")  # Identity
```

### `verify_logic(query: str, format: str = "dsl") -> VerificationResult`

Verify logical constraints using Z3.

```python
result = verify_logic("(AND (GT x 5) (LT x 10))")
print(result.model)  # {'x': 6}
```

### `verify_code(code: str, language: str = "python") -> VerificationResult`

Check code for security vulnerabilities.

```python
result = verify_code(code, language="python")
for vuln in result.vulnerabilities:
    print(f"{vuln.severity}: {vuln.message}")
```

### `verify_sql(query: str, schema: str) -> VerificationResult`

Validate SQL queries against a schema.

```python
result = verify_sql(
    "SELECT * FROM users WHERE id = 1",
    schema="CREATE TABLE users (id INT, name TEXT)"
)
```

## Docker

```bash
docker build -t qwed-core .
docker run -p 8080:8080 qwed-core
```

## License

Apache 2.0
