# QWED SDK

> Python SDK for the QWED Verification Platform

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

## Installation

```bash
pip install qwed-new
```

---

## Quick Start

```python
from qwed_sdk import QWEDClient

client = QWEDClient(
    api_key="qwed_your_api_key",
    base_url="http://localhost:8000"  # or your production URL
)

# Verify a math query
result = client.verify("What is 15% of 200?")
print(result.status)  # "VERIFIED"
```

---

## Client Classes

### QWEDClient (Synchronous)

For standard Python applications.

```python
from qwed_sdk import QWEDClient

client = QWEDClient(api_key="qwed_...", base_url="http://localhost:8000")

# Use context manager for automatic cleanup
with QWEDClient(api_key="qwed_...") as client:
    result = client.verify("2+2=4")
```

### QWEDAsyncClient (Asynchronous)

For async/await applications (FastAPI, asyncio, etc.)

```python
from qwed_sdk import QWEDAsyncClient

async with QWEDAsyncClient(api_key="qwed_...") as client:
    result = await client.verify("Is 2+2=4?")
```

---

## Methods

### `verify(query, provider=None)`

Verify a natural language math query.

```python
result = client.verify("What is 15% of 200?")
print(result.status)       # "VERIFIED"
print(result.is_verified)  # True
print(result.result)       # {"answer": 30, ...}
```

### `verify_math(expression)`

Verify a mathematical expression or identity.

```python
result = client.verify_math("x**2 + 2*x + 1 = (x+1)**2")
print(result.is_verified)  # True (algebraic identity)

result = client.verify_math("2+2=5")
print(result.is_verified)  # False
```

### `verify_logic(query)`

Verify a QWED-Logic DSL expression using Z3.

```python
result = client.verify_logic("(AND (GT x 5) (LT y 10))")
print(result.status)  # "SAT"
print(result.result)  # {"model": {"x": 6, "y": 9}}
```

### `verify_code(code, language="python")`

Check code for security vulnerabilities.

```python
result = client.verify_code("import os; os.system('rm -rf /')")
print(result.is_verified)  # False - dangerous!
print(result.result)       # {"vulnerabilities": [...]}

# From file
with open("script.py") as f:
    result = client.verify_code(f.read())
```

### `verify_fact(claim, context)`

Verify a factual claim against provided context.

```python
result = client.verify_fact(
    claim="Paris is the capital of France",
    context="France is a country in Europe. Its capital city is Paris."
)
print(result.result["verdict"])  # "SUPPORTED"
```

### `verify_sql(query, schema_ddl, dialect="sqlite")`

Validate SQL query against a schema.

```python
result = client.verify_sql(
    query="SELECT * FROM users WHERE id = 1",
    schema_ddl="CREATE TABLE users (id INT, name TEXT)",
    dialect="sqlite"
)
print(result.is_verified)  # True
```

### `verify_batch(items)`

Process multiple verifications concurrently.

```python
result = client.verify_batch([
    {"query": "2+2=4", "type": "math"},
    {"query": "3*3=9", "type": "math"},
    {"query": "(AND (GT x 5))", "type": "logic"},
    {"query": "x**2 - y**2 = (x-y)*(x+y)", "type": "math"}
])

print(f"Total: {result.total_items}")
print(f"Success rate: {result.success_rate}%")

for item in result.items:
    print(f"{item.id}: {item.status} - {item.query[:30]}")
```

### `health()`

Check API health status.

```python
status = client.health()
print(status)  # {"status": "healthy", "version": "1.0.0"}
```

---

## Response Models

### VerificationResult

```python
@dataclass
class VerificationResult:
    status: str           # "VERIFIED", "FAILED", "ERROR", "BLOCKED"
    is_verified: bool     # True if verification passed
    result: dict          # Full response data
    error: str | None     # Error message if any
    latency_ms: float     # Request latency
```

### BatchResult

```python
@dataclass
class BatchResult:
    job_id: str
    status: str                # "completed", "partial", "failed"
    total_items: int
    completed_items: int
    failed_items: int
    items: List[BatchItem]
    
    @property
    def success_rate(self) -> float  # Percentage of successful items
```

---

## Error Handling

```python
import httpx
from qwed_sdk import QWEDClient

client = QWEDClient(api_key="qwed_...")

try:
    result = client.verify("What is 2+2?")
except httpx.HTTPStatusError as e:
    if e.response.status_code == 401:
        print("Invalid API key")
    elif e.response.status_code == 429:
        print("Rate limit exceeded")
    else:
        print(f"API error: {e.response.status_code}")
except httpx.RequestError as e:
    print(f"Network error: {e}")
```

---

## Environment Variables

The SDK can be configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `QWED_API_KEY` | - | Your API key (required for CLI) |
| `QWED_API_URL` | `http://localhost:8000` | API base URL |

---

## CLI Usage

The SDK includes a command-line interface:

```bash
# Set API key
export QWED_API_KEY="qwed_your_key"

# Health check
qwed health

# Verify queries
qwed verify "What is 2+2?"
qwed verify-math "x**2 + 2*x + 1 = (x+1)**2"
qwed verify-logic "(AND (GT x 5) (LT y 10))"
qwed verify-code -f script.py

# Batch processing
qwed batch input.json -o results.json
```

### CLI Flags

| Flag | Description |
|------|-------------|
| `-j, --json` | Output raw JSON |
| `-o, --output` | Write results to file |
| `-f, --file` | Read input from file |
| `-l, --language` | Programming language (for code) |

---

## Examples

### Integration with FastAPI

```python
from fastapi import FastAPI
from qwed_sdk import QWEDAsyncClient

app = FastAPI()
client = QWEDAsyncClient(api_key="qwed_...")

@app.on_event("startup")
async def startup():
    await client.__aenter__()

@app.on_event("shutdown")
async def shutdown():
    await client.__aexit__(None, None, None)

@app.post("/verify")
async def verify(query: str):
    result = await client.verify(query)
    return {"verified": result.is_verified, "result": result.result}
```

### Bulk Verification Script

```python
import json
from qwed_sdk import QWEDClient

client = QWEDClient(api_key="qwed_...")

# Load queries from file
with open("queries.json") as f:
    queries = json.load(f)

# Process in batch
result = client.verify_batch(queries)

# Save results
with open("results.json", "w") as f:
    json.dump({
        "success_rate": result.success_rate,
        "items": [
            {"id": item.id, "status": item.status, "result": item.result}
            for item in result.items
        ]
    }, f, indent=2)

print(f"Processed {result.total_items} queries")
print(f"Success rate: {result.success_rate:.1f}%")
```

---

## License

Apache 2.0
