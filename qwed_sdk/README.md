# QWED SDK

> Python SDK for the QWED Verification Platform

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

## Installation

```bash
pip install qwed
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
    attestation: str | None  # The server's signed token, on a VERIFIED answer
    proof_ref: str | None    # The proof the token binds
```

### Verifying the attestation

Every `VERIFIED` answer carries `attestation`, an ES256 JWT the server
signed after checking the verdict. Verifying it shows that server issued a
VERIFIED verdict for this answer's `proof_ref` (and, when you pass `query`,
for that statement). On a route that decides an admission (maths, code,
SQL and natural language, the agent route, and their batch items), the
token signs that too, and `verify_attestation`
checks it is the answer's `admission`. It covers only what the token signs,
not other fields of the response such as `agent_message`:

```python
from qwed_sdk import AttestationError

result = client.verify_math("2+2=4")
if result.attestation:
    try:
        # Fetches /.well-known/jwks.json (cached for five minutes), then
        # checks the signature, issuer, expiry (and any nbf), a VERIFIED
        # status, and that the token is this answer's (its proof_hash is
        # result.proof_ref). If no cached key verifies it, the keys are
        # fetched once more, at most once every 30 s, to pick up a rotated
        # key or a restarted server's new one. If the keys cannot be
        # fetched it raises KeysUnavailableError (an AttestationError).
        claims = client.verify_attestation(result, query="2+2=4")
    except AttestationError as exc:
        print("attestation does not verify for this answer:", exc)
```

To verify offline, or against keys you pinned, use
`qwed_sdk.verify_attestation(token, jwks, proof_ref=..., query=..., admission=...)` with the
JWKS you hold. A token says the server reached the verdict; whether to act
on it is still the answer's admission.

### Verification Context documents

A document's `proof_ref` is a commitment anyone can compute, so it does not
show who issued the document. The server returns spec v1.1 documents, which
carry `attestation`: its signature over every other field of the document
(the token cannot sign itself). By default
`validate_verification_context` and `resolve_verification_context` verify
it against the server's keys before asking the server:

```python
document = client.create_verification_context_from_diagnostic(
    diagnostic, query="mean of a == 2", verifier="stats", attestation_token=result.attestation,
)
client.resolve_verification_context(document)        # {"resolved": True}
client.resolve_verification_context(forged_document) # {"resolved": False, "error": "attestation_invalid"}
client.validate_verification_context(local_v1_0)     # {"valid": False, "error": "attestation_required"}
client.validate_verification_context(local_v1_0, require_attestation=False)  # the schema alone
```

The server's routes and the CLI check it too, by default:

```bash
qwed context resolve --server http://localhost:8000 document.json
qwed context validate --jwks-file jwks.json document.json
qwed context validate --no-require-attestation local_v1_0.json
```

`client.verify_document_attestation(document)` returns the claims or raises
`AttestationError`; offline, use
`qwed_sdk.verify_document_attestation(document, jwks)`. Keys that cannot be
fetched raise `KeysUnavailableError` rather than report a document invalid.
The signature authenticates the document; it adds nothing to its verdict or
admission. A server without a configured signing key (`QWED_SIGNING_KEY` or
`QWED_SIGNING_KEY_FILE`) signs with a key generated per process, so its
documents stop verifying after a restart, or on another replica.

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

`QWEDClient` and `QWEDAsyncClient` read no environment variables: pass `api_key` and `base_url` when you create them.

---

## CLI Usage

The SDK includes the `qwed` command:

```bash
qwed init      # set up a model provider and its model, and a local API key
qwed doctor    # health check: engines, provider, server, database
qwed test      # the built-in engine checks; needs no model or server

# Verify with a model provider, from this machine
qwed verify "What is 2+2?"
qwed verify "derivative of x^2" --provider openai --model <model> --api-key <openai-key>
qwed verify "5!" --base-url http://localhost:11434/v1 --model <model>
qwed interactive

qwed cache stats    # or: qwed cache clear
qwed pii "My email is john@example.com"    # needs qwed[pii]
```

`qwed verify` and `qwed interactive` call the model provider directly, with no QWED server.

- **Model.** QWED names no model. They use `--model`, else the selected provider's model variable (`OLLAMA_MODEL`, `CUSTOM_MODEL`, `OPENAI_MODEL`, `ANTHROPIC_MODEL` or `GEMINI_MODEL`), and stop with a message naming it when neither is set.
- **Provider.** Without `--provider` (or `--base-url`, for `qwed verify`), they run the provider `ACTIVE_PROVIDER` selects: the one `qwed init` saved, and Ollama when it is unset. Its key comes from its own variable (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `CUSTOM_API_KEY`, or for Gemini `GOOGLE_API_KEY`, else `GEMINI_API_KEY`), never from `QWED_API_KEY`. `qwed verify --api-key` overrides it. `qwed interactive` has no `--api-key`: for OpenAI, Anthropic or Gemini it asks for the key when the variable is unset.
- **Key with `--provider`.** `qwed verify --provider` takes the key from `--api-key` or `QWED_API_KEY`; `qwed interactive --provider` asks for it.

### `qwed verify` options

| Option | Description |
|--------|-------------|
| `-p, --provider` | `openai`, `anthropic` or `gemini` |
| `-m, --model` | The model to run |
| `--base-url` | An OpenAI-compatible endpoint, such as Ollama's |
| `--api-key` | The provider's API key |
| `--no-cache` | Do not use the result cache |
| `-q, --quiet` | Minimal output |
| `--mask-pii` | Mask emails, phone numbers and similar before the question goes to the model |

Run `qwed <command> --help` for the other commands' options.

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

