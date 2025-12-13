# QWED API Integration Guide

**Version:** 1.0.0  
**Base URL:** `https://api.qwed.tech/v1` (Production) / `http://localhost:8000` (Local)

---

## Overview

QWED is a **Deterministic Verification Engine** for AI. It acts as a safety layer between your LLM application and your users.

Instead of trusting an LLM's output directly, you send the user's query to QWED. We:
1.  **Translate** the query into a structured mathematical or logical expression.
2.  **Validate** the expression for semantic correctness.
3.  **Verify** the result using a deterministic symbolic engine (SymPy/Z3).

This guarantees that the answer is mathematically correct, auditable, and hallucination-free.

---

## Authentication

All API requests require an API key passed in the header.

**Header:** `X-API-Key: <YOUR_API_KEY>`

> **Note**: For local development, authentication is currently disabled.

---

## Endpoints

### 1. Verify Natural Language Query

The main entry point for most applications. It handles the full pipeline: Translation → Validation → Verification.

- **URL:** `/verify/natural_language`
- **Method:** `POST`
- **Content-Type:** `application/json`

#### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `query` | string | Yes | The natural language question to verify. |
| `provider` | string | No | The LLM provider to use (`azure_openai` or `anthropic`). Defaults to Azure. |

**Example Request:**
```json
{
  "query": "What is the compound interest on $1000 at 5% for 2 years?"
}
```

#### Response Body

The response provides full transparency into the verification process.

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `VERIFIED` (Correct), `CORRECTED` (LLM was wrong, we fixed it), `FAILED` (Could not verify). |
| `final_answer` | float | The deterministically calculated correct answer. |
| `verification` | object | Details of the symbolic verification. |
| `translation` | object | How the LLM interpreted the query (for auditing). |
| `latency_ms` | float | Total processing time in milliseconds. |

**Example Response (Success):**
```json
{
  "status": "VERIFIED",
  "final_answer": 1102.5,
  "user_query": "What is the compound interest on $1000 at 5% for 2 years?",
  "translation": {
    "expression": "1000 * (1 + 0.05)**2",
    "claimed_answer": 1102.5,
    "reasoning": "Compound interest formula P(1+r)^t with P=1000, r=0.05, t=2",
    "confidence": 1.0
  },
  "verification": {
    "is_correct": true,
    "calculated_value": 1102.5,
    "diff": 0.0
  },
  "latency_ms": 1250.5
}
```

**Example Response (Correction):**
*When the LLM makes a mistake, QWED catches it.*

```json
{
  "status": "CORRECTED",
  "final_answer": 1102.5,
  "translation": {
    "expression": "1000 * (1 + 0.05)**2",
    "claimed_answer": 1100.0,  <-- LLM Hallucinated this
    "confidence": 0.9
  },
  "verification": {
    "is_correct": false,
    "calculated_value": 1102.5, <-- QWED Fixed it
    "diff": 2.5
  }
}
```

#### Error Codes

| Code | Message | Description |
|------|---------|-------------|
| 400 | `Validation Failed` | The query could not be translated into a valid mathematical expression (e.g., "What is the color of hope?"). |
| 429 | `Rate Limit Exceeded` | You have sent too many requests. |
| 500 | `Internal Server Error` | An unexpected error occurred in the engine. |

---

### 2. Verify Raw Expression (Low Level)

If you already have a mathematical expression and just want to verify it deterministically, use this endpoint.

- **URL:** `/verify/math`
- **Method:** `POST`

#### Request Body

```json
{
  "expression": "1000 * (1 + 0.05)**2",
  "claimed_value": 1102.5
}
```

#### Response Body

}
```

---

### 3. Verify Logic Puzzle (Engine 2)

Verifies logic puzzles and constraint satisfaction problems using Z3.

- **URL:** `/verify/logic`
- **Method:** `POST`
- **Content-Type:** `application/json`

#### Request Body
```json
{
  "query": "A farmer has 17 sheep. All but 9 die. How many are left?",
  "provider": "anthropic"
}
```

#### Response Body
```json
{
  "status": "SAT",
  "model": {
    "sheep_left": 9
  },
  "error": null
}
```

---

### 4. Verify Statistical Claim (Engine 3)

Verifies claims about tabular data by executing generated Pandas code.

- **URL:** `/verify/stats`
- **Method:** `POST`
- **Content-Type:** `multipart/form-data`

#### Form Data
| Field | Type | Description |
|-------|------|-------------|
| `file` | File (CSV) | The dataset to analyze. |
| `query` | Text | The question to answer (e.g., "Total sales?"). |
| `provider` | Text | Optional LLM provider. |

#### Response Body
```json
{
  "result": "220",
  "code": "result = df['Sales'].sum()",
  "columns": ["Date", "Product", "Sales"]
}
```

---

### 5. Verify Fact (Engine 4)

Verifies a claim against a provided text context (RAG-style).

- **URL:** `/verify/fact`
- **Method:** `POST`
- **Content-Type:** `application/json`

#### Request Body
```json
{
  "claim": "The policy covers floods.",
  "context": "The policy excludes floods...",
  "provider": "azure_openai"
}
```

#### Response Body
```json
{
  "verdict": "REFUTED",
  "reasoning": "Context explicitly excludes floods.",
  "citations": ["The policy excludes floods..."]
}
```

---

### 6. Verify Code Security (Engine 5)

Performs static analysis (AST & Regex) to detect security vulnerabilities in code.

- **URL:** `/verify/code`
- **Method:** `POST`
- **Content-Type:** `application/json`

#### Request Body
```json
{
  "code": "import os; os.system('rm -rf /')",
  "language": "python"
}
```

#### Response Body
```json
{
  "is_safe": false,
  "issues": ["Use of dangerous function: os.system"]
}
```

---

### 7. Get History

Retrieve past verifications.

- **URL:** `/history`
- **Method:** `GET`
- **Query Params:** `limit` (default 10).

---

## Client Libraries

### Python
```python
import requests

def verify_query(query):
    response = requests.post(
        "https://api.qwed.tech/v1/verify/natural_language",
        json={"query": query},
        headers={"X-API-Key": "YOUR_KEY"}
    )
    return response.json()

result = verify_query("What is 15% of 200?")
print(f"Verified Answer: {result['final_answer']}")
```

### cURL
```bash
curl -X POST https://api.qwed.tech/v1/verify/natural_language \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"query": "What is 15% of 200?"}'
```
