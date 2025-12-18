# API Reference

Complete reference for all QWED API endpoints.

## Base URL

```
https://api.qwed.tech/v1
```

For local development:
```
http://localhost:8000
```

---

## Authentication

All API requests require an API key passed in the header:

```bash
curl -H "X-API-Key: qwed_your_api_key_here" https://api.qwed.tech/v1/verify/math
```

---

## Endpoints

### POST `/verify/math`

Verify mathematical calculations and expressions.

**Request:**
```json
{
  "query": "What is 15% of 200?",
  "use_decimal": true
}
```

**Response:**
```json
{
  "status": "VERIFIED",
  "final_answer": 30.0,
  "verification": {
    "is_correct": true,
    "calculated_value": "30.00",
    "expression": "0.15 * 200"
  },
  "provider_used": "azure_openai",
  "latency_ms": 245.3
}
```

---

### POST `/verify/logic`

Verify logical constraints and business rules using Z3 solver.

**Request:**
```json
{
  "query": "If age >= 18 and has_license = true, can the person drive?",
  "context": {
    "age": 21,
    "has_license": true
  }
}
```

**Response:**
```json
{
  "status": "SAT",
  "model": {
    "can_drive": true
  },
  "dsl_code": "(AND (GTE age 18) (EQ has_license true))",
  "latency_ms": 89.2
}
```

---

### POST `/verify/sql`

Validate AI-generated SQL for security vulnerabilities.

**Request:**
```json
{
  "query": "SELECT * FROM users WHERE id = 1",
  "schema": {
    "users": ["id", "name", "email"]
  }
}
```

**Response:**
```json
{
  "is_safe": true,
  "parsed_tables": ["users"],
  "parsed_columns": ["id", "name", "email"],
  "warnings": []
}
```

---

### POST `/verify/code`

Static security analysis for code snippets.

**Request:**
```json
{
  "code": "user_input = input('Code: ')\neval(user_input)",
  "language": "python"
}
```

**Response:**
```json
{
  "is_safe": false,
  "status": "BLOCKED",
  "issues": [
    {
      "severity": "CRITICAL",
      "type": "dangerous_function",
      "function": "eval",
      "description": "Critical function 'eval' detected. This is blocked."
    }
  ],
  "critical_count": 1,
  "warning_count": 0
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "status": "ERROR",
  "error": "Description of the error",
  "latency_ms": 12.5
}
```

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| `200` | Success |
| `400` | Bad Request - Invalid input |
| `401` | Unauthorized - Invalid API key |
| `429` | Rate Limited - Too many requests |
| `500` | Server Error |

---

## Rate Limits

| Plan | Requests/Minute |
|------|-----------------|
| Free | 60 |
| Pro | 300 |
| Enterprise | Unlimited |

When rate limited, you'll receive:

```json
{
  "status": "BLOCKED",
  "error": "Rate limit exceeded. Please try again later."
}
```
