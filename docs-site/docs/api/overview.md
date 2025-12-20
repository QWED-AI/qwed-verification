---
sidebar_position: 1
---

# API Overview

QWED provides a RESTful API for verification.

## Base URL

```
https://api.qwed.ai/v1
```

Or for local development:
```
http://localhost:8000
```

## Authentication

All requests require an API key:

```bash
curl -H "X-API-Key: qwed_your_key" https://api.qwed.ai/v1/health
```

## Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/verify` | Auto-detect verification |
| POST | `/verify/math` | Math verification |
| POST | `/verify/logic` | Logic verification |
| POST | `/verify/code` | Code security |
| POST | `/verify/sql` | SQL validation |
| POST | `/verify/fact` | Fact checking |
| POST | `/verify/batch` | Batch verification |

## Request Format

```json
{
  "query": "2+2=4",
  "type": "math",
  "options": {
    "include_attestation": true,
    "timeout_ms": 30000
  }
}
```

## Response Format

```json
{
  "status": "VERIFIED",
  "verified": true,
  "engine": "math",
  "result": {
    "is_valid": true,
    "message": "Expression is correct"
  },
  "attestation": "eyJhbGciOiJFUzI1NiIs...",
  "metadata": {
    "request_id": "req_abc123",
    "latency_ms": 45
  }
}
```

## Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad request |
| 401 | Unauthorized |
| 429 | Rate limited |
| 500 | Server error |

## Rate Limits

| Plan | Requests/min | Requests/day |
|------|--------------|--------------|
| Free | 60 | 1,000 |
| Pro | 600 | 50,000 |
| Enterprise | Unlimited | Unlimited |

## Detailed Reference

- [All Endpoints](/docs/api/endpoints)
- [Authentication](/docs/api/authentication)
- [Error Codes](/docs/api/errors)
- [Rate Limits](/docs/api/rate-limits)
