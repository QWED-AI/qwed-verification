---
sidebar_position: 2
---

# API Endpoints

Complete reference for all QWED API endpoints.

## Base URL

```
https://api.qwed.ai/v1
```

## Health Check

### GET /health

Check API status.

```bash
curl https://api.qwed.ai/v1/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2024-12-20T12:00:00Z"
}
```

---

## Verification Endpoints

### POST /verify

Auto-detect and verify any claim.

**Request:**
```json
{
  "query": "Is 2+2=4?",
  "options": {
    "include_attestation": true
  }
}
```

**Response:**
```json
{
  "status": "VERIFIED",
  "verified": true,
  "engine": "math",
  "result": {
    "is_valid": true
  },
  "attestation": "eyJhbGciOiJFUzI1NiIs..."
}
```

---

### POST /verify/math

Verify mathematical expressions.

**Request:**
```json
{
  "expression": "x**2 + 2*x + 1 = (x+1)**2"
}
```

---

### POST /verify/logic

Verify logical constraints.

**Request:**
```json
{
  "query": "(AND (GT x 5) (LT y 10))",
  "format": "dsl"
}
```

**Response:**
```json
{
  "status": "VERIFIED",
  "verified": true,
  "result": {
    "satisfiability": "SAT",
    "model": {"x": 6, "y": 9}
  }
}
```

---

### POST /verify/code

Check code for security vulnerabilities.

**Request:**
```json
{
  "code": "import os\nos.system('rm -rf /')",
  "language": "python"
}
```

**Response:**
```json
{
  "status": "BLOCKED",
  "verified": false,
  "result": {
    "vulnerabilities": [
      {
        "type": "os.system",
        "severity": "critical",
        "line": 2,
        "message": "Shell command execution"
      }
    ]
  }
}
```

---

### POST /verify/sql

Validate SQL queries.

**Request:**
```json
{
  "query": "SELECT * FROM users WHERE id = 1",
  "schema": "CREATE TABLE users (id INT, name TEXT)",
  "dialect": "postgresql"
}
```

---

### POST /verify/fact

Verify factual claims.

**Request:**
```json
{
  "claim": "Paris is the capital of France",
  "context": "France is a country in Western Europe. Its capital is Paris."
}
```

---

### POST /verify/batch

Verify multiple items at once.

**Request:**
```json
{
  "items": [
    {"query": "2+2=4", "type": "math"},
    {"query": "3*3=9", "type": "math"},
    {"query": "(GT x 5)", "type": "logic"}
  ],
  "options": {
    "parallel": true,
    "stop_on_failure": false
  }
}
```

**Response:**
```json
{
  "results": [...],
  "summary": {
    "total": 3,
    "verified": 3,
    "failed": 0,
    "success_rate": 100.0
  }
}
```

---

## Agent Endpoints

### POST /agent/register

Register a new AI agent.

**Request:**
```json
{
  "name": "MyAgent",
  "type": "supervised",
  "principal_id": "user_123",
  "permissions": {
    "allowed_engines": ["math", "logic"]
  },
  "budget": {
    "max_daily_cost_usd": 100,
    "max_requests_per_hour": 1000
  }
}
```

---

### POST /agent/verify-action

Verify an agent action before execution.

**Request:**
```json
{
  "agent_id": "agent_abc123",
  "action": {
    "type": "execute_sql",
    "query": "SELECT * FROM users"
  }
}
```

---

## Attestation Endpoints

### GET /attestation/:id

Get an attestation by ID.

### POST /attestation/verify

Verify an attestation JWT.

**Request:**
```json
{
  "jwt": "eyJhbGciOiJFUzI1NiIs..."
}
```

---

## Badge Endpoints

### GET /badge/verified

Get a verified badge SVG.

### GET /badge/status/:status

Get a badge for any status.

### GET /badge/custom

Generate a custom badge.

**Query params:** `label`, `message`, `color`, `logo`

