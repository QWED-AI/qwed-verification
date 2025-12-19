# QWED-Agent Specification v1.0

> **Status:** Draft  
> **Version:** 1.0.0  
> **Date:** 2025-12-20  
> **Extends:** QWED-SPEC v1.0, QWED-Attestation v1.0

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Agent Verification Model](#2-agent-verification-model)
3. [Agent Registration](#3-agent-registration)
4. [Verification Requests](#4-verification-requests)
5. [Tool Verification](#5-tool-verification)
6. [Budget & Limits](#6-budget--limits)
7. [Audit Trail](#7-audit-trail)
8. [Trust Levels](#8-trust-levels)
9. [Implementation Guidelines](#9-implementation-guidelines)

---

## 1. Introduction

### 1.1 Purpose

QWED-Agent defines a protocol for **AI agents to verify their actions** before execution. As agentic AI systems become more autonomous, QWED-Agent provides guardrails ensuring agents operate within defined boundaries.

### 1.2 Problem Statement

| Problem | Risk |
|---------|------|
| Agents execute unverified code | Security vulnerabilities |
| Agents make unverified calculations | Financial errors |
| Agents generate unverified SQL | Data corruption |
| Agents exceed resource limits | Cost overruns |
| No audit trail of agent actions | Compliance violations |

### 1.3 Solution

QWED-Agent establishes:
- Pre-execution verification of agent outputs
- Tool call approval workflow
- Budget enforcement
- Complete audit trail
- Trust level management

### 1.4 Terminology

| Term | Definition |
|------|------------|
| **Agent** | Autonomous AI system performing tasks |
| **Principal** | Entity that owns/controls the agent |
| **Tool** | External capability an agent can invoke |
| **Action** | Any operation an agent wants to perform |
| **Verification Gate** | Check before action execution |
| **Budget** | Resource limits for the agent |

---

## 2. Agent Verification Model

### 2.1 Verification Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    AGENT EXECUTION LOOP                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │  Agent   │───▶│ QWED Gate    │───▶│  Execution   │      │
│  │  Plans   │    │ (Verify)     │    │  (If Passed) │      │
│  └──────────┘    └──────────────┘    └──────────────┘      │
│       │                │                    │               │
│       │                ▼                    │               │
│       │         ┌──────────────┐           │               │
│       │         │  Attestation │           │               │
│       │         │  (Record)    │           │               │
│       │         └──────────────┘           │               │
│       │                                    │               │
│       ◀────────────────────────────────────┘               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Verification Types for Agents

| Action Type | Verification Engine | Risk Level |
|-------------|---------------------|------------|
| Math calculation | Math Engine | Low |
| Database query | SQL Engine | High |
| Code execution | Code Engine | Critical |
| External API call | Tool Verification | Medium |
| File operations | Security Check | High |
| Network requests | Policy Check | Medium |

### 2.3 Decision Matrix

```
┌─────────────────────────────────────────────────────────────┐
│              QWED-AGENT DECISION MATRIX                     │
├──────────────┬──────────────┬──────────────────────────────┤
│ Verification │ Risk Level   │ Action                       │
├──────────────┼──────────────┼──────────────────────────────┤
│ VERIFIED     │ Low          │ Execute immediately          │
│ VERIFIED     │ High         │ Execute with attestation     │
│ FAILED       │ Any          │ Block + notify principal     │
│ CORRECTED    │ Low          │ Execute corrected version    │
│ CORRECTED    │ High         │ Request principal approval   │
│ UNCERTAIN    │ Any          │ Request principal approval   │
└──────────────┴──────────────┴──────────────────────────────┘
```

---

## 3. Agent Registration

### 3.1 Registration Request

Agents MUST register with QWED before use:

```json
{
  "agent": {
    "name": "CustomerSupportBot",
    "type": "autonomous",
    "description": "Handles customer inquiries",
    "principal_id": "org_abc123",
    "framework": "langchain",
    "model": "claude-3.5-sonnet"
  },
  "permissions": {
    "allowed_engines": ["math", "fact", "sql"],
    "allowed_tools": ["database_read", "send_email"],
    "blocked_tools": ["database_write", "file_delete"]
  },
  "budget": {
    "max_daily_cost_usd": 100.00,
    "max_requests_per_hour": 1000,
    "max_tokens_per_request": 4096
  },
  "trust_level": "supervised"
}
```

### 3.2 Registration Response

```json
{
  "agent_id": "agent_xyz789",
  "agent_token": "qwed_agent_...",
  "status": "active",
  "created_at": "2025-12-20T00:30:00Z",
  "permissions": { ... },
  "budget": { ... }
}
```

### 3.3 Agent Types

| Type | Description | Trust Level |
|------|-------------|-------------|
| `supervised` | Human approval for high-risk actions | Low |
| `autonomous` | Self-executing within limits | Medium |
| `trusted` | Full autonomy (enterprise only) | High |

### 3.4 Agent Identity

Agents receive a DID-based identity:

```
did:qwed:agent:<agent_id>
```

---

## 4. Verification Requests

### 4.1 Agent Verification Request

```json
{
  "agent_id": "agent_xyz789",
  "agent_token": "qwed_agent_...",
  "action": {
    "type": "execute_sql",
    "query": "SELECT * FROM customers WHERE status = 'active'",
    "target": "production_db"
  },
  "context": {
    "conversation_id": "conv_123",
    "step_number": 5,
    "user_intent": "Get list of active customers"
  },
  "options": {
    "require_attestation": true,
    "risk_threshold": "medium"
  }
}
```

### 4.2 Verification Response

```json
{
  "decision": "APPROVED",
  "verification": {
    "status": "VERIFIED",
    "engine": "sql",
    "risk_level": "low",
    "checks_passed": [
      "no_destructive_operations",
      "no_sensitive_columns",
      "schema_valid"
    ]
  },
  "attestation": "eyJhbGciOiJFUzI1NiIs...",
  "budget_remaining": {
    "daily_cost_usd": 89.50,
    "hourly_requests": 42
  }
}
```

### 4.3 Decision Types

| Decision | Meaning | Agent Action |
|----------|---------|--------------|
| `APPROVED` | Safe to execute | Proceed |
| `DENIED` | Verification failed | Abort + log |
| `CORRECTED` | Fixed version available | Use corrected |
| `PENDING` | Requires human approval | Wait |
| `BUDGET_EXCEEDED` | Limits reached | Abort |

---

## 5. Tool Verification

### 5.1 Tool Call Request

Before an agent calls an external tool:

```json
{
  "agent_id": "agent_xyz789",
  "tool_call": {
    "tool_name": "send_email",
    "parameters": {
      "to": "user@example.com",
      "subject": "Your order status",
      "body": "Your order #12345 has shipped..."
    }
  },
  "justification": "User requested order status update"
}
```

### 5.2 Tool Risk Assessment

```json
{
  "tool_name": "send_email",
  "risk_assessment": {
    "base_risk": "medium",
    "factors": [
      {"factor": "external_communication", "weight": 0.3},
      {"factor": "pii_in_content", "weight": 0.5}
    ],
    "final_risk": "medium",
    "requires_approval": false
  },
  "policy_checks": [
    {"policy": "no_pii_leakage", "passed": true},
    {"policy": "rate_limit", "passed": true}
  ]
}
```

### 5.3 Tool Registry

```json
{
  "tools": [
    {
      "name": "database_read",
      "risk_level": "low",
      "requires_verification": true,
      "verification_engine": "sql"
    },
    {
      "name": "database_write",
      "risk_level": "critical",
      "requires_verification": true,
      "requires_approval": true,
      "verification_engine": "sql"
    },
    {
      "name": "execute_code",
      "risk_level": "critical",
      "requires_verification": true,
      "verification_engine": "code",
      "sandbox_required": true
    }
  ]
}
```

---

## 6. Budget & Limits

### 6.1 Budget Schema

```json
{
  "budget": {
    "cost": {
      "max_daily_usd": 100.00,
      "max_per_request_usd": 1.00,
      "current_daily_usd": 10.50
    },
    "requests": {
      "max_per_hour": 1000,
      "max_per_day": 10000,
      "current_hour": 42,
      "current_day": 350
    },
    "tokens": {
      "max_per_request": 4096,
      "max_daily": 1000000,
      "current_daily": 50000
    },
    "tools": {
      "max_calls_per_hour": 100,
      "high_risk_calls_remaining": 5
    }
  }
}
```

### 6.2 Budget Enforcement

```
┌─────────────────────────────────────────────────────────────┐
│                  BUDGET CHECK FLOW                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Request ──▶ [Check Cost] ──▶ [Check Rate] ──▶ [Execute]   │
│                   │                │                        │
│                   ▼                ▼                        │
│              Exceeded?         Exceeded?                    │
│                   │                │                        │
│              ┌────┴────┐     ┌────┴────┐                   │
│              │  DENY   │     │  DENY   │                   │
│              │  +429   │     │  +429   │                   │
│              └─────────┘     └─────────┘                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.3 Budget Response

```json
{
  "decision": "BUDGET_EXCEEDED",
  "error": {
    "code": "QWED-AGENT-BUDGET-001",
    "message": "Daily cost limit exceeded",
    "details": {
      "limit": 100.00,
      "current": 102.50,
      "reset_at": "2025-12-21T00:00:00Z"
    }
  }
}
```

---

## 7. Audit Trail

### 7.1 Activity Log Schema

Every agent action is logged:

```json
{
  "activity_id": "act_abc123",
  "agent_id": "agent_xyz789",
  "timestamp": "2025-12-20T00:30:00Z",
  "action": {
    "type": "tool_call",
    "tool": "database_read",
    "parameters": { ... }
  },
  "verification": {
    "status": "VERIFIED",
    "engine": "sql",
    "latency_ms": 45
  },
  "decision": "APPROVED",
  "execution": {
    "success": true,
    "result_hash": "sha256:..."
  },
  "cost": {
    "usd": 0.05,
    "tokens": 150
  },
  "attestation_id": "att_xyz789"
}
```

### 7.2 Audit Query API

```http
GET /agents/{agent_id}/activity?from=2025-12-01&to=2025-12-20
```

Response:
```json
{
  "agent_id": "agent_xyz789",
  "period": {
    "from": "2025-12-01T00:00:00Z",
    "to": "2025-12-20T00:00:00Z"
  },
  "summary": {
    "total_actions": 15420,
    "approved": 15200,
    "denied": 180,
    "corrected": 40,
    "total_cost_usd": 850.00
  },
  "activities": [ ... ]
}
```

### 7.3 Compliance Export

```http
GET /agents/{agent_id}/compliance-report?format=pdf
```

---

## 8. Trust Levels

### 8.1 Trust Level Definitions

| Level | Description | Verification | Approval |
|-------|-------------|--------------|----------|
| **0: Untrusted** | No autonomous actions | All | All |
| **1: Supervised** | Low-risk autonomous | High-risk | High-risk |
| **2: Autonomous** | Most actions autonomous | Critical only | Critical only |
| **3: Trusted** | Full autonomy | None | None |

### 8.2 Trust Elevation

Agents can request trust elevation:

```json
{
  "agent_id": "agent_xyz789",
  "request": "trust_elevation",
  "from_level": 1,
  "to_level": 2,
  "justification": "30 days of safe operation",
  "evidence": {
    "days_active": 30,
    "total_actions": 50000,
    "denied_actions": 50,
    "denial_rate": 0.001,
    "attestations": 50000
  }
}
```

### 8.3 Trust Degradation

Automatic trust reduction on violations:

| Violation | Penalty |
|-----------|---------|
| Security policy violation | -2 levels |
| Repeated denials (>10%) | -1 level |
| Budget abuse | -1 level |
| Principal complaint | Suspend |

---

## 9. Implementation Guidelines

### 9.1 SDK Integration

```python
from qwed_sdk import QWEDAgentClient

# Register agent
agent = QWEDAgentClient.register(
    name="MyAgent",
    principal_id="org_123",
    permissions={
        "allowed_engines": ["math", "sql"],
        "allowed_tools": ["database_read"]
    },
    budget={
        "max_daily_cost_usd": 50.00
    }
)

# Before executing any action
result = agent.verify_action({
    "type": "execute_sql",
    "query": "SELECT * FROM users"
})

if result.decision == "APPROVED":
    # Safe to execute
    execute_query(result.verified_query)
    
    # Log with attestation
    agent.log_execution(
        action_id=result.action_id,
        success=True,
        attestation=result.attestation
    )
```

### 9.2 LangChain Integration

```python
from langchain.agents import AgentExecutor
from qwed_sdk.langchain import QWEDVerificationCallback

# Wrap agent with QWED verification
agent_executor = AgentExecutor(
    agent=my_agent,
    tools=my_tools,
    callbacks=[QWEDVerificationCallback(
        agent_id="agent_xyz789",
        agent_token="qwed_agent_..."
    )]
)

# All tool calls automatically verified
result = agent_executor.run("Get customer data")
```

### 9.3 CrewAI Integration

```python
from crewai import Agent, Task, Crew
from qwed_sdk.crewai import QWEDVerifiedAgent

# Wrap agents with QWED
verified_agent = QWEDVerifiedAgent(
    agent=researcher,
    qwed_settings={
        "verify_all_tools": True,
        "require_attestation": True
    }
)
```

---

## Appendix A: Error Codes

| Code | Description |
|------|-------------|
| `QWED-AGENT-001` | Agent not registered |
| `QWED-AGENT-002` | Invalid agent token |
| `QWED-AGENT-003` | Agent suspended |
| `QWED-AGENT-004` | Tool not allowed |
| `QWED-AGENT-005` | Verification failed |
| `QWED-AGENT-BUDGET-001` | Daily cost exceeded |
| `QWED-AGENT-BUDGET-002` | Hourly rate exceeded |
| `QWED-AGENT-BUDGET-003` | Token limit exceeded |
| `QWED-AGENT-TRUST-001` | Insufficient trust level |
| `QWED-AGENT-TRUST-002` | Action requires approval |

## Appendix B: HTTP Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/agents/register` | POST | Register new agent |
| `/agents/{id}` | GET | Get agent details |
| `/agents/{id}/verify` | POST | Verify agent action |
| `/agents/{id}/tools/{tool}` | POST | Verify tool call |
| `/agents/{id}/activity` | GET | Get activity log |
| `/agents/{id}/budget` | GET | Get budget status |
| `/agents/{id}/trust` | POST | Request trust change |

---

*© 2025 QWED-AI. This specification is released under Apache 2.0 License.*
