---
sidebar_position: 1
---

# Protocol Specifications

QWED is defined by formal specifications that enable interoperability.

## Core Specifications

| Specification | Version | Description |
|---------------|---------|-------------|
| [QWED-SPEC](/docs/specs/qwed-spec) | v1.0.0 | Core protocol definition |
| [QWED-Attestation](/docs/specs/attestation) | v1.0.0 | Cryptographic proofs |
| [QWED-Agent](/docs/specs/agent) | v1.0.0 | AI agent verification |

## What's in a Spec?

### QWED-SPEC v1.0

The core specification defines:

- **Request/Response Format** — JSON schemas for API
- **Verification Engines** — Math, Logic, Code, SQL, etc.
- **QWED-Logic DSL** — Grammar for logical expressions
- **Error Codes** — Standardized error taxonomy
- **Versioning** — Semantic versioning rules

### QWED-Attestation v1.0

The attestation specification defines:

- **JWT Format** — ES256 signed tokens
- **Claims** — Standard and custom JWT claims
- **Trust Anchors** — Issuer verification
- **Chain Validation** — Linked attestations

### QWED-Agent v1.0

The agent specification defines:

- **Registration** — Agent identity and permissions
- **Action Verification** — Pre-execution checks
- **Budget Management** — Cost and rate limits
- **Trust Levels** — 0-3 autonomy scale

## JSON Schemas

Machine-readable schemas are available at:

```
specs/schemas/
├── request.v1.json
├── response.v1.json
├── attestation.v1.json
└── agent.v1.json
```

## Implementing QWED

To implement the QWED protocol:

1. Parse requests per `request.v1.json`
2. Route to appropriate verification engine
3. Return responses per `response.v1.json`
4. Optionally generate attestations per QWED-Attestation

## Conformance Levels

| Level | Requirements |
|-------|--------------|
| **Basic** | Request/response format |
| **Standard** | + All 8 engines |
| **Full** | + Attestations + Agent API |
