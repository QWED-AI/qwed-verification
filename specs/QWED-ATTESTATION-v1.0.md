# QWED-Attestation Specification v1.0

> **Status:** Draft  
> **Version:** 1.0.0  
> **Date:** 2025-12-20  
> **Extends:** QWED-SPEC v1.0

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Attestation Model](#2-attestation-model)
3. [Attestation Format](#3-attestation-format)
4. [Cryptographic Operations](#4-cryptographic-operations)
5. [Verification Chain](#5-verification-chain)
6. [Trust Anchors](#6-trust-anchors)
7. [Transport & Storage](#7-transport--storage)
8. [Implementation Guidelines](#8-implementation-guidelines)

---

## 1. Introduction

### 1.1 Purpose

QWED-Attestation defines a standard format for **cryptographic proofs of verification**. An attestation is a signed statement that a specific verification was performed by a trusted verifier at a specific time.

### 1.2 Use Cases

| Use Case | Description |
|----------|-------------|
| **Audit Trail** | Prove that verification occurred for compliance |
| **Trust Transfer** | Third party can verify without re-running |
| **Offline Verification** | Validate attestation without network |
| **Chain of Custody** | Track verification through system handoffs |
| **Non-Repudiation** | Verifier cannot deny issuing attestation |

### 1.3 Terminology

| Term | Definition |
|------|------------|
| **Attestation** | Signed proof of verification result |
| **Issuer** | QWED verifier that creates the attestation |
| **Subject** | The content that was verified |
| **Holder** | Entity that possesses the attestation |
| **Verifier** | Party validating the attestation |
| **Claim** | Statement within the attestation |

---

## 2. Attestation Model

### 2.1 Conceptual Model

```
┌─────────────────────────────────────────────────────────────┐
│                     QWED ATTESTATION                        │
├─────────────────────────────────────────────────────────────┤
│  Header                                                     │
│  ├── Algorithm: ES256                                       │
│  ├── Type: qwed-attestation+jwt                            │
│  └── Key ID: did:qwed:issuer123                            │
├─────────────────────────────────────────────────────────────┤
│  Payload (Claims)                                           │
│  ├── Issuer: qwed-node-xyz                                 │
│  ├── Subject: sha256(original_query)                       │
│  ├── Issued At: 2025-12-20T00:30:00Z                       │
│  ├── Expiration: 2026-12-20T00:30:00Z                      │
│  ├── Verification Result: VERIFIED                          │
│  ├── Engine: math                                           │
│  ├── Confidence: 1.0                                        │
│  └── Proof Hash: sha256(proof_data)                        │
├─────────────────────────────────────────────────────────────┤
│  Signature                                                  │
│  └── ECDSA-P256(header + payload, issuer_private_key)      │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Trust Flow

```
1. Client submits verification request
2. QWED Verifier performs verification
3. Verifier creates attestation with result
4. Verifier signs attestation with private key
5. Attestation returned to client
6. Client can share attestation with third parties
7. Third parties verify signature against issuer's public key
```

### 2.3 Attestation Lifecycle

| State | Description |
|-------|-------------|
| `issued` | Attestation created and signed |
| `valid` | Within validity period, signature valid |
| `expired` | Past expiration time |
| `revoked` | Explicitly invalidated by issuer |

---

## 3. Attestation Format

### 3.1 Structure (JWT)

QWED Attestations use JSON Web Token (JWT) format per [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519).

```
<header>.<payload>.<signature>
```

### 3.2 Header Schema

```json
{
  "alg": "ES256",
  "typ": "qwed-attestation+jwt",
  "kid": "did:qwed:node:abc123#key-1"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `alg` | REQUIRED | Signature algorithm (ES256, EdDSA) |
| `typ` | REQUIRED | Token type (MUST be `qwed-attestation+jwt`) |
| `kid` | REQUIRED | Key identifier (DID-based) |

### 3.3 Payload Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://qwed.ai/schemas/attestation/v1",
  "type": "object",
  "required": ["iss", "sub", "iat", "qwed"],
  "properties": {
    "iss": {
      "type": "string",
      "description": "Issuer identifier (DID or URL)"
    },
    "sub": {
      "type": "string",
      "description": "Subject hash (SHA-256 of verified content)"
    },
    "iat": {
      "type": "integer",
      "description": "Issued at (Unix timestamp)"
    },
    "exp": {
      "type": "integer",
      "description": "Expiration (Unix timestamp)"
    },
    "nbf": {
      "type": "integer",
      "description": "Not before (Unix timestamp)"
    },
    "jti": {
      "type": "string",
      "description": "Unique attestation ID"
    },
    "qwed": {
      "type": "object",
      "description": "QWED-specific claims",
      "required": ["version", "result"],
      "properties": {
        "version": {
          "type": "string",
          "const": "1.0"
        },
        "result": {
          "type": "object",
          "required": ["status", "verified"],
          "properties": {
            "status": {
              "type": "string",
              "enum": ["VERIFIED", "FAILED", "CORRECTED", "BLOCKED"]
            },
            "verified": {
              "type": "boolean"
            },
            "engine": {
              "type": "string"
            },
            "confidence": {
              "type": "number",
              "minimum": 0,
              "maximum": 1
            }
          }
        },
        "query_hash": {
          "type": "string",
          "description": "SHA-256 of original query"
        },
        "proof_hash": {
          "type": "string",
          "description": "SHA-256 of proof data"
        },
        "chain_id": {
          "type": "string",
          "description": "Verification chain ID for linked attestations"
        }
      }
    }
  }
}
```

### 3.4 Example Attestation (Decoded)

**Header:**
```json
{
  "alg": "ES256",
  "typ": "qwed-attestation+jwt",
  "kid": "did:qwed:node:mainnet-001#signing-key-2025"
}
```

**Payload:**
```json
{
  "iss": "did:qwed:node:mainnet-001",
  "sub": "sha256:a1b2c3d4e5f6...",
  "iat": 1734653400,
  "exp": 1766189400,
  "jti": "att_7f8e9d0c1b2a",
  "qwed": {
    "version": "1.0",
    "result": {
      "status": "VERIFIED",
      "verified": true,
      "engine": "math",
      "confidence": 1.0
    },
    "query_hash": "sha256:9f8e7d6c5b4a...",
    "proof_hash": "sha256:1a2b3c4d5e6f..."
  }
}
```

**Encoded JWT:**
```
eyJhbGciOiJFUzI1NiIsInR5cCI6InF3ZWQtYXR0ZXN0YXRpb24rand0Iiwia2lk
IjoiZGlkOnF3ZWQ6bm9kZTptYWlubmV0LTAwMSNzaWduaW5nLWtleS0yMDI1In0.
eyJpc3MiOiJkaWQ6cXdlZDpub2RlOm1haW5uZXQtMDAxIiwic3ViIjoic2hhMjU2
OmExYjJjM2Q0ZTVmNi4uLiIsImlhdCI6MTczNDY1MzQwMCwiZXhwIjoxNzY2MTg5
NDAwLCJqdGkiOiJhdHRfN2Y4ZTlkMGMxYjJhIiwicXdlZCI6eyJ2ZXJzaW9uIjoi
MS4wIiwicmVzdWx0Ijp7InN0YXR1cyI6IlZFUklGSUVEIiwidmVyaWZpZWQiOnRy
dWUsImVuZ2luZSI6Im1hdGgiLCJjb25maWRlbmNlIjoxLjB9fX0.
MEUCIQDKZnw...signature...
```

---

## 4. Cryptographic Operations

### 4.1 Algorithms

| Algorithm | Usage | Requirement |
|-----------|-------|-------------|
| **ES256** | Attestation signing | REQUIRED |
| **EdDSA** | Attestation signing | RECOMMENDED |
| **SHA-256** | Content hashing | REQUIRED |
| **SHA-384** | Content hashing | OPTIONAL |

### 4.2 Key Types

**Issuer Keys:**
```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "base64url...",
  "y": "base64url...",
  "kid": "did:qwed:node:xyz#key-1"
}
```

### 4.3 Signing Process

```python
# Pseudocode
def create_attestation(verification_result, issuer_key):
    header = {
        "alg": "ES256",
        "typ": "qwed-attestation+jwt",
        "kid": issuer_key.kid
    }
    
    payload = {
        "iss": issuer_key.issuer_did,
        "sub": sha256(verification_result.query),
        "iat": current_timestamp(),
        "exp": current_timestamp() + VALIDITY_PERIOD,
        "jti": generate_uuid(),
        "qwed": {
            "version": "1.0",
            "result": {
                "status": verification_result.status,
                "verified": verification_result.verified,
                "engine": verification_result.engine,
                "confidence": verification_result.confidence
            },
            "query_hash": sha256(verification_result.query),
            "proof_hash": sha256(verification_result.proof)
        }
    }
    
    signature = ecdsa_sign(
        base64url(header) + "." + base64url(payload),
        issuer_key.private_key
    )
    
    return base64url(header) + "." + base64url(payload) + "." + base64url(signature)
```

### 4.4 Verification Process

```python
def verify_attestation(attestation_jwt, trusted_issuers):
    # 1. Parse JWT
    header, payload, signature = parse_jwt(attestation_jwt)
    
    # 2. Validate header
    assert header["typ"] == "qwed-attestation+jwt"
    assert header["alg"] in ["ES256", "EdDSA"]
    
    # 3. Get issuer public key
    issuer_did = payload["iss"]
    if issuer_did not in trusted_issuers:
        raise UntrustedIssuerError()
    
    public_key = resolve_did_key(issuer_did, header["kid"])
    
    # 4. Verify signature
    if not ecdsa_verify(header + "." + payload, signature, public_key):
        raise InvalidSignatureError()
    
    # 5. Check validity period
    now = current_timestamp()
    if payload.get("nbf") and now < payload["nbf"]:
        raise NotYetValidError()
    if payload.get("exp") and now > payload["exp"]:
        raise ExpiredError()
    
    # 6. Check revocation (optional)
    if is_revoked(payload["jti"]):
        raise RevokedError()
    
    return payload["qwed"]["result"]
```

---

## 5. Verification Chain

### 5.1 Chained Attestations

For complex verifications, multiple attestations can be chained:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Attestation 1  │────▶│  Attestation 2  │────▶│  Attestation 3  │
│  (Translation)  │     │  (Verification) │     │  (Consensus)    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### 5.2 Chain Reference

```json
{
  "qwed": {
    "chain_id": "chain_abc123",
    "chain_index": 2,
    "previous_attestation": "att_xyz789",
    "previous_hash": "sha256:..."
  }
}
```

### 5.3 Multi-Engine Attestation

When multiple engines verify the same query:

```json
{
  "qwed": {
    "result": {
      "status": "VERIFIED",
      "verified": true,
      "consensus": {
        "mode": "unanimous",
        "engines": ["math", "logic"],
        "agreement": 1.0
      }
    }
  }
}
```

---

## 6. Trust Anchors

### 6.1 Issuer Registry

QWED maintains a registry of trusted issuers:

```
https://qwed.ai/registry/issuers.json
```

```json
{
  "issuers": [
    {
      "did": "did:qwed:node:mainnet-001",
      "name": "QWED Mainnet Node 1",
      "public_keys": [
        {
          "kid": "did:qwed:node:mainnet-001#key-2025",
          "kty": "EC",
          "crv": "P-256",
          "x": "...",
          "y": "..."
        }
      ],
      "status": "active",
      "certification_level": "full"
    }
  ]
}
```

### 6.2 Decentralized Identifiers (DIDs)

QWED uses DIDs for issuer identification:

```
did:qwed:node:<node-id>
did:qwed:provider:<provider-id>
did:qwed:user:<user-id>
```

### 6.3 Key Rotation

Issuers SHOULD rotate keys annually. Old keys remain valid for attestation verification until their designated expiry.

---

## 7. Transport & Storage

### 7.1 HTTP Header

Attestations can be returned in HTTP headers:

```http
HTTP/1.1 200 OK
Content-Type: application/json
QWED-Attestation: eyJhbGciOiJFUzI1NiIsInR5cCI6...
```

### 7.2 Response Body

Attestations can be included in the response:

```json
{
  "status": "VERIFIED",
  "verified": true,
  "attestation": "eyJhbGciOiJFUzI1NiIsInR5cCI6..."
}
```

### 7.3 Standalone Document

Attestations can be stored as standalone files:

```
verification_result.qwed-attestation
```

### 7.4 Blockchain Anchoring (Optional)

Attestation hashes can be anchored to public blockchains:

```json
{
  "qwed": {
    "anchor": {
      "chain": "ethereum",
      "tx_hash": "0x...",
      "block_number": 12345678
    }
  }
}
```

---

## 8. Implementation Guidelines

### 8.1 Request Attestation

Request attestation in verification request:

```json
{
  "query": "2+2=4",
  "type": "math",
  "options": {
    "include_attestation": true,
    "attestation_validity_days": 365
  }
}
```

### 8.2 SDK Example (Python)

```python
from qwed_sdk import QWEDClient
from qwed_sdk.attestation import verify_attestation

client = QWEDClient(api_key="qwed_...")

# Request with attestation
result = client.verify(
    "What is 2+2?",
    options={"include_attestation": True}
)

# Get attestation
attestation = result.attestation
print(f"Attestation ID: {attestation.jti}")

# Share with third party
attestation_jwt = attestation.to_jwt()

# Third party verifies
is_valid, claims = verify_attestation(
    attestation_jwt,
    trusted_issuers=["did:qwed:node:mainnet-001"]
)

if is_valid:
    print(f"Verified by {claims['iss']} at {claims['iat']}")
```

### 8.3 Storage Recommendations

| Use Case | Recommended Storage |
|----------|---------------------|
| Short-term audit | In-memory / Redis |
| Long-term compliance | Database with indexing |
| Immutable record | Blockchain anchor |
| Offline verification | File system |

### 8.4 Security Recommendations

1. **Protect Private Keys** - Use HSM or secure key management
2. **Validate Issuers** - Only trust registered issuers
3. **Check Expiration** - Reject expired attestations
4. **Verify Chains** - Validate all attestations in a chain
5. **Monitor Revocations** - Check revocation status

---

## Appendix A: Error Codes

| Code | Description |
|------|-------------|
| `ATT-001` | Invalid attestation format |
| `ATT-002` | Untrusted issuer |
| `ATT-003` | Invalid signature |
| `ATT-004` | Attestation expired |
| `ATT-005` | Attestation not yet valid |
| `ATT-006` | Attestation revoked |
| `ATT-007` | Missing required claim |
| `ATT-008` | Chain validation failed |

## Appendix B: MIME Types

| Type | Usage |
|------|-------|
| `application/qwed-attestation+jwt` | Attestation JWT |
| `application/qwed-attestation+json` | Decoded attestation |

## Appendix C: DID Method

The `did:qwed` method specification will be published separately.

---

*© 2025 QWED-AI. This specification is released under Apache 2.0 License.*
