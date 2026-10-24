# qwed

> Rust SDK for QWED Verification Protocol

[![crates.io](https://img.shields.io/crates/v/qwed.svg)](https://crates.io/crates/qwed)
[![Rust 1.70+](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
qwed = "7.3.0"
tokio = { version = "1.0", features = ["rt-multi-thread", "macros"] }
```

## Quick Start

```rust
use qwed::QWEDClient;

#[tokio::main]
async fn main() -> Result<(), qwed::Error> {
    let client = QWEDClient::new("qwed_your_api_key");

    let result = client.verify_math("2 + 2 = 4").await?;
    println!("Status: {:?}", result.status);       // Verified
    println!("Admitted: {}", result.is_admitted()); // true

    Ok(())
}
```

## Reading a result

Every verification returns the server's DiagnosticResult envelope:

| Field | Meaning |
|-------|---------|
| `status` | `Verified`, `Unverifiable` or `Blocked` (`Unknown` for a value this SDK does not know) |
| `raw_status` | The server's status text exactly as sent, such as `SAT` where `status` is `Unknown`; never used for admission |
| `admission` | `Some(Admit)` or `Some(Blocked)` where the endpoint decides; `None` where it does not |
| `proof_ref` | Set only when `status` is `Verified` |
| `attestation` | On a `Verified` answer, the server's signed token: an ES256 JWT whose header `kid` names a key at `GET /.well-known/jwks.json`, and whose `qwed.proof_hash` claim is the answer's `proof_ref`. Verify it with `client.verify_attestation` (below). |
| `agent_message`, `developer_fields`, `is_authoritative`, `constraint_id` | Explanation and detail |
| `extra` | Endpoint-specific fields, such as `is_valid` or `issues` |

**Gate on `is_admitted()`, not on `status`.** `Verified` means the engine reached a deterministic answer, not that the claim holds: `2 + 2 = 5` is `Verified` (proven false) with admission `Blocked`, and unsafe code is `Verified` (proven unsafe) and `Blocked`. `is_admitted()` is true only for `Admit` together with `Verified` and a `proof_ref`; a missing or unknown admission is never admitted.

Endpoints that make no admission decision (`/verify/logic`, `/verify/fact`, `/verify/rag`, `/verify/process`, and batch logic and fact items) are therefore never admitted. `/verify/rag` and `/verify/process` also send a `verified` field, which is their guard's own result, not an admission; it is in `extra["verified"]` and `developer_fields`. The deprecated `is_verified()` returns `is_admitted()`.

### Verifying the attestation

Every `Verified` answer carries `attestation`, an ES256 JWT the server
signed after checking the verdict. Verifying it shows that server issued a
VERIFIED verdict for this answer's `proof_ref` (and, when you pass the
query, for that statement). It covers only what the token signs, not other
fields of the response such as `admission` or `agent_message`:

```rust
use qwed::{AttestationError, AttestationOptions};

let result = client.verify_math("2+2=4").await?;
// Fetches /.well-known/jwks.json (cached for five minutes), then checks the
// signature, issuer, expiry (and any nbf), a VERIFIED status, and that the
// token is this answer's (its proof_hash is result.proof_ref). If no cached
// key verifies it, the keys are fetched once more, at most once every 30 s,
// to pick up a rotated key or a restarted server's new one.
match client.verify_attestation(&result, &AttestationOptions::new().query("2+2=4")).await {
    Ok(claims) => println!("attested by {}", claims.iss),
    Err(error) => println!("attestation does not verify for this answer: {error}"),
}
```

`AttestationError::KeysUnavailable` says the keys could not be fetched; that
failure is returned to every caller for 30 seconds after the fetch ends,
without another request (a token the cached keys do not verify gets it too),
and keys past their five minutes are not used instead. To verify offline, or
against keys you pinned, call `qwed::verify_attestation(token, &jwks,
proof_ref, &options)` with the JWKS you hold. A token says the server reached
the verdict; whether to act on it is still `is_admitted()`. The checks use
the RustCrypto `p256` crate.

## Verification Methods

### Natural Language

```rust
let result = client.verify("Is 15% of 200 equal to 30?").await?;
```

### Math Expressions

```rust
let result = client.verify_math("x**2 + 2*x + 1 = (x+1)**2").await?;
```

### Logic (QWED-DSL)

```rust
let result = client.verify_logic("(AND (GT x 5) (LT y 10))").await?;
// /verify/logic makes no admission decision, so is_admitted() is false.
```

### Code Security

```rust
let result = client.verify_code(r#"
import os
os.system('rm -rf /')
"#, "python").await?;
```

### Fact Verification

```rust
let result = client.verify_fact(
    "Paris is the capital of France",
    "France is a country in Europe. Its capital city is Paris.",
).await?;
```

### SQL Validation

```rust
let result = client.verify_sql(
    "SELECT * FROM users WHERE id = 1",
    "CREATE TABLE users (id INT PRIMARY KEY, name TEXT)",
    "postgresql",
).await?;
```

## Batch Verification

```rust
use qwed::{BatchItem, VerificationType};

let items = vec![
    BatchItem { query: "2+2=4".into(), r#type: Some(VerificationType::Math) },
    BatchItem { query: "3*3=9".into(), r#type: Some(VerificationType::Math) },
];

let batch = client.verify_batch(items).await?;
println!("Job {} is {}", batch.job_id, batch.status);
for item in &batch.items {
    if let Some(result) = &item.result {
        println!("{}: {:?}, admitted={}", item.id, result.status, item.is_admitted());
    }
}
```

## Client Configuration

```rust
use std::time::Duration;

let client = QWEDClient::with_options(
    "qwed_...",
    "http://localhost:8000", // your local QWED server
    Duration::from_secs(60),
);
```

## Error Handling

```rust
use qwed::{QWEDClient, Error};

match client.verify("test").await {
    Ok(result) => println!("Admitted: {}", result.is_admitted()),
Err(Error::Auth) => eprintln!("Invalid API key"),
    Err(Error::RateLimit) => eprintln!("Rate limit exceeded"),
    Err(Error::Api { code, message }) => eprintln!("Error {}: {}", code, message),
    Err(e) => eprintln!("Error: {}", e),
}
```

## Types

| Type | Description |
|------|-------------|
| `VerificationType` | Enum: Math, Logic, Stats, Fact, Code, Sql, etc. |
| `VerificationStatus` | Enum: Verified, Unverifiable, Blocked, Unknown |
| `Admission` | Enum: Admit, Blocked, Unknown |
| `VerificationResponse` | The DiagnosticResult envelope, with `is_admitted()` |
| `BatchResponse`, `BatchResult` | A batch job and its items; each item (`BatchResult`) has `is_admitted()` |
| `Error` | Error enum with Http, Auth, RateLimit, Api and Serialization variants |

## Async Runtime

This crate requires `tokio` as the async runtime:

```rust
#[tokio::main]
async fn main() {
    // ...
}
```

## License

Apache 2.0

