# qwed

> Rust SDK for QWED Verification Protocol

[![crates.io](https://img.shields.io/crates/v/qwed.svg)](https://crates.io/crates/qwed)
[![Rust 1.70+](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
qwed = "5.1.1"
tokio = { version = "1.0", features = ["rt-multi-thread", "macros"] }
```

## Quick Start

```rust
use qwed::QWEDClient;

#[tokio::main]
async fn main() -> Result<(), qwed::Error> {
    let client = QWEDClient::new("qwed_your_api_key");
    
    let result = client.verify("What is 2+2?").await?;
    println!("Verified: {}", result.verified); // true
    println!("Status: {:?}", result.status);   // Verified
    
    Ok(())
}
```

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
// result.result["satisfiability"] = "SAT"
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

let result = client.verify_batch(items).await?;
if let Some(summary) = result.summary {
    println!("Success rate: {:.1}%", summary.success_rate);
}
```

## Client Configuration

```rust
use std::time::Duration;

let client = QWEDClient::with_options(
    "qwed_...",
    "https://api.qwed.ai",
    Duration::from_secs(60),
);
```

## Error Handling

```rust
use qwed::{QWEDClient, Error};

match client.verify("test").await {
    Ok(result) => println!("Verified: {}", result.verified),
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
| `VerificationStatus` | Enum: Verified, Failed, Corrected, Blocked, etc. |
| `VerificationResponse` | Full verification result |
| `BatchResponse` | Batch operation result |
| `Error` | Error enum with Auth, RateLimit, Api variants |

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

