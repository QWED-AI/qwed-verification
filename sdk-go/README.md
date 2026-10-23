# QWED Go SDK

Official Go SDK for the [QWED Verification Protocol](https://github.com/QWED-AI/qwed-verification).

[![Go Reference](https://pkg.go.dev/badge/github.com/QWED-AI/qwed-verification/sdk-go/v7.svg)](https://pkg.go.dev/github.com/QWED-AI/qwed-verification/sdk-go/v7)
[![Go Report Card](https://goreportcard.com/badge/github.com/QWED-AI/qwed-verification/sdk-go/v7)](https://goreportcard.com/report/github.com/QWED-AI/qwed-verification/sdk-go/v7)
[![CI](https://github.com/QWED-AI/qwed-verification/actions/workflows/ci.yml/badge.svg)](https://github.com/QWED-AI/qwed-verification/actions)

## Installation

```bash
go get github.com/QWED-AI/qwed-verification/sdk-go/v7
```

The module lives in the `sdk-go/` subdirectory and tracks the main QWED version
line, so it carries the `/v7` major-version suffix and is released under
`sdk-go/vX.Y.Z` tags — e.g. `go get github.com/QWED-AI/qwed-verification/sdk-go/v7@v7.3.0`.

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    qwed "github.com/QWED-AI/qwed-verification/sdk-go/v7"
)

func main() {
    // Create client
    client := qwed.NewClient("your-api-key")

    // Verify math
    result, err := client.VerifyMath(context.Background(), "2 + 2 = 4")
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Println(result.Status, result.Admission) // VERIFIED ADMIT
    fmt.Println(result.IsAdmitted())             // true
}
```

## Reading a result

Every verification returns the server's DiagnosticResult envelope:

| Field | Meaning |
|-------|---------|
| `Status` | `StatusVerified`, `StatusUnverifiable` or `StatusBlocked` (`StatusUnknown` for a missing value or one this SDK does not know) |
| `RawStatus` | The server's status text exactly as sent, such as `SAT` where `Status` is `StatusUnknown`; never used for admission |
| `Admission` | `AdmissionAdmit` or `AdmissionBlocked` where the endpoint decides (`AdmissionUnknown` for a value this SDK does not know); empty where it does not, as on `/verify/logic`, `/verify/fact` and batch logic and fact items |
| `ProofRef` | Set only when `Status` is `StatusVerified` |
| `AgentMessage`, `DeveloperFields`, `IsAuthoritative`, `ConstraintID` | Explanation and detail |
| `Extra` | The endpoint's own fields, such as `is_valid`, `issues` or `error`. Numbers here and in `DeveloperFields` are `json.Number`, so they keep their exact text |

**Gate on `IsAdmitted()`, not on `Status`.** `VERIFIED` means the engine reached a deterministic answer, not that the claim holds: `2 + 2 = 5` is `VERIFIED · BLOCKED` (proven false), and unsafe code is `VERIFIED · BLOCKED` (proven unsafe). `IsAdmitted()` is true only for `ADMIT` together with `VERIFIED` and a `ProofRef`; a missing or unknown admission is never admitted.

The `Verified` field and `IsVerified()` are deprecated. Decoding always sets `Verified` to `IsAdmitted()`, whatever the body says, and `IsVerified()` returns `IsAdmitted()`. Endpoints that make no admission decision (`/verify/logic`, `/verify/fact`, `/verify/rag`, `/verify/process`, and batch logic and fact items) are therefore never admitted. `/verify/rag` and `/verify/process` do send a top-level `verified`, which is their guard's own result; it is kept in `Extra["verified"]` and `DeveloperFields["verified"]`.

## Features

- **Zero Dependencies** - Uses only Go standard library
- **Context Support** - All methods accept `context.Context` for cancellation
- **Mockable** - Implements `Verifier` interface for easy testing
- **Type Safe** - Full type definitions for all requests/responses

## Available Methods

| Method | Description |
|--------|-------------|
| `Health(ctx)` | Check API health status |
| `Verify(ctx, query)` | Natural language verification |
| `VerifyMath(ctx, expr)` | Mathematical expression verification |
| `VerifyLogic(ctx, query)` | Logic/reasoning verification (Z3) |
| `VerifyCode(ctx, code, lang)` | Code security scanning |
| `VerifyFact(ctx, claim, context)` | Fact verification |
| `VerifySQL(ctx, query, schema, dialect)` | SQL validation |
| `VerifyBatch(ctx, items, opts)` | Batch verification |

## Client Options

```go
client := qwed.NewClient("api-key",
    qwed.WithBaseURL("http://localhost:8000"), // your local QWED server
    qwed.WithTimeout(30 * time.Second),
    qwed.WithHTTPClient(customClient),
)
```

## Testing with Mocks

The SDK provides a `Verifier` interface for easy mocking:

```go
type Verifier interface {
    Health(ctx context.Context) (map[string]interface{}, error)
    Verify(ctx context.Context, query string) (*VerificationResponse, error)
    VerifyMath(ctx context.Context, expression string) (*VerificationResponse, error)
    // ... other methods
}

// In your tests:
type MockVerifier struct{}

func (m *MockVerifier) VerifyMath(ctx context.Context, expr string) (*qwed.VerificationResponse, error) {
    return &qwed.VerificationResponse{
        Status:    qwed.StatusVerified,
        Admission: qwed.AdmissionAdmit,
        ProofRef:  "sha256:...",
    }, nil
}

// Use mock in your code that accepts Verifier interface
func ProcessData(v qwed.Verifier, data string) error {
    result, err := v.VerifyMath(context.Background(), data)
    // ...
}
```

## Error Handling

```go
result, err := client.VerifyMath(ctx, "invalid")
if err != nil {
    if qwedErr, ok := err.(*qwed.QWEDError); ok {
        fmt.Printf("QWED Error [%s]: %s\n", qwedErr.Code, qwedErr.Message)
        fmt.Printf("HTTP Status: %d\n", qwedErr.StatusCode)
    }
}
```

## Response Types

```go
type VerificationResponse struct {
    Status          VerificationStatus     // VERIFIED, UNVERIFIABLE, BLOCKED or UNKNOWN
    RawStatus       string                 // the server's status text, such as SAT
    Admission       Admission              // ADMIT, BLOCKED, UNKNOWN, or "" for no decision
    ProofRef        string                 // set only for VERIFIED
    AgentMessage    string
    IsAuthoritative *bool
    ConstraintID    string
    DeveloperFields map[string]interface{}
    Extra           map[string]interface{} // the endpoint's own fields
    Verified        bool                   // Deprecated: set to IsAdmitted()
}

func (r *VerificationResponse) IsAdmitted() bool
```

A batch job:

```go
batch, err := client.VerifyBatch(ctx, []qwed.BatchItem{
    {Query: "2 + 2 = 4", Type: qwed.TypeMath},
    {Query: "2 + 2 = 5", Type: qwed.TypeMath},
}, nil)
if err != nil {
    log.Fatal(err)
}
// batch.Status is the job state: completed, partial, failed, ...
fmt.Println(batch.JobID, batch.Status, batch.CompletedItems, batch.FailedItems, batch.TotalItems)
for _, item := range batch.Items {
    // item.Status is the item state; item.Result is its verification answer.
    fmt.Println(item.Query, item.Status, item.IsAdmitted())
}
```

## Tests

```bash
go test ./...
```

`contract_test.go` parses responses captured from the server, stored in
`sdk-fixtures/` at the repository root, so run the tests from a checkout of
the whole repository. The Rust and TypeScript SDKs parse the same files, and
`tests/test_issue_468_rust_sdk_contract.py` fails if the server's answers
drift from them.

## Examples

See the [examples](./examples/) directory for complete usage examples.

## License

Apache 2.0 - See [LICENSE](../LICENSE)

## Related

- [QWED Main Repository](https://github.com/QWED-AI/qwed-verification)
- [Python SDK](https://pypi.org/project/qwed/)
- [TypeScript SDK](https://www.npmjs.com/package/@qwed-ai/sdk)
- [Documentation](https://docs.qwedai.tech)
