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
`sdk-go/vX.Y.Z` tags — e.g. `go get github.com/QWED-AI/qwed-verification/sdk-go/v7@v7.2.4`.

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
    
    fmt.Printf("Verified: %v\n", result.Verified)
}
```

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
    qwed.WithBaseURL("https://api.qwedai.com"),
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
    return &qwed.VerificationResponse{Verified: true}, nil
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
    Status      VerificationStatus     `json:"status"`
    Verified    bool                   `json:"verified"`
    Engine      string                 `json:"engine,omitempty"`
    Result      map[string]interface{} `json:"result,omitempty"`
    Attestation string                 `json:"attestation,omitempty"`
    Error       *ErrorInfo             `json:"error,omitempty"`
    Metadata    *ResponseMetadata      `json:"metadata,omitempty"`
}
```

## Examples

See the [examples](./examples/) directory for complete usage examples.

## License

Apache 2.0 - See [LICENSE](../LICENSE)

## Related

- [QWED Main Repository](https://github.com/QWED-AI/qwed-verification)
- [Python SDK](https://pypi.org/project/qwed/)
- [TypeScript SDK](https://www.npmjs.com/package/@qwed-ai/sdk)
- [Documentation](https://docs.qwedai.com)
