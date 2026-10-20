package qwed

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ============================================================================
// Mock Server Setup
// ============================================================================

func mockServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

// ============================================================================
// Client Tests
// ============================================================================

func TestNewClient(t *testing.T) {
	client := NewClient("test-api-key")

	if client == nil {
		t.Fatal("expected non-nil client")
	}

	if client.apiKey != "test-api-key" {
		t.Errorf("expected apiKey 'test-api-key', got '%s'", client.apiKey)
	}

	if client.baseURL != "http://localhost:8000" {
		t.Errorf("expected default baseURL, got '%s'", client.baseURL)
	}
}

func TestNewClientWithOptions(t *testing.T) {
	client := NewClient("test-key",
		WithBaseURL("http://127.0.0.1:9000"),
		WithTimeout(10*time.Second),
	)

	if client.baseURL != "http://127.0.0.1:9000" {
		t.Errorf("expected custom baseURL, got '%s'", client.baseURL)
	}
}

func TestClientImplementsVerifier(t *testing.T) {
	var _ Verifier = (*Client)(nil)
	// If this compiles, Client implements Verifier
}

// ============================================================================
// API Method Tests with Mock Server
// ============================================================================

func TestHealth(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("expected path /health, got %s", r.URL.Path)
		}
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "healthy",
			"version": "2.0.0",
		})
	})
	defer server.Close()

	client := NewClient("test-key", WithBaseURL(server.URL))
	result, err := client.Health(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got '%v'", result["status"])
	}
}

func TestVerifyMath(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify/math" {
			t.Errorf("expected path /verify/math, got %s", r.URL.Path)
		}

		// Check headers
		if r.Header.Get("X-API-Key") != "test-key" {
			t.Error("missing or incorrect API key header")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(VerificationResponse{
			Status:   StatusVerified,
			Verified: true,
			Engine:   "math",
		})
	})
	defer server.Close()

	client := NewClient("test-key", WithBaseURL(server.URL))
	result, err := client.VerifyMath(context.Background(), "2 + 2 = 4")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Verified {
		t.Error("expected verified to be true")
	}

	if result.Engine != "math" {
		t.Errorf("expected engine 'math', got '%s'", result.Engine)
	}
}

func TestVerifyLogic(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(VerificationResponse{
			Status:   StatusVerified,
			Verified: true,
			Engine:   "logic",
		})
	})
	defer server.Close()

	client := NewClient("test-key", WithBaseURL(server.URL))
	result, err := client.VerifyLogic(context.Background(), "(A AND B) implies B")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Verified {
		t.Error("expected verified to be true")
	}
}

func TestVerifyCode(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(VerificationResponse{
			Status:   StatusFailed,
			Verified: false,
			Engine:   "code",
			Result: map[string]interface{}{
				"vulnerabilities": []string{"eval_usage"},
			},
		})
	})
	defer server.Close()

	client := NewClient("test-key", WithBaseURL(server.URL))
	result, err := client.VerifyCode(context.Background(), "eval(input())", "python")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Verified {
		t.Error("expected verified to be false for unsafe code")
	}
}

func TestVerifyFact(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(VerificationResponse{
			Status:   StatusVerified,
			Verified: true,
			Engine:   "fact",
		})
	})
	defer server.Close()

	client := NewClient("test-key", WithBaseURL(server.URL))
	result, err := client.VerifyFact(
		context.Background(),
		"Paris is the capital of France",
		"France is a country in Europe. Its capital city is Paris.",
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Verified {
		t.Error("expected fact to be verified")
	}
}

func TestVerifySQL(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(VerificationResponse{
			Status:   StatusVerified,
			Verified: true,
			Engine:   "sql",
		})
	})
	defer server.Close()

	client := NewClient("test-key", WithBaseURL(server.URL))
	result, err := client.VerifySQL(
		context.Background(),
		"SELECT * FROM users WHERE id = 1",
		"CREATE TABLE users (id INT, name VARCHAR(100))",
		"postgresql",
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Verified {
		t.Error("expected SQL to be verified")
	}
}

// ============================================================================
// Error Handling Tests
// ============================================================================

func TestAPIError(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "INVALID_API_KEY",
				"message": "The provided API key is invalid",
			},
		})
	})
	defer server.Close()

	client := NewClient("bad-key", WithBaseURL(server.URL))
	_, err := client.Health(context.Background())

	if err == nil {
		t.Fatal("expected error for invalid API key")
	}

	qwedErr, ok := err.(*QWEDError)
	if !ok {
		t.Fatal("expected QWEDError type")
	}

	if qwedErr.StatusCode != 401 {
		t.Errorf("expected status 401, got %d", qwedErr.StatusCode)
	}
}

func TestContextCancellation(t *testing.T) {
	server := mockServer(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
	})
	defer server.Close()

	client := NewClient("test-key", WithBaseURL(server.URL))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := client.Health(ctx)

	if err == nil {
		t.Error("expected context deadline error")
	}
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestIsVerified(t *testing.T) {
	tests := []struct {
		name     string
		response *VerificationResponse
		expected bool
	}{
		{"nil response", nil, false},
		{"verified true", &VerificationResponse{Verified: true}, true},
		{"verified false", &VerificationResponse{Verified: false}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsVerified(tt.response)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// ============================================================================
// Mock Client Example (for documentation)
// ============================================================================

// MockClient is an example of how users can mock the QWED client for testing.
type MockClient struct {
	VerifyMathFunc func(ctx context.Context, expr string) (*VerificationResponse, error)
}

func (m *MockClient) Health(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{"status": "mock"}, nil
}

func (m *MockClient) Verify(ctx context.Context, query string) (*VerificationResponse, error) {
	return &VerificationResponse{Verified: true}, nil
}

func (m *MockClient) VerifyWithOptions(ctx context.Context, query string, opts *RequestOptions) (*VerificationResponse, error) {
	return &VerificationResponse{Verified: true}, nil
}

func (m *MockClient) VerifyMath(ctx context.Context, expression string) (*VerificationResponse, error) {
	if m.VerifyMathFunc != nil {
		return m.VerifyMathFunc(ctx, expression)
	}
	return &VerificationResponse{Verified: true, Engine: "math"}, nil
}

func (m *MockClient) VerifyLogic(ctx context.Context, query string) (*VerificationResponse, error) {
	return &VerificationResponse{Verified: true, Engine: "logic"}, nil
}

func (m *MockClient) VerifyCode(ctx context.Context, code, language string) (*VerificationResponse, error) {
	return &VerificationResponse{Verified: true, Engine: "code"}, nil
}

func (m *MockClient) VerifyFact(ctx context.Context, claim, factContext string) (*VerificationResponse, error) {
	return &VerificationResponse{Verified: true, Engine: "fact"}, nil
}

func (m *MockClient) VerifySQL(ctx context.Context, query, schemaDDL, dialect string) (*VerificationResponse, error) {
	return &VerificationResponse{Verified: true, Engine: "sql"}, nil
}

func (m *MockClient) VerifyBatch(ctx context.Context, items []BatchItem, opts *BatchOptions) (*BatchResponse, error) {
	return &BatchResponse{Status: "complete"}, nil
}

// Verify MockClient implements Verifier
var _ Verifier = (*MockClient)(nil)

func TestMockClientUsage(t *testing.T) {
	// Example: Using mock in tests
	mock := &MockClient{
		VerifyMathFunc: func(ctx context.Context, expr string) (*VerificationResponse, error) {
			return &VerificationResponse{
				Verified: true,
				Engine:   "math",
				Result:   map[string]interface{}{"answer": 4},
			}, nil
		},
	}

	result, err := mock.VerifyMath(context.Background(), "2 + 2")
	if err != nil {
		t.Fatal(err)
	}

	if !result.Verified {
		t.Error("expected mock to return verified")
	}
}
