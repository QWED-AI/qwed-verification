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

// serveFixture answers every request with a response captured from the server.
func serveFixture(t *testing.T, path, name string) *httptest.Server {
	t.Helper()
	body := fixture(t, name)
	return mockServer(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			t.Errorf("expected path %s, got %s", path, r.URL.Path)
		}
		if r.Header.Get("X-API-Key") != "test-key" {
			t.Error("missing or incorrect API key header")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})
}

func TestVerifyMath(t *testing.T) {
	server := serveFixture(t, "/verify/math", "math_verified")
	defer server.Close()

	client := NewClient("test-key", WithBaseURL(server.URL))
	result, err := client.VerifyMath(context.Background(), "2 + 2 = 4")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != StatusVerified || result.Admission != AdmissionAdmit {
		t.Errorf("expected VERIFIED / ADMIT, got %s / %s", result.Status, result.Admission)
	}

	if !result.IsAdmitted() {
		t.Error("expected a true identity to be admitted")
	}
}

func TestVerifyMathProvenFalseIsNotAdmitted(t *testing.T) {
	server := serveFixture(t, "/verify/math", "math_false")
	defer server.Close()

	client := NewClient("test-key", WithBaseURL(server.URL))
	result, err := client.VerifyMath(context.Background(), "2 + 2 = 5")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != StatusVerified || result.IsAdmitted() {
		t.Errorf("expected VERIFIED and not admitted, got %s admitted=%v", result.Status, result.IsAdmitted())
	}
}

func TestVerifyLogic(t *testing.T) {
	server := serveFixture(t, "/verify/logic", "logic")
	defer server.Close()

	client := NewClient("test-key", WithBaseURL(server.URL))
	result, err := client.VerifyLogic(context.Background(), "(A AND B) implies B")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != StatusBlocked || result.Admission != "" || result.IsAdmitted() {
		t.Errorf("expected BLOCKED with no admission, got %s / %q", result.Status, result.Admission)
	}
}

func TestVerifyCode(t *testing.T) {
	server := serveFixture(t, "/verify/code", "code_unsafe")
	defer server.Close()

	client := NewClient("test-key", WithBaseURL(server.URL))
	// The server is mocked, so the code sent does not matter.
	result, err := client.VerifyCode(context.Background(), "eval(input())", "python")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Admission != AdmissionBlocked || result.IsAdmitted() {
		t.Error("expected unsafe code to be blocked")
	}
}

func TestVerifyFact(t *testing.T) {
	server := serveFixture(t, "/verify/fact", "fact")
	defer server.Close()

	client := NewClient("test-key", WithBaseURL(server.URL))
	result, err := client.VerifyFact(
		context.Background(),
		"Paris is the capital of France",
		"Paris is the capital of France.",
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != StatusUnverifiable || result.IsAdmitted() {
		t.Error("expected a heuristic fact match to be UNVERIFIABLE and not admitted")
	}
}

func TestVerifySQL(t *testing.T) {
	server := serveFixture(t, "/verify/sql", "sql")
	defer server.Close()

	client := NewClient("test-key", WithBaseURL(server.URL))
	result, err := client.VerifySQL(
		context.Background(),
		"SELECT id FROM users",
		"CREATE TABLE users (id INT)",
		"sqlite",
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.IsAdmitted() {
		t.Error("expected a safe SQL query to be admitted")
	}
}

func TestVerifyBatch(t *testing.T) {
	server := serveFixture(t, "/verify/batch", "batch")
	defer server.Close()

	client := NewClient("test-key", WithBaseURL(server.URL))
	result, err := client.VerifyBatch(context.Background(), []BatchItem{
		{Query: "2 + 2 = 4", Type: TypeMath},
		{Query: "2 + 2 = 5", Type: TypeMath},
	}, nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != "completed" || len(result.Items) != 2 {
		t.Errorf("expected a completed job with 2 items, got %s with %d", result.Status, len(result.Items))
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
		{"admitted", &VerificationResponse{Status: StatusVerified, Admission: AdmissionAdmit, ProofRef: "sha256:ab"}, true},
		{"verified but blocked", &VerificationResponse{Status: StatusVerified, Admission: AdmissionBlocked, ProofRef: "sha256:ab"}, false},
		// The deprecated field is not read: IsVerified follows admission.
		{"verified field only", &VerificationResponse{Verified: true}, false},
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
	return &VerificationResponse{Status: StatusUnverifiable, Admission: AdmissionBlocked}, nil
}

func (m *MockClient) VerifyWithOptions(ctx context.Context, query string, opts *RequestOptions) (*VerificationResponse, error) {
	return &VerificationResponse{Status: StatusUnverifiable, Admission: AdmissionBlocked}, nil
}

func (m *MockClient) VerifyMath(ctx context.Context, expression string) (*VerificationResponse, error) {
	if m.VerifyMathFunc != nil {
		return m.VerifyMathFunc(ctx, expression)
	}
	return &VerificationResponse{Status: StatusUnverifiable, Admission: AdmissionBlocked}, nil
}

func (m *MockClient) VerifyLogic(ctx context.Context, query string) (*VerificationResponse, error) {
	return &VerificationResponse{Status: StatusUnverifiable, Admission: AdmissionBlocked}, nil
}

func (m *MockClient) VerifyCode(ctx context.Context, code, language string) (*VerificationResponse, error) {
	return &VerificationResponse{Status: StatusUnverifiable, Admission: AdmissionBlocked}, nil
}

func (m *MockClient) VerifyFact(ctx context.Context, claim, factContext string) (*VerificationResponse, error) {
	return &VerificationResponse{Status: StatusUnverifiable, Admission: AdmissionBlocked}, nil
}

func (m *MockClient) VerifySQL(ctx context.Context, query, schemaDDL, dialect string) (*VerificationResponse, error) {
	return &VerificationResponse{Status: StatusUnverifiable, Admission: AdmissionBlocked}, nil
}

func (m *MockClient) VerifyBatch(ctx context.Context, items []BatchItem, opts *BatchOptions) (*BatchResponse, error) {
	return &BatchResponse{Status: "completed"}, nil
}

// Verify MockClient implements Verifier
var _ Verifier = (*MockClient)(nil)

func TestMockClientUsage(t *testing.T) {
	// Example: Using mock in tests
	mock := &MockClient{
		VerifyMathFunc: func(ctx context.Context, expr string) (*VerificationResponse, error) {
			return &VerificationResponse{
				Status:    StatusVerified,
				Admission: AdmissionAdmit,
				ProofRef:  "sha256:ab",
				Extra:     map[string]interface{}{"is_valid": true},
			}, nil
		},
	}

	result, err := mock.VerifyMath(context.Background(), "2 + 2")
	if err != nil {
		t.Fatal(err)
	}

	if !result.IsAdmitted() {
		t.Error("expected mock to return an admitted result")
	}
}
