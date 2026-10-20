// Package qwed provides a Go client for the QWED Verification Protocol.
//
// Example usage:
//
//	client := qwed.NewClient("qwed_your_api_key")
//	result, err := client.VerifyMath(context.Background(), "2 + 2 = 4")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(result.Status, result.Admission, result.IsAdmitted()) // VERIFIED ADMIT true
//
// Every verification answer is a QWED DiagnosticResult: a Status (VERIFIED,
// UNVERIFIABLE or BLOCKED), an Admission decision (ADMIT or BLOCKED) where
// the endpoint makes one, and a ProofRef when the status is VERIFIED. Gate on
// IsAdmitted, never on the status alone: 2 + 2 = 5 is also VERIFIED (proven
// false) but is not admitted.
package qwed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ============================================================================
// Types
// ============================================================================

// VerificationType represents the type of verification to perform.
type VerificationType string

const (
	TypeNaturalLanguage VerificationType = "natural_language"
	TypeMath            VerificationType = "math"
	TypeLogic           VerificationType = "logic"
	TypeStats           VerificationType = "stats"
	TypeFact            VerificationType = "fact"
	TypeCode            VerificationType = "code"
	TypeSQL             VerificationType = "sql"
	TypeImage           VerificationType = "image"
	TypeReasoning       VerificationType = "reasoning"
)

// VerificationStatus is the diagnostic status of a verification
// (DiagnosticResult.status).
//
// StatusVerified says the engine reached a deterministic answer, not that the
// claim holds: a false identity such as 2 + 2 = 5 is VERIFIED too, and its
// admission is BLOCKED. Gate on VerificationResponse.IsAdmitted.
type VerificationStatus string

const (
	// StatusVerified: the claim was evaluated deterministically and
	// ProofRef is set.
	StatusVerified VerificationStatus = "VERIFIED"
	// StatusUnverifiable: the claim could not be proven.
	StatusUnverifiable VerificationStatus = "UNVERIFIABLE"
	// StatusBlocked: verification could not be attempted (parse error,
	// policy, missing dependency).
	StatusBlocked VerificationStatus = "BLOCKED"
	// StatusUnknown: a missing status, or one this SDK version does not
	// know. Never admitted.
	StatusUnknown VerificationStatus = "UNKNOWN"
)

// UnmarshalJSON keeps the three statuses the server sends and maps any other
// value, including null, to StatusUnknown.
func (s *VerificationStatus) UnmarshalJSON(data []byte) error {
	var raw *string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*s = StatusUnknown
	if raw != nil {
		switch v := VerificationStatus(*raw); v {
		case StatusVerified, StatusUnverifiable, StatusBlocked:
			*s = v
		}
	}
	return nil
}

// Admission is the server's decision at its enforcement boundary.
//
// The empty value means the endpoint made no admission decision, as
// /verify/logic, /verify/fact and batch items do today. It is never admitted.
type Admission string

const (
	// AdmissionAdmit: the boundary may proceed with the verdict.
	AdmissionAdmit Admission = "ADMIT"
	// AdmissionBlocked: the boundary must not admit.
	AdmissionBlocked Admission = "BLOCKED"
	// AdmissionUnknown: a decision this SDK version does not know. Never
	// admitted.
	AdmissionUnknown Admission = "UNKNOWN"
)

// UnmarshalJSON keeps ADMIT and BLOCKED, maps null to the empty value (no
// decision) and any other value to AdmissionUnknown.
func (a *Admission) UnmarshalJSON(data []byte) error {
	var raw *string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*a = ""
	if raw != nil {
		*a = AdmissionUnknown
		switch v := Admission(*raw); v {
		case AdmissionAdmit, AdmissionBlocked:
			*a = v
		}
	}
	return nil
}

// VerificationRequest represents a verification request.
type VerificationRequest struct {
	Query   string                 `json:"query"`
	Type    VerificationType       `json:"type,omitempty"`
	Params  map[string]interface{} `json:"params,omitempty"`
	Options *RequestOptions        `json:"options,omitempty"`
}

// RequestOptions configures request behavior.
type RequestOptions struct {
	TimeoutMs            int  `json:"timeout_ms,omitempty"`
	IncludeProof         bool `json:"include_proof,omitempty"`
	IncludeAttestation   bool `json:"include_attestation,omitempty"`
}

// VerificationResponse is a verification answer: the server's
// DiagnosticResult envelope.
type VerificationResponse struct {
	Status VerificationStatus `json:"status"`
	// Admission is empty where the endpoint makes no decision. Empty is not
	// admitted.
	Admission Admission `json:"admission,omitempty"`
	// ProofRef is set only when Status is StatusVerified.
	ProofRef        string                 `json:"proof_ref,omitempty"`
	AgentMessage    string                 `json:"agent_message,omitempty"`
	IsAuthoritative *bool                  `json:"is_authoritative,omitempty"`
	ConstraintID    string                 `json:"constraint_id,omitempty"`
	DeveloperFields map[string]interface{} `json:"developer_fields,omitempty"`
	// Extra holds the endpoint's own fields, such as is_valid, issues or
	// error.
	Extra map[string]interface{} `json:"-"`

	// Verified is set to IsAdmitted() when a response is decoded. The server
	// sends no verified field.
	//
	// Deprecated: use IsAdmitted.
	Verified bool `json:"-"`
}

// envelopeFields are the keys VerificationResponse reads itself; every other
// key goes to Extra.
var envelopeFields = map[string]bool{
	"status": true, "admission": true, "proof_ref": true, "agent_message": true,
	"is_authoritative": true, "constraint_id": true, "developer_fields": true,
}

// UnmarshalJSON decodes the envelope, keeps the other fields in Extra and
// sets the deprecated Verified field from IsAdmitted. A field of the wrong
// JSON type, such as a non-string proof_ref, is an error.
func (r *VerificationResponse) UnmarshalJSON(data []byte) error {
	type envelope VerificationResponse // no methods, so no recursion
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return err
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for key := range envelopeFields {
		delete(fields, key)
	}
	*r = VerificationResponse(env)
	if r.Status == "" {
		// No status key: the field's own UnmarshalJSON never ran.
		r.Status = StatusUnknown
	}
	r.Extra = fields
	r.Verified = r.IsAdmitted()
	return nil
}

// MarshalJSON writes the envelope fields with Extra's keys beside them, as
// the server sent them, so a decoded response survives a round trip. An
// Extra key never replaces an envelope field, even one left out because it
// is empty.
func (r VerificationResponse) MarshalJSON() ([]byte, error) {
	type envelope VerificationResponse // no methods, so no recursion
	data, err := json.Marshal(envelope(r))
	if err != nil || len(r.Extra) == 0 {
		return data, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	for key, value := range r.Extra {
		if envelopeFields[key] {
			continue
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		fields[key] = raw
	}
	return json.Marshal(fields)
}

// IsAdmitted reports whether the server admitted the result: Admission is
// ADMIT, Status is VERIFIED and ProofRef is set. Anything else, including a
// missing or unknown admission, is not admitted. It is false for nil.
func (r *VerificationResponse) IsAdmitted() bool {
	return r != nil &&
		r.Admission == AdmissionAdmit &&
		r.Status == StatusVerified &&
		r.ProofRef != ""
}

// ErrorInfo contains the details of a failed HTTP request.
type ErrorInfo struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// BatchRequest represents a batch verification request.
type BatchRequest struct {
	Items   []BatchItem    `json:"items"`
	Options *BatchOptions  `json:"options,omitempty"`
}

// BatchItem represents a single item in a batch.
type BatchItem struct {
	Query string           `json:"query"`
	Type  VerificationType `json:"type,omitempty"`
}

// BatchOptions configures batch behavior.
type BatchOptions struct {
	MaxParallel int  `json:"max_parallel,omitempty"`
	FailFast    bool `json:"fail_fast,omitempty"`
}

// BatchResponse is a batch job and its items.
type BatchResponse struct {
	JobID string `json:"job_id"`
	// Status is the job state: pending, processing, completed, partial or
	// failed.
	Status          string        `json:"status"`
	ProgressPercent float64       `json:"progress_percent"`
	TotalItems      int           `json:"total_items"`
	CompletedItems  int           `json:"completed_items"`
	FailedItems     int           `json:"failed_items"`
	CreatedAt       string        `json:"created_at,omitempty"`
	CompletedAt     string        `json:"completed_at,omitempty"`
	Items           []BatchResult `json:"items"`
}

// BatchResult is one item of a batch job.
type BatchResult struct {
	ID string `json:"id"`
	// Status is the item state, such as pending, completed or failed. The
	// verification status is Result.Status.
	Status string           `json:"status"`
	Query  string           `json:"query,omitempty"`
	Type   VerificationType `json:"type,omitempty"`
	// Result is the item's verification answer, once it has one.
	Result    *VerificationResponse `json:"result,omitempty"`
	Error     string                `json:"error,omitempty"`
	LatencyMs float64               `json:"latency_ms,omitempty"`

	// Verified is set to IsAdmitted() when an item is decoded. The server
	// sends no verified field.
	//
	// Deprecated: use IsAdmitted.
	Verified bool `json:"-"`
}

// UnmarshalJSON decodes the item and sets the deprecated Verified field from
// IsAdmitted.
func (b *BatchResult) UnmarshalJSON(data []byte) error {
	type item BatchResult // no methods, so no recursion
	var it item
	if err := json.Unmarshal(data, &it); err != nil {
		return err
	}
	*b = BatchResult(it)
	b.Verified = b.IsAdmitted()
	return nil
}

// IsAdmitted reports whether the item has a result that is admitted (see
// VerificationResponse.IsAdmitted). It is false for nil.
func (b *BatchResult) IsAdmitted() bool {
	return b != nil && b.Result.IsAdmitted()
}

// ============================================================================
// Errors
// ============================================================================

// QWEDError represents a QWED API error.
type QWEDError struct {
	Code       string
	Message    string
	StatusCode int
}

func (e *QWEDError) Error() string {
	return fmt.Sprintf("QWED Error [%s]: %s", e.Code, e.Message)
}

// ============================================================================
// Verifier Interface (for mocking in tests)
// ============================================================================

// Verifier defines the interface for QWED verification operations.
// Users can implement this interface to create mock clients for testing.
type Verifier interface {
	Health(ctx context.Context) (map[string]interface{}, error)
	Verify(ctx context.Context, query string) (*VerificationResponse, error)
	VerifyWithOptions(ctx context.Context, query string, opts *RequestOptions) (*VerificationResponse, error)
	VerifyMath(ctx context.Context, expression string) (*VerificationResponse, error)
	VerifyLogic(ctx context.Context, query string) (*VerificationResponse, error)
	VerifyCode(ctx context.Context, code, language string) (*VerificationResponse, error)
	VerifyFact(ctx context.Context, claim, factContext string) (*VerificationResponse, error)
	VerifySQL(ctx context.Context, query, schemaDDL, dialect string) (*VerificationResponse, error)
	VerifyBatch(ctx context.Context, items []BatchItem, opts *BatchOptions) (*BatchResponse, error)
}

// Ensure Client implements Verifier
var _ Verifier = (*Client)(nil)

// ============================================================================
// Client
// ============================================================================

// Client is the QWED API client.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// ClientOption configures the client.
type ClientOption func(*Client)

// WithBaseURL sets a custom base URL.
func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseURL = url
	}
}

// WithTimeout sets the HTTP timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient = client
	}
}

// NewClient creates a new QWED client.
func NewClient(apiKey string, opts ...ClientOption) *Client {
	c := &Client{
		apiKey:  apiKey,
		baseURL: "http://localhost:8000",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// ============================================================================
// API Methods
// ============================================================================

// Health checks the API health status.
func (c *Client) Health(ctx context.Context) (map[string]interface{}, error) {
	var result map[string]interface{}
	err := c.request(ctx, "GET", "/health", nil, &result)
	return result, err
}

// Verify performs a natural language verification.
func (c *Client) Verify(ctx context.Context, query string) (*VerificationResponse, error) {
	return c.VerifyWithOptions(ctx, query, nil)
}

// VerifyWithOptions performs verification with custom options.
func (c *Client) VerifyWithOptions(ctx context.Context, query string, opts *RequestOptions) (*VerificationResponse, error) {
	req := &VerificationRequest{
		Query:   query,
		Type:    TypeNaturalLanguage,
		Options: opts,
	}

	var resp VerificationResponse
	err := c.request(ctx, "POST", "/verify/natural_language", req, &resp)
	return &resp, err
}

// VerifyMath verifies a mathematical expression.
func (c *Client) VerifyMath(ctx context.Context, expression string) (*VerificationResponse, error) {
	req := map[string]interface{}{
		"expression": expression,
	}

	var resp VerificationResponse
	err := c.request(ctx, "POST", "/verify/math", req, &resp)
	return &resp, err
}

// VerifyLogic verifies a QWED-Logic DSL expression.
func (c *Client) VerifyLogic(ctx context.Context, query string) (*VerificationResponse, error) {
	req := map[string]interface{}{
		"query": query,
	}

	var resp VerificationResponse
	err := c.request(ctx, "POST", "/verify/logic", req, &resp)
	return &resp, err
}

// VerifyCode checks code for security vulnerabilities.
func (c *Client) VerifyCode(ctx context.Context, code, language string) (*VerificationResponse, error) {
	req := map[string]interface{}{
		"code":     code,
		"language": language,
	}

	var resp VerificationResponse
	err := c.request(ctx, "POST", "/verify/code", req, &resp)
	return &resp, err
}

// VerifyFact verifies a factual claim against context.
func (c *Client) VerifyFact(ctx context.Context, claim, factContext string) (*VerificationResponse, error) {
	req := map[string]interface{}{
		"claim":   claim,
		"context": factContext,
	}

	var resp VerificationResponse
	err := c.request(ctx, "POST", "/verify/fact", req, &resp)
	return &resp, err
}

// VerifySQL validates a SQL query against a schema.
func (c *Client) VerifySQL(ctx context.Context, query, schemaDDL, dialect string) (*VerificationResponse, error) {
	req := map[string]interface{}{
		"query":      query,
		"schema_ddl": schemaDDL,
		"dialect":    dialect,
	}

	var resp VerificationResponse
	err := c.request(ctx, "POST", "/verify/sql", req, &resp)
	return &resp, err
}

// VerifyBatch processes multiple verifications concurrently.
func (c *Client) VerifyBatch(ctx context.Context, items []BatchItem, opts *BatchOptions) (*BatchResponse, error) {
	req := map[string]interface{}{
		"items":   items,
		"options": opts,
	}

	var resp BatchResponse
	err := c.request(ctx, "POST", "/verify/batch", req, &resp)
	return &resp, err
}

// ============================================================================
// HTTP Helpers
// ============================================================================

func (c *Client) request(ctx context.Context, method, path string, body, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error *ErrorInfo `json:"error"`
		}
		json.Unmarshal(data, &errResp)

		code := fmt.Sprintf("HTTP-%d", resp.StatusCode)
		message := string(data)
		if errResp.Error != nil {
			code = errResp.Error.Code
			message = errResp.Error.Message
		}

		return &QWEDError{
			Code:       code,
			Message:    message,
			StatusCode: resp.StatusCode,
		}
	}

	if result != nil {
		if err := json.Unmarshal(data, result); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// ============================================================================
// Helpers
// ============================================================================

// IsVerified returns resp.IsAdmitted().
//
// Deprecated: use VerificationResponse.IsAdmitted. VERIFIED alone is not a
// pass, and the server sends no verified field.
func IsVerified(resp *VerificationResponse) bool {
	return resp.IsAdmitted()
}
