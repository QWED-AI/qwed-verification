package qwed

// Contract tests (#480): the SDK must parse what the QWED server sends.
//
// Every file in sdk-fixtures/ at the repository root is a response captured
// from the server. The Rust and TypeScript SDKs parse the same files, and
// tests/test_issue_468_rust_sdk_contract.py checks that the deterministic
// ones still match what the server returns today.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "sdk-fixtures", name+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return data
}

func response(t *testing.T, name string) *VerificationResponse {
	t.Helper()
	var r VerificationResponse
	if err := json.Unmarshal(fixture(t, name), &r); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return &r
}

func TestContractEveryFixture(t *testing.T) {
	tests := []struct {
		name      string
		status    VerificationStatus
		admission Admission
		proof     bool
		admitted  bool
	}{
		{"math_verified", StatusVerified, AdmissionAdmit, true, true},
		// The engine proved 2 + 2 = 5 false: VERIFIED, with a proof, yet BLOCKED.
		{"math_false", StatusVerified, AdmissionBlocked, true, false},
		{"math_ambiguous", StatusBlocked, AdmissionBlocked, false, false},
		{"code_safe", StatusVerified, AdmissionAdmit, true, true},
		{"code_unsafe", StatusVerified, AdmissionBlocked, true, false},
		{"sql", StatusVerified, AdmissionAdmit, true, true},
		{"natural_language", StatusUnverifiable, AdmissionBlocked, false, false},
		// /verify/logic and /verify/fact make no admission decision.
		{"logic", StatusBlocked, "", false, false},
		{"fact", StatusUnverifiable, "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := response(t, tt.name)
			if r.Status != tt.status {
				t.Errorf("status: got %q, want %q", r.Status, tt.status)
			}
			if r.Admission != tt.admission {
				t.Errorf("admission: got %q, want %q", r.Admission, tt.admission)
			}
			if (r.ProofRef != "") != tt.proof {
				t.Errorf("proof_ref: got %q, want present=%v", r.ProofRef, tt.proof)
			}
			if r.IsAdmitted() != tt.admitted {
				t.Errorf("IsAdmitted: got %v, want %v", r.IsAdmitted(), tt.admitted)
			}
			if r.Verified != tt.admitted {
				t.Errorf("deprecated Verified: got %v, want %v", r.Verified, tt.admitted)
			}
			if r.AgentMessage == "" {
				t.Error("agent_message is empty")
			}
			if r.IsAuthoritative == nil {
				t.Error("is_authoritative is missing")
			}
		})
	}
}

func TestContractEnvelopeDetails(t *testing.T) {
	verified := response(t, "math_verified")
	if len(verified.ProofRef) < 7 || verified.ProofRef[:7] != "sha256:" {
		t.Errorf("proof_ref: got %q, want a sha256: reference", verified.ProofRef)
	}
	if verified.IsAuthoritative == nil || !*verified.IsAuthoritative {
		t.Error("a deterministic proof should be authoritative")
	}

	// Endpoint fields go to Extra; envelope fields do not.
	falseIdentity := response(t, "math_false")
	if falseIdentity.Extra["is_valid"] != false {
		t.Errorf("Extra[is_valid]: got %v, want false", falseIdentity.Extra["is_valid"])
	}
	// /verify/math sends result as a boolean.
	if falseIdentity.Extra["result"] != false {
		t.Errorf("Extra[result]: got %v, want false", falseIdentity.Extra["result"])
	}
	for _, key := range envelopeFields {
		if _, ok := falseIdentity.Extra[key]; ok {
			t.Errorf("Extra holds envelope field %q", key)
		}
	}

	// /verify/logic sends error as a string.
	logic := response(t, "logic")
	if _, ok := logic.Extra["error"].(string); !ok {
		t.Errorf("Extra[error]: got %T, want string", logic.Extra["error"])
	}

	unsafeCode := response(t, "code_unsafe")
	if unsafeCode.ConstraintID != "code_verifier.code_unsafe" {
		t.Errorf("constraint_id: got %q", unsafeCode.ConstraintID)
	}
	if unsafeCode.DeveloperFields["is_safe"] != false {
		t.Errorf("developer_fields[is_safe]: got %v, want false", unsafeCode.DeveloperFields["is_safe"])
	}
}

func TestContractBatch(t *testing.T) {
	var batch BatchResponse
	if err := json.Unmarshal(fixture(t, "batch"), &batch); err != nil {
		t.Fatal(err)
	}
	if batch.JobID == "" || batch.Status != "completed" {
		t.Errorf("job: got id %q status %q", batch.JobID, batch.Status)
	}
	if batch.TotalItems != 2 || batch.CompletedItems != 2 || batch.FailedItems != 0 {
		t.Errorf("counts: got %d/%d/%d", batch.TotalItems, batch.CompletedItems, batch.FailedItems)
	}
	if batch.ProgressPercent != 100 {
		t.Errorf("progress_percent: got %v", batch.ProgressPercent)
	}
	if len(batch.Items) != 2 {
		t.Fatalf("items: got %d, want 2", len(batch.Items))
	}

	want := []VerificationStatus{StatusVerified, StatusUnverifiable}
	for i, item := range batch.Items {
		if item.Status != "completed" || item.Type != TypeMath || item.Query == "" {
			t.Errorf("item %d: got status %q type %q query %q", i, item.Status, item.Type, item.Query)
		}
		if item.Result == nil {
			t.Fatalf("item %d: no result", i)
		}
		if item.Result.Status != want[i] {
			t.Errorf("item %d: status %q, want %q", i, item.Result.Status, want[i])
		}
		// Batch math items carry no admission decision today, so none is admitted.
		if item.Result.Admission != "" || item.IsAdmitted() || item.Verified {
			t.Errorf("item %d: admitted without an admission decision", i)
		}
	}
	if batch.Items[0].Result.ProofRef == "" {
		t.Error("the VERIFIED batch item has no proof_ref")
	}
}

func TestStatusAndAdmissionParsing(t *testing.T) {
	tests := []struct {
		body      string
		status    VerificationStatus
		admission Admission
	}{
		{`{"status": "VERIFIED", "admission": "ADMIT"}`, StatusVerified, AdmissionAdmit},
		{`{"status": "UNVERIFIABLE", "admission": "BLOCKED"}`, StatusUnverifiable, AdmissionBlocked},
		{`{"status": "BLOCKED"}`, StatusBlocked, ""},
		{`{"status": "BLOCKED", "admission": null}`, StatusBlocked, ""},
		// Unrecognised values, wrong case and old statuses are Unknown.
		{`{"status": "PASSED", "admission": "DENY"}`, StatusUnknown, AdmissionUnknown},
		{`{"status": "verified", "admission": "admit"}`, StatusUnknown, AdmissionUnknown},
		{`{"status": "FAILED"}`, StatusUnknown, ""},
		{`{"status": null}`, StatusUnknown, ""},
		{`{}`, StatusUnknown, ""},
	}
	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			var r VerificationResponse
			if err := json.Unmarshal([]byte(tt.body), &r); err != nil {
				t.Fatal(err)
			}
			if r.Status != tt.status || r.Admission != tt.admission {
				t.Errorf("got %q/%q, want %q/%q", r.Status, r.Admission, tt.status, tt.admission)
			}
		})
	}
}

func TestIsAdmittedFailsClosed(t *testing.T) {
	proof := `"proof_ref": "sha256:ab"`
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"admit, verified, proof", `{"status": "VERIFIED", "admission": "ADMIT", ` + proof + `}`, true},
		{"blocked admission", `{"status": "VERIFIED", "admission": "BLOCKED", ` + proof + `}`, false},
		{"no admission", `{"status": "VERIFIED", ` + proof + `}`, false},
		{"unknown admission", `{"status": "VERIFIED", "admission": "DENY", ` + proof + `}`, false},
		{"admit without proof", `{"status": "VERIFIED", "admission": "ADMIT"}`, false},
		{"admit with empty proof", `{"status": "VERIFIED", "admission": "ADMIT", "proof_ref": ""}`, false},
		{"admit with null proof", `{"status": "VERIFIED", "admission": "ADMIT", "proof_ref": null}`, false},
		{"admit, unverifiable", `{"status": "UNVERIFIABLE", "admission": "ADMIT", ` + proof + `}`, false},
		{"admit, unknown status", `{"status": "PASSED", "admission": "ADMIT", ` + proof + `}`, false},
		{"admit, no status", `{"admission": "ADMIT", ` + proof + `}`, false},
		// A top-level verified field is not read.
		{"verified true only", `{"status": "VERIFIED", "verified": true}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r VerificationResponse
			if err := json.Unmarshal([]byte(tt.body), &r); err != nil {
				t.Fatal(err)
			}
			if r.IsAdmitted() != tt.want || r.Verified != tt.want || IsVerified(&r) != tt.want {
				t.Errorf("IsAdmitted %v, Verified %v, IsVerified %v; want %v",
					r.IsAdmitted(), r.Verified, IsVerified(&r), tt.want)
			}
		})
	}

	var nilResponse *VerificationResponse
	var nilItem *BatchResult
	if nilResponse.IsAdmitted() || IsVerified(nil) || nilItem.IsAdmitted() || (&BatchResult{}).IsAdmitted() {
		t.Error("nil responses and items without a result must not be admitted")
	}
}

func TestEnvelopeFieldOfTheWrongTypeIsAnError(t *testing.T) {
	for _, body := range []string{
		`{"status": "VERIFIED", "admission": "ADMIT", "proof_ref": {"sha256": "ab"}}`,
		`{"status": "VERIFIED", "is_authoritative": "true"}`,
		`{"status": "VERIFIED", "admission": true}`,
		`{"status": 1}`,
	} {
		var r VerificationResponse
		if err := json.Unmarshal([]byte(body), &r); err == nil {
			t.Errorf("%s: parsed without an error", body)
		}
	}
}
