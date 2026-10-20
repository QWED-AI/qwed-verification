//! Contract tests (#468): the SDK must parse what the QWED server sends.
//!
//! Every file in `sdk-fixtures/` at the repository root is a response
//! captured from the server for the request this SDK makes. The Go and
//! TypeScript SDKs parse the same files. `tests/test_issue_468_rust_sdk_contract.py`
//! checks that the deterministic ones still match what the server returns today.

use qwed::{Admission, BatchResponse, VerificationResponse, VerificationStatus};

fn fixture(name: &str) -> String {
    let path = format!("{}/../sdk-fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn response(name: &str) -> VerificationResponse {
    serde_json::from_str(&fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

#[test]
fn a_true_identity_is_verified_and_admitted() {
    let r = response("math_verified");
    assert_eq!(r.status, VerificationStatus::Verified);
    assert_eq!(r.admission, Some(Admission::Admit));
    assert!(r.proof_ref.as_deref().unwrap().starts_with("sha256:"));
    assert_eq!(r.is_authoritative, Some(true));
    assert!(r.is_admitted());
}

#[test]
fn a_false_identity_is_verified_but_not_admitted() {
    // The engine proved 2 + 2 = 5 false: VERIFIED, with a proof, yet BLOCKED.
    let r = response("math_false");
    assert_eq!(r.status, VerificationStatus::Verified);
    assert_eq!(r.admission, Some(Admission::Blocked));
    assert!(r.proof_ref.is_some());
    assert_eq!(r.extra["is_valid"], serde_json::Value::Bool(false));
    assert!(!r.is_admitted());
}

#[test]
fn an_ambiguous_expression_is_blocked() {
    let r = response("math_ambiguous");
    assert_eq!(r.status, VerificationStatus::Blocked);
    assert_eq!(r.admission, Some(Admission::Blocked));
    assert!(r.proof_ref.is_none());
    assert!(!r.is_admitted());
}

#[test]
fn safe_code_is_admitted_and_unsafe_code_is_not() {
    let safe = response("code_safe");
    assert_eq!(safe.status, VerificationStatus::Verified);
    assert!(safe.is_admitted());

    let unsafe_code = response("code_unsafe");
    assert_eq!(unsafe_code.status, VerificationStatus::Verified);
    assert_eq!(unsafe_code.admission, Some(Admission::Blocked));
    assert!(!unsafe_code.is_admitted());
}

#[test]
fn a_safe_sql_query_is_admitted() {
    let r = response("sql");
    assert_eq!(r.status, VerificationStatus::Verified);
    assert!(r.is_admitted());
}

#[test]
fn unverifiable_natural_language_is_not_admitted() {
    let r = response("natural_language");
    assert_eq!(r.status, VerificationStatus::Unverifiable);
    assert_eq!(r.admission, Some(Admission::Blocked));
    assert!(r.proof_ref.is_none());
    assert!(!r.is_admitted());
}

#[test]
fn responses_without_an_admission_are_not_admitted() {
    // /verify/logic and /verify/fact make no admission decision.
    let logic = response("logic");
    assert_eq!(logic.status, VerificationStatus::Blocked);
    assert_eq!(logic.admission, None);
    assert!(logic.extra["error"].is_string());
    assert!(!logic.is_admitted());

    let fact = response("fact");
    assert_eq!(fact.status, VerificationStatus::Unverifiable);
    assert_eq!(fact.admission, None);
    assert!(!fact.is_admitted());
}

#[test]
fn a_batch_job_and_its_items_parse() {
    let batch: BatchResponse = serde_json::from_str(&fixture("batch")).unwrap();
    assert_eq!(batch.status, "completed");
    assert_eq!(batch.total_items, Some(2));
    assert_eq!(batch.items.len(), 2);

    let statuses: Vec<_> = batch
        .items
        .iter()
        .map(|item| item.result.as_ref().unwrap().status.clone())
        .collect();
    assert_eq!(statuses, [VerificationStatus::Verified, VerificationStatus::Unverifiable]);
    assert_eq!(batch.items[0].item_type.as_deref(), Some("math"));

    // Batch math items carry no admission decision today, so none is admitted.
    assert!(batch.items.iter().all(|item| !item.is_admitted()));
}
