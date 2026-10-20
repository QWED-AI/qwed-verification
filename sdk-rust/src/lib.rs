//! QWED Rust SDK
//!
//! A Rust client for the QWED Verification Protocol.
//!
//! # Example
//! ```rust,no_run
//! use qwed::QWEDClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), qwed::Error> {
//!     let client = QWEDClient::new("qwed_your_api_key");
//!     let result = client.verify_math("2 + 2 = 4").await?;
//!     // Gate on admission, not on the status alone: `2 + 2 = 5` is also
//!     // VERIFIED (proven false) but is not admitted.
//!     println!("{:?} admitted={}", result.status, result.is_admitted());
//!     Ok(())
//! }
//! ```
//!
//! Every verification answer is a QWED DiagnosticResult: a `status`
//! (`VERIFIED`, `UNVERIFIABLE` or `BLOCKED`), an `admission` decision
//! (`ADMIT` or `BLOCKED`) where the endpoint makes one, and a `proof_ref`
//! when the status is `VERIFIED`. [`VerificationResponse::is_admitted`] is
//! the only check to gate on.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

// ============================================================================
// Types
// ============================================================================

/// Verification type/engine
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VerificationType {
    #[default]
    NaturalLanguage,
    Math,
    Logic,
    Stats,
    Fact,
    Code,
    Sql,
    Image,
    Reasoning,
}

/// Diagnostic status of a verification (`DiagnosticResult.status`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum VerificationStatus {
    /// The claim was evaluated deterministically and `proof_ref` is set. This
    /// says the engine reached an answer, not that the claim holds: a false
    /// identity is VERIFIED too. Gate on [`VerificationResponse::is_admitted`].
    Verified,
    /// The claim could not be proven.
    Unverifiable,
    /// Verification could not be attempted (parse error, policy, missing
    /// dependency).
    Blocked,
    /// A status this SDK version does not know. Never admitted.
    #[serde(other)]
    Unknown,
}

/// Admission decision at the server's enforcement boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Admission {
    /// The boundary may proceed with the verdict.
    Admit,
    /// The boundary must not admit.
    Blocked,
    /// A decision this SDK version does not know. Never admitted.
    #[serde(other)]
    Unknown,
}

/// Verification request
#[derive(Debug, Clone, Serialize)]
pub struct VerificationRequest {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<VerificationType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<RequestOptions>,
}

/// Request options
#[derive(Debug, Clone, Serialize, Default)]
pub struct RequestOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_proof: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_attestation: Option<bool>,
}

/// A verification answer: the server's DiagnosticResult envelope.
#[derive(Debug, Clone, Deserialize)]
#[serde(from = "WireResponse")]
pub struct VerificationResponse {
    /// One of the known statuses, or `Unknown`. Gate on
    /// [`VerificationResponse::is_admitted`], not on the status.
    pub status: VerificationStatus,
    /// The server's status text exactly as sent, such as `SAT` or
    /// `NOT_MATH_QUERY` where `status` is `Unknown`. Never used for admission.
    pub raw_status: String,
    /// Present on endpoints that make an admission decision. Missing means
    /// not admitted.
    pub admission: Option<Admission>,
    /// Set only when `status` is VERIFIED.
    pub proof_ref: Option<String>,
    pub agent_message: Option<String>,
    pub is_authoritative: Option<bool>,
    pub constraint_id: Option<String>,
    pub developer_fields: Option<HashMap<String, serde_json::Value>>,
    /// Endpoint-specific fields, such as `is_valid`, `issues` or `error`.
    pub extra: HashMap<String, serde_json::Value>,
}

/// A verification answer as it arrives. `status` is required and must be a
/// string; `VerificationResponse` keeps it as `raw_status` and parses it.
#[derive(Deserialize)]
struct WireResponse {
    status: String,
    #[serde(default)]
    admission: Option<Admission>,
    #[serde(default)]
    proof_ref: Option<String>,
    #[serde(default)]
    agent_message: Option<String>,
    #[serde(default)]
    is_authoritative: Option<bool>,
    #[serde(default)]
    constraint_id: Option<String>,
    #[serde(default)]
    developer_fields: Option<HashMap<String, serde_json::Value>>,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

impl From<WireResponse> for VerificationResponse {
    fn from(wire: WireResponse) -> Self {
        // VerificationStatus maps any value it does not know to Unknown.
        let status = serde_json::from_value(serde_json::Value::String(wire.status.clone()))
            .unwrap_or(VerificationStatus::Unknown);
        Self {
            status,
            raw_status: wire.status,
            admission: wire.admission,
            proof_ref: wire.proof_ref,
            agent_message: wire.agent_message,
            is_authoritative: wire.is_authoritative,
            constraint_id: wire.constraint_id,
            developer_fields: wire.developer_fields,
            extra: wire.extra,
        }
    }
}

impl VerificationResponse {
    /// True only when the server admitted the result: `admission` is ADMIT,
    /// `status` is VERIFIED and a `proof_ref` is present. Anything else,
    /// including a missing or unknown admission, is not admitted.
    pub fn is_admitted(&self) -> bool {
        self.admission == Some(Admission::Admit)
            && self.status == VerificationStatus::Verified
            && self.proof_ref.as_deref().is_some_and(|r| !r.is_empty())
    }
}

/// Batch item
#[derive(Debug, Clone, Serialize)]
pub struct BatchItem {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<VerificationType>,
}

/// Batch job and its items.
#[derive(Debug, Clone, Deserialize)]
pub struct BatchResponse {
    pub job_id: String,
    /// Job state, such as `completed` or `processing`.
    pub status: String,
    #[serde(default)]
    pub progress_percent: Option<f64>,
    #[serde(default)]
    pub total_items: Option<u32>,
    #[serde(default)]
    pub completed_items: Option<u32>,
    #[serde(default)]
    pub failed_items: Option<u32>,
    #[serde(default)]
    pub items: Vec<BatchResult>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// One item of a batch job.
#[derive(Debug, Clone, Deserialize)]
pub struct BatchResult {
    pub id: String,
    /// Item state, such as `completed` or `failed`.
    pub status: String,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default, rename = "type")]
    pub item_type: Option<String>,
    /// The item's verification answer, once it has one.
    #[serde(default)]
    pub result: Option<VerificationResponse>,
    #[serde(default)]
    pub error: Option<serde_json::Value>,
    #[serde(default)]
    pub latency_ms: Option<f64>,
}

impl BatchResult {
    /// True only when the item has a result that [`VerificationResponse::is_admitted`].
    pub fn is_admitted(&self) -> bool {
        self.result.as_ref().is_some_and(VerificationResponse::is_admitted)
    }
}

// ============================================================================
// Errors
// ============================================================================

/// QWED Error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    
    #[error("API error [{code}]: {message}")]
    Api { code: String, message: String },
    
    #[error("Authentication failed")]
    Auth,
    
    #[error("Rate limit exceeded")]
    RateLimit,
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

// ============================================================================
// Client
// ============================================================================

/// QWED API Client
pub struct QWEDClient {
    api_key: String,
    base_url: String,
    client: Client,
}

impl QWEDClient {
    /// Create a new QWED client
    pub fn new(api_key: impl Into<String>) -> Self {
        Self::with_options(api_key, "http://localhost:8000", Duration::from_secs(30))
    }

    /// Create a client with custom options
    pub fn with_options(
        api_key: impl Into<String>,
        base_url: impl Into<String>,
        timeout: Duration,
    ) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client: Client::builder()
                .timeout(timeout)
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Check API health
    pub async fn health(&self) -> Result<HashMap<String, serde_json::Value>, Error> {
        self.get("/health").await
    }

    /// Verify a natural language query
    pub async fn verify(&self, query: &str) -> Result<VerificationResponse, Error> {
        let req = VerificationRequest {
            query: query.to_string(),
            r#type: Some(VerificationType::NaturalLanguage),
            params: None,
            options: None,
        };
        self.post("/verify/natural_language", &req).await
    }

    /// Verify a math expression
    pub async fn verify_math(&self, expression: &str) -> Result<VerificationResponse, Error> {
        let mut body = HashMap::new();
        body.insert("expression", expression);
        self.post("/verify/math", &body).await
    }

    /// Verify a QWED-Logic expression
    pub async fn verify_logic(&self, query: &str) -> Result<VerificationResponse, Error> {
        let mut body = HashMap::new();
        body.insert("query", query);
        self.post("/verify/logic", &body).await
    }

    /// Verify code for security vulnerabilities
    pub async fn verify_code(&self, code: &str, language: &str) -> Result<VerificationResponse, Error> {
        let mut body = HashMap::new();
        body.insert("code", code);
        body.insert("language", language);
        self.post("/verify/code", &body).await
    }

    /// Verify a factual claim
    pub async fn verify_fact(&self, claim: &str, context: &str) -> Result<VerificationResponse, Error> {
        let mut body = HashMap::new();
        body.insert("claim", claim);
        body.insert("context", context);
        self.post("/verify/fact", &body).await
    }

    /// Verify a SQL query
    pub async fn verify_sql(&self, query: &str, schema: &str, dialect: &str) -> Result<VerificationResponse, Error> {
        let mut body = HashMap::new();
        body.insert("query", query);
        body.insert("schema_ddl", schema);
        body.insert("dialect", dialect);
        self.post("/verify/sql", &body).await
    }

    /// Batch verification
    pub async fn verify_batch(&self, items: Vec<BatchItem>) -> Result<BatchResponse, Error> {
        let mut body = HashMap::new();
        body.insert("items", items);
        self.post("/verify/batch", &body).await
    }

    // HTTP helpers
    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, Error> {
        let response = self.client
            .get(format!("{}{}", self.base_url, path))
            .header("X-API-Key", &self.api_key)
            .send()
            .await?;

        self.handle_response(response).await
    }

    async fn post<T: for<'de> Deserialize<'de>, B: Serialize>(&self, path: &str, body: &B) -> Result<T, Error> {
        let response = self.client
            .post(format!("{}{}", self.base_url, path))
            .header("X-API-Key", &self.api_key)
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await?;

        self.handle_response(response).await
    }

    async fn handle_response<T: for<'de> Deserialize<'de>>(&self, response: reqwest::Response) -> Result<T, Error> {
        let status = response.status();
        
        if status == 401 {
            return Err(Error::Auth);
        }
        
        if status == 429 {
            return Err(Error::RateLimit);
        }
        
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(Error::Api {
                code: format!("HTTP-{}", status.as_u16()),
                message: text,
            });
        }

        // Read the body first so a shape mismatch surfaces as
        // Error::Serialization rather than as an HTTP error.
        let text = response.text().await?;
        Ok(serde_json::from_str(&text)?)
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Whether the server admitted the result. Same as
/// [`VerificationResponse::is_admitted`].
#[deprecated(since = "7.3.1", note = "use VerificationResponse::is_admitted; a `verified` field is not an admission decision")]
pub fn is_verified(response: &VerificationResponse) -> bool {
    response.is_admitted()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_type_serialization() {
        let t = VerificationType::Math;
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"math\"");
    }

    #[test]
    fn test_verification_status_deserialization() {
        let json = "\"VERIFIED\"";
        let status: VerificationStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status, VerificationStatus::Verified);
    }

    #[test]
    fn test_every_server_status_parses() {
        for (raw, expected) in [
            ("\"VERIFIED\"", VerificationStatus::Verified),
            ("\"UNVERIFIABLE\"", VerificationStatus::Unverifiable),
            ("\"BLOCKED\"", VerificationStatus::Blocked),
            ("\"SOMETHING_NEW\"", VerificationStatus::Unknown),
        ] {
            let status: VerificationStatus = serde_json::from_str(raw).unwrap();
            assert_eq!(status, expected, "{raw}");
        }
    }

    fn response(json: &str) -> VerificationResponse {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn test_admission_needs_admit_verified_and_proof_ref() {
        let admitted = r#"{"status":"VERIFIED","admission":"ADMIT","proof_ref":"sha256:ab"}"#;
        assert!(response(admitted).is_admitted());

        for json in [
            // Proven false, or unsafe: VERIFIED but blocked.
            r#"{"status":"VERIFIED","admission":"BLOCKED","proof_ref":"sha256:ab"}"#,
            // No admission decision at all (logic, fact).
            r#"{"status":"VERIFIED","proof_ref":"sha256:ab"}"#,
            // An admission the SDK does not know.
            r#"{"status":"VERIFIED","admission":"DENY","proof_ref":"sha256:ab"}"#,
            // ADMIT without the proof VERIFIED requires.
            r#"{"status":"VERIFIED","admission":"ADMIT"}"#,
            r#"{"status":"VERIFIED","admission":"ADMIT","proof_ref":""}"#,
            r#"{"status":"VERIFIED","admission":"ADMIT","proof_ref":null}"#,
            // ADMIT with a status that is not VERIFIED.
            r#"{"status":"UNVERIFIABLE","admission":"ADMIT","proof_ref":"sha256:ab"}"#,
            r#"{"status":"SOMETHING_NEW","admission":"ADMIT","proof_ref":"sha256:ab"}"#,
        ] {
            assert!(!response(json).is_admitted(), "{json}");
        }
    }

    #[test]
    fn test_a_response_without_status_does_not_parse() {
        assert!(serde_json::from_str::<VerificationResponse>(r#"{"admission":"ADMIT"}"#).is_err());
        assert!(serde_json::from_str::<VerificationResponse>(r#"{"status":null}"#).is_err());
        assert!(serde_json::from_str::<VerificationResponse>(r#"{"status":1}"#).is_err());
    }

    #[test]
    fn test_raw_status_keeps_the_servers_text() {
        // A batch logic item can answer with a solver status, not an envelope one.
        let sat = response(r#"{"status":"SAT","admission":"ADMIT","proof_ref":"sha256:ab","model":{"x":6}}"#);
        assert_eq!(sat.status, VerificationStatus::Unknown);
        assert_eq!(sat.raw_status, "SAT");
        assert!(!sat.is_admitted());
        assert!(!sat.extra.contains_key("status"));
        assert_eq!(sat.extra["model"]["x"], 6);

        for (json, status, raw) in [
            (r#"{"status":"VERIFIED"}"#, VerificationStatus::Verified, "VERIFIED"),
            (r#"{"status":"UNVERIFIABLE"}"#, VerificationStatus::Unverifiable, "UNVERIFIABLE"),
            (r#"{"status":"BLOCKED"}"#, VerificationStatus::Blocked, "BLOCKED"),
            (r#"{"status":"verified"}"#, VerificationStatus::Unknown, "verified"),
            (r#"{"status":"NOT_MATH_QUERY"}"#, VerificationStatus::Unknown, "NOT_MATH_QUERY"),
        ] {
            let r = response(json);
            assert_eq!(r.status, status, "{json}");
            assert_eq!(r.raw_status, raw, "{json}");
        }
    }

    #[test]
    fn test_envelope_fields_still_parse_through_the_wire_type() {
        let r = response(
            r#"{"status":"VERIFIED","admission":"ADMIT","proof_ref":"sha256:ab","agent_message":"ok",
                "is_authoritative":true,"constraint_id":"c","developer_fields":{"is_valid":true},"is_valid":true}"#,
        );
        assert!(r.is_admitted());
        assert_eq!(r.agent_message.as_deref(), Some("ok"));
        assert_eq!(r.is_authoritative, Some(true));
        assert_eq!(r.constraint_id.as_deref(), Some("c"));
        assert_eq!(r.developer_fields.unwrap()["is_valid"], true);
        assert_eq!(r.extra["is_valid"], true);
        for key in ["status", "admission", "proof_ref", "agent_message", "developer_fields"] {
            assert!(!r.extra.contains_key(key), "{key} leaked into extra");
        }
        // A field of the wrong type is still an error.
        assert!(serde_json::from_str::<VerificationResponse>(r#"{"status":"VERIFIED","proof_ref":{"a":1}}"#).is_err());
    }

    #[test]
    #[allow(deprecated)]
    fn test_is_verified_follows_admission() {
        let blocked = response(r#"{"status":"VERIFIED","admission":"BLOCKED","proof_ref":"sha256:ab"}"#);
        assert!(!is_verified(&blocked));
    }
}
