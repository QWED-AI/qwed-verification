//! Verify a QWED attestation (#319).
//!
//! A VERIFIED answer from a QWED server carries `attestation`: an ES256 JWT
//! the server signed after checking the verdict. Verifying it shows that
//! server issued a VERIFIED verdict for this answer's `proof_ref` (and, when
//! you pass it, for this statement). It covers only what the token signs: the
//! status, `proof_ref`, statement hash and, on a route that decides one, the
//! admission; not other fields of the response such as `agent_message`. What
//! is checked:
//!
//! - the signature, with the key the token header's `kid` names in the
//!   server's JWKS (`GET /.well-known/jwks.json`);
//! - the issuer, and that the token has not expired (nor is used before any
//!   `nbf` it carries);
//! - that it attests a VERIFIED result;
//! - that its `proof_hash` is the answer's `proof_ref`, so it is this
//!   answer's token;
//! - optionally, that its `query_hash` is the SHA-256 of the statement the
//!   verdict covers;
//! - on a route that decides an admission, the token signs it too
//!   (`qwed.admission`, #321): the client checks it is the answer's
//!   `admission`, so the server's ADMIT or BLOCKED is verified as well.
//!
//! A token says the server reached the verdict and, where it signs one, the
//! admission; act on the admission ([`VerificationResponse::is_admitted`]).
//! Fetching
//! the JWKS from the server you asked trusts that server's TLS; to verify
//! offline or against a pinned key, call [`verify_attestation`] with the JWKS
//! you hold.

use crate::{Admission, QWEDClient, VerificationResponse};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The issuer a QWED server signs as.
pub const DEFAULT_ISSUER: &str = "did:qwed:node:local";
/// Where a QWED server publishes its attestation keys.
pub const JWKS_PATH: &str = "/.well-known/jwks.json";
const TOKEN_TYPE: &str = "qwed-attestation+jwt";

/// How long a fetched JWKS is reused, as the server's Cache-Control says.
const JWKS_MAX_AGE: Duration = Duration::from_secs(300);
/// The least time since the last attempt to fetch the JWKS before another:
/// after a token none of the cached keys verifies (a key rotation or a
/// restart with a new ephemeral key is picked up within this, but a stream of
/// forged tokens cannot turn each one into a request), and after a failed
/// fetch, whose failure every caller gets meanwhile instead of a request each.
const JWKS_MIN_REFRESH: Duration = Duration::from_secs(30);

/// Why an attestation was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AttestationError {
    /// The attestation does not verify, or does not attest this answer.
    #[error("attestation rejected: {0}")]
    Rejected(String),
    /// No key in the JWKS verifies the token, so fetching the JWKS again may
    /// help: the key rotated, or the server restarted with a new ephemeral
    /// key under the same kid.
    #[error("attestation rejected: no key in the JWKS verifies it: {0}")]
    KeyMismatch(String),
    /// The server's keys could not be fetched, so nothing can be verified.
    /// The client asks again at most once every 30 seconds.
    #[error("attestation keys unavailable: {0}")]
    KeysUnavailable(String),
}

fn rejected(reason: &str) -> AttestationError {
    AttestationError::Rejected(reason.to_string())
}

fn key_mismatch(reason: &str) -> AttestationError {
    AttestationError::KeyMismatch(reason.to_string())
}

/// One public key of a JWKS. Read one from JSON; the members are those a
/// QWED server publishes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Jwk {
    #[serde(default)]
    pub kty: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default, rename = "use")]
    pub key_use: Option<String>,
}

/// A set of public keys, as a QWED server publishes at [`JWKS_PATH`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwks {
    #[serde(default)]
    pub keys: Vec<Jwk>,
}

/// The verdict a token attests.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[non_exhaustive]
pub struct AttestedResult {
    pub status: String,
    #[serde(default)]
    pub verified: Option<bool>,
    #[serde(default)]
    pub engine: Option<String>,
    #[serde(default)]
    pub confidence: Option<f64>,
}

/// The token's `qwed` claims.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[non_exhaustive]
pub struct QwedClaims {
    #[serde(default)]
    pub version: Option<String>,
    pub result: AttestedResult,
    #[serde(default)]
    pub query_hash: Option<String>,
    pub proof_hash: String,
    /// The server's admission, `ADMIT` or `BLOCKED`, on a route that decides
    /// one (#321); `None` otherwise.
    #[serde(default)]
    pub admission: Option<String>,
}

/// A verified token's claims. Times are Unix seconds.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[non_exhaustive]
pub struct AttestationClaims {
    pub iss: String,
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(default)]
    pub nbf: Option<i64>,
    pub jti: String,
    pub qwed: QwedClaims,
}

/// How to verify. The default checks [`DEFAULT_ISSUER`] with no leeway and
/// no statement.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct AttestationOptions {
    /// When set, the statement the verdict covers: the query you sent (for
    /// natural language, the translated expression the server reports).
    pub query: Option<String>,
    /// Defaults to [`DEFAULT_ISSUER`].
    pub issuer: Option<String>,
    /// Clock skew allowed on expiry and `nbf`.
    pub leeway: Duration,
    /// The current time (tests); the system clock when `None`.
    pub now: Option<SystemTime>,
    /// When set, the admission the token must sign: the answer's `admission`
    /// (#321). See [`check_admission`].
    pub admission: Option<String>,
}

impl AttestationOptions {
    /// The default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check that the verdict covers `query`.
    pub fn query(mut self, query: impl Into<String>) -> Self {
        self.query = Some(query.into());
        self
    }

    /// Check the token was issued by `issuer`.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Allow `leeway` of clock skew on expiry and `nbf`.
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    /// Verify as at `now` instead of the system clock.
    pub fn now(mut self, now: SystemTime) -> Self {
        self.now = Some(now);
        self
    }

    /// Check the token signs `admission`, the answer's (#321).
    pub fn admission(mut self, admission: impl Into<String>) -> Self {
        self.admission = Some(admission.into());
        self
    }
}

/// An error unless the verified `claims` sign `admission`: the answer's
/// `admission` (#321), or `None` for an answer that carries none, whose token
/// must then sign none.
pub fn check_admission(
    claims: &AttestationClaims,
    admission: Option<&str>,
) -> Result<(), AttestationError> {
    if claims.qwed.admission.as_deref() != admission {
        return Err(rejected(
            "attestation is for another admission (admission differs)",
        ));
    }
    Ok(())
}

/// The `query_hash` a token carries for `statement`.
pub fn statement_hash(statement: &str) -> String {
    let digest = Sha256::digest(statement.as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("sha256:{hex}")
}

/// An error unless there is a token and a proof_ref to bind it to; checked
/// before any key is fetched.
fn require_answer(token: &str, proof_ref: &str) -> Result<(), AttestationError> {
    if token.is_empty() {
        return Err(rejected("no attestation"));
    }
    if proof_ref.is_empty() {
        return Err(rejected("no proof_ref to bind the attestation to"));
    }
    Ok(())
}

/// A token segment that must be a JSON object.
fn json_segment(segment: &str) -> Result<Map<String, Value>, AttestationError> {
    let raw = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| rejected("not a JWT"))?;
    match serde_json::from_slice(&raw) {
        Ok(Value::Object(fields)) => Ok(fields),
        _ => Err(rejected("not a JWT")),
    }
}

/// The ECDSA P-256 key `jwk` holds.
fn verifying_key(jwk: &Jwk) -> Result<VerifyingKey, AttestationError> {
    if jwk.kty.as_deref() != Some("EC")
        || jwk.crv.as_deref() != Some("P-256")
        || jwk.alg.as_deref().is_some_and(|alg| alg != "ES256")
    {
        return Err(rejected("JWKS key is not an ES256 P-256 key"));
    }
    let coordinate = |value: &Option<String>| {
        value
            .as_deref()
            .and_then(|text| URL_SAFE_NO_PAD.decode(text).ok())
            .filter(|bytes| bytes.len() == 32)
    };
    let (Some(x), Some(y)) = (coordinate(&jwk.x), coordinate(&jwk.y)) else {
        return Err(rejected("JWKS key is unusable"));
    };
    let mut point = vec![4u8];
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    // Refuses a point that is not on the curve.
    VerifyingKey::from_sec1_bytes(&point).map_err(|_| rejected("JWKS key is unusable"))
}

const NANOS: i128 = 1_000_000_000;

/// `time` in nanoseconds since the Unix epoch.
fn unix_nanos(time: SystemTime) -> i128 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(since) => since.as_nanos() as i128,
        Err(before) => -(before.duration().as_nanos() as i128),
    }
}

/// Verify `token` as the attestation of the answer whose `proof_ref` is
/// `proof_ref`, against `jwks`, and return its claims.
/// [`AttestationError::KeyMismatch`] says fetching the JWKS again may help.
pub fn verify_attestation(
    token: &str,
    jwks: &Jwks,
    proof_ref: &str,
    options: &AttestationOptions,
) -> Result<AttestationClaims, AttestationError> {
    require_answer(token, proof_ref)?;
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(rejected("not a JWT"));
    }
    let header = json_segment(parts[0])?;
    // Only ES256: a token that names another algorithm, including "none" or
    // an HMAC one, is refused before any key is used.
    if header.get("alg").and_then(Value::as_str) != Some("ES256") {
        return Err(rejected("not signed with ES256"));
    }
    if header.get("typ").and_then(Value::as_str) != Some(TOKEN_TYPE) {
        return Err(rejected("token is not a QWED attestation"));
    }
    let kid = match header.get("kid").and_then(Value::as_str) {
        Some(kid) if !kid.is_empty() => kid,
        _ => return Err(rejected("token header names no key (kid)")),
    };
    let jwk = jwks
        .keys
        .iter()
        .find(|jwk| jwk.kid.as_deref() == Some(kid))
        .ok_or_else(|| key_mismatch("no JWKS key matches the token's kid"))?;
    let key = verifying_key(jwk)?;

    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| rejected("not a JWT"))?;
    // JWS ES256 is the raw r || s pair, 64 bytes.
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let valid = signature.len() == 64
        && Signature::from_slice(&signature)
            .is_ok_and(|signature| key.verify(signing_input.as_bytes(), &signature).is_ok());
    if !valid {
        return Err(key_mismatch("signature does not verify"));
    }

    // From here on the header and claims are verified.
    let payload = json_segment(parts[1])?;
    for name in ["iss", "sub", "iat", "exp", "jti"] {
        if payload.get(name).is_none_or(Value::is_null) {
            return Err(rejected(&format!("claims do not verify (no {name})")));
        }
    }
    let claims: AttestationClaims = serde_json::from_value(Value::Object(payload))
        .map_err(|_| rejected("claims do not verify"))?;
    let issuer = options.issuer.as_deref().unwrap_or(DEFAULT_ISSUER);
    if claims.iss != issuer {
        return Err(rejected("claims do not verify (issuer differs)"));
    }
    // As RFC 7519, PyJWT and the other SDKs: expired once now reaches exp,
    // and not valid while now is before an nbf the token carries. The leeway
    // counts in full, a fraction of a second included.
    let now = unix_nanos(options.now.unwrap_or_else(SystemTime::now));
    let leeway = options.leeway.as_nanos() as i128;
    if now >= i128::from(claims.exp) * NANOS + leeway {
        return Err(rejected("attestation has expired"));
    }
    if claims
        .nbf
        .is_some_and(|nbf| now + leeway < i128::from(nbf) * NANOS)
    {
        return Err(rejected("attestation is not yet valid (nbf)"));
    }
    if claims.qwed.result.status != "VERIFIED" {
        return Err(rejected("attestation does not attest a VERIFIED result"));
    }
    if claims.qwed.proof_hash != proof_ref {
        return Err(rejected(
            "attestation is for another answer (proof_ref differs)",
        ));
    }
    if let Some(query) = &options.query {
        if claims.qwed.query_hash.as_deref() != Some(statement_hash(query).as_str()) {
            return Err(rejected(
                "attestation is for another statement (query differs)",
            ));
        }
    }
    if let Some(admission) = &options.admission {
        check_admission(&claims, Some(admission))?;
    }
    Ok(claims)
}

// ============================================================================
// The client's keys
// ============================================================================

/// The server's keys as the client last fetched them.
#[derive(Debug, Default)]
pub(crate) struct JwksCache {
    jwks: Option<Arc<Jwks>>,
    fetched_at: Option<Instant>,
    /// When the last fetch the server answered ended.
    attempted_at: Option<Instant>,
    error: Option<AttestationError>,
}

/// The client's keys: the state, held only briefly, and one fetch at a
/// time. A caller waiting for the fetch stops when its future is dropped.
#[derive(Debug, Default)]
pub(crate) struct KeyCache {
    state: std::sync::Mutex<JwksCache>,
    fetch: tokio::sync::Mutex<()>,
}

fn within(at: Option<Instant>, limit: Duration) -> bool {
    at.is_some_and(|at| at.elapsed() < limit)
}

impl JwksCache {
    fn fresh(&self) -> Option<Arc<Jwks>> {
        self.jwks
            .clone()
            .filter(|_| within(self.fetched_at, JWKS_MAX_AGE))
    }

    /// Within [`JWKS_MIN_REFRESH`] of a failed fetch, its failure.
    fn recent_failure(&self) -> Option<AttestationError> {
        self.error
            .clone()
            .filter(|_| within(self.attempted_at, JWKS_MIN_REFRESH))
    }
}

impl KeyCache {
    fn state(&self) -> std::sync::MutexGuard<'_, JwksCache> {
        // The state is only ever assigned whole fields, so a panic elsewhere
        // cannot leave it half written.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl QWEDClient {
    async fn request_jwks(&self) -> Result<Jwks, AttestationError> {
        fn unavailable(error: impl std::fmt::Display) -> AttestationError {
            AttestationError::KeysUnavailable(error.to_string())
        }
        let response = self
            .client
            .get(format!("{}{}", self.base_url, JWKS_PATH))
            .send()
            .await
            .map_err(unavailable)?;
        let status = response.status();
        if !status.is_success() {
            return Err(unavailable(format!("HTTP {}", status.as_u16())));
        }
        let text = response.text().await.map_err(unavailable)?;
        serde_json::from_str(&text).map_err(unavailable)
    }

    /// Fetch the keys; the caller holds the fetch lock. The attempt is
    /// recorded when the fetch ends, so a slow failure is still shared for
    /// the full 30 seconds, and a caller dropped mid-fetch records nothing.
    async fn fetch_jwks(&self) -> Result<Arc<Jwks>, AttestationError> {
        let fetched = self.request_jwks().await.map(Arc::new);
        let mut cache = self.jwks.state();
        cache.attempted_at = Some(Instant::now());
        match &fetched {
            Ok(jwks) => {
                cache.jwks = Some(Arc::clone(jwks));
                cache.fetched_at = cache.attempted_at;
                cache.error = None;
            }
            Err(error) => cache.error = Some(error.clone()),
        }
        fetched
    }

    /// The keys the client holds, fetched when they are missing or past their
    /// age (or when `refresh`). Fresh keys are returned without waiting for a
    /// fetch in flight.
    async fn cached_jwks(&self, refresh: bool) -> Result<Arc<Jwks>, AttestationError> {
        if !refresh {
            if let Some(jwks) = self.jwks.state().fresh() {
                return Ok(jwks);
            }
        }
        let _fetching = self.jwks.fetch.lock().await;
        if !refresh {
            // Callers that waited get what the fetch before them got.
            let cache = self.jwks.state();
            if let Some(jwks) = cache.fresh() {
                return Ok(jwks);
            }
            if let Some(error) = cache.recent_failure() {
                return Err(error);
            }
        }
        self.fetch_jwks().await
    }

    /// The server's attestation keys (`GET /.well-known/jwks.json`, no API
    /// key), reused for five minutes as the server's Cache-Control says.
    /// Callers that need keys while a fetch is in flight wait for it and
    /// share what it got. A failed fetch's
    /// [`AttestationError::KeysUnavailable`] is returned again for 30
    /// seconds without a request, unless `refresh`. Keys past their age are
    /// not used instead: a key the server has since withdrawn would still
    /// verify.
    pub async fn get_jwks(&self, refresh: bool) -> Result<Jwks, AttestationError> {
        Ok(Jwks::clone(&*self.cached_jwks(refresh).await?))
    }

    /// The keys to try once more after none in `used` verified a token: those
    /// another caller fetched meanwhile, else a fresh fetch if the last one
    /// ended at least 30 seconds ago. Within those 30 seconds, the last
    /// fetch's failure if it failed, else `None`.
    async fn jwks_after_mismatch(
        &self,
        used: &Arc<Jwks>,
    ) -> Result<Option<Arc<Jwks>>, AttestationError> {
        let _fetching = self.jwks.fetch.lock().await;
        {
            let cache = self.jwks.state();
            if let Some(jwks) = cache.jwks.as_ref().filter(|jwks| !Arc::ptr_eq(jwks, used)) {
                return Ok(Some(Arc::clone(jwks)));
            }
            if within(cache.attempted_at, JWKS_MIN_REFRESH) {
                // A refresh that just failed is reported as such, not as a
                // token whose key is missing.
                return cache.error.clone().map_or(Ok(None), Err);
            }
        }
        self.fetch_jwks().await.map(Some)
    }

    /// Verify `response`'s attestation against this server's keys and return
    /// its claims. An error says the token does not verify or is not this
    /// answer's (its `proof_ref`, and the `admission` it carries, which the
    /// token must sign, none if it carries none, #321), or
    /// ([`AttestationError::KeysUnavailable`]) the keys could not be fetched. To verify against keys you pinned, call
    /// [`verify_attestation`] with your JWKS.
    pub async fn verify_attestation(
        &self,
        response: &VerificationResponse,
        options: &AttestationOptions,
    ) -> Result<AttestationClaims, AttestationError> {
        let token = response.attestation.as_deref().unwrap_or_default();
        let proof_ref = response.proof_ref.as_deref().unwrap_or_default();
        // A missing token or proof_ref is refused before any key is fetched.
        require_answer(token, proof_ref)?;
        let jwks = self.cached_jwks(false).await?;
        let claims = match verify_attestation(token, &jwks, proof_ref, options) {
            Err(AttestationError::KeyMismatch(reason)) => {
                // The key may have rotated, or the server restarted with a new
                // key under the same kid, since the JWKS was cached: try the
                // keys once more.
                match self.jwks_after_mismatch(&jwks).await? {
                    Some(newer) => verify_attestation(token, &newer, proof_ref, options),
                    None => Err(AttestationError::KeyMismatch(reason)),
                }
            }
            verified => verified,
        }?;
        // The token signs the server's admission where the route decides one
        // (#321): the answer's admission must be that one.
        let carried = response
            .admission
            .as_ref()
            .map(|admission| match admission {
                Admission::Admit => "ADMIT",
                Admission::Blocked => "BLOCKED",
                Admission::Unknown => "UNKNOWN",
            });
        check_admission(&claims, carried)?;
        Ok(claims)
    }
}

#[cfg(test)]
#[path = "attestation_tests.rs"]
mod tests;
