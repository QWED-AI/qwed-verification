//! #319: the Rust SDK verifies attestations.
//!
//! Tokens are signed at test time with keys derived here, shaped as the
//! server issues them (ES256, typ qwed-attestation+jwt, kid naming the key);
//! none is stored in the repository.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use qwed::{
    check_admission, statement_hash, verify_attestation, AttestationError, AttestationOptions,
    Jwks, DEFAULT_ISSUER,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PROOF: &str = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const QUERY: &str = "2+2=4";
/// A statement the tokens here do not attest.
const OTHER_QUERY: &str = "2+2=5";
const KID: &str = "did:qwed:node:local#test-key";

/// A signing key derived from `label`, and the JWKS that holds it under `kid`.
fn key(label: &str, kid: &str) -> (SigningKey, Jwks) {
    let signing = SigningKey::from_slice(&Sha256::digest(label.as_bytes())).unwrap();
    let point = signing.verifying_key().to_sec1_point(false);
    let jwks = serde_json::from_value(json!({"keys": [{
        "kty": "EC", "crv": "P-256", "kid": kid, "alg": "ES256", "use": "sig",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    }]}))
    .unwrap();
    (signing, jwks)
}

fn b64_json(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap())
}

fn header() -> Value {
    json!({"alg": "ES256", "typ": "qwed-attestation+jwt", "kid": KID})
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn claims() -> Value {
    let now = now();
    json!({
        "iss": "did:qwed:node:local",
        "sub": statement_hash(QUERY),
        "iat": now,
        "exp": now + 3600,
        "jti": "att_test",
        "qwed": {
            "version": "1.0",
            "result": {"status": "VERIFIED", "verified": true, "engine": "math", "confidence": 1},
            "query_hash": statement_hash(QUERY),
            "proof_hash": PROOF,
        },
    })
}

fn with(mut value: Value, name: &str, field: Value) -> Value {
    if field.is_null() {
        value.as_object_mut().unwrap().remove(name);
    } else {
        value[name] = field;
    }
    value
}

/// `header.claims` signed with `key`. `high_s` gives the other valid
/// signature, (r, n - s), which the server's own library may produce.
fn sign(key: &SigningKey, header: &Value, claims: &Value, high_s: bool) -> String {
    let input = format!("{}.{}", b64_json(header), b64_json(claims));
    let signature: Signature = key.sign(input.as_bytes());
    let signature = if high_s {
        let (r, s) = signature.split_scalars();
        Signature::from_scalars(r, -s).unwrap()
    } else {
        signature
    };
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

fn rejected(
    result: Result<qwed::AttestationClaims, AttestationError>,
    fragment: &str,
) -> AttestationError {
    let error = result.expect_err("verified");
    assert!(
        error.to_string().contains(fragment),
        "{error} does not mention {fragment:?}"
    );
    error
}

#[test]
fn a_genuine_attestation_verifies_with_either_signature() {
    let (signing, jwks) = key("genuine", KID);
    for high_s in [false, true] {
        let token = sign(&signing, &header(), &claims(), high_s);

        let verified = verify_attestation(
            &token,
            &jwks,
            PROOF,
            &AttestationOptions::new().query(QUERY),
        )
        .unwrap();

        assert_eq!(verified.qwed.proof_hash, PROOF);
        assert_eq!(verified.qwed.result.status, "VERIFIED");
        assert_eq!(verified.iss, DEFAULT_ISSUER);
    }
}

#[test]
fn the_statement_hash_is_the_servers_query_hash() {
    // sha256("2+2=4"), as Python's hashlib and the server's query_hash give it.
    assert_eq!(
        statement_hash(QUERY),
        "sha256:ccb87154d21d3d96a3835bcdba1aa5f3481a06d34a84f437a7ba312bef8c8b43"
    );
}

#[test]
fn refusals() {
    let (signing, jwks) = key("genuine", KID);
    let (forger, _) = key("forger", KID);
    let now = now();
    let genuine = sign(&signing, &header(), &claims(), false);
    let parts: Vec<&str> = genuine.split('.').collect();
    let opts = AttestationOptions::new();
    let other_proof = format!("sha256:{}", "f".repeat(64));
    let tampered = format!(
        "{}.{}.{}",
        parts[0],
        b64_json(&with(claims(), "jti", json!("att_other"))),
        parts[2]
    );
    let header_with = |alg: &str, typ: &str, kid: Option<&str>| {
        let mut h = json!({"alg": alg, "typ": typ});
        if let Some(kid) = kid {
            h["kid"] = json!(kid);
        }
        h
    };

    let cases: Vec<(&str, String, &str, AttestationOptions, &str, bool)> = vec![
        // (name, token, proof_ref, options, fragment, is a key mismatch)
        (
            "another answer",
            genuine.clone(),
            &other_proof,
            opts.clone(),
            "another answer",
            false,
        ),
        (
            "another statement",
            genuine.clone(),
            PROOF,
            opts.clone().query(OTHER_QUERY),
            "another statement",
            false,
        ),
        (
            "not VERIFIED",
            sign(
                &signing,
                &header(),
                &with(
                    claims(),
                    "qwed",
                    json!({"result": {"status": "BLOCKED"}, "proof_hash": PROOF}),
                ),
                false,
            ),
            PROOF,
            opts.clone(),
            "VERIFIED",
            false,
        ),
        (
            "expired",
            sign(
                &signing,
                &header(),
                &with(claims(), "exp", json!(now - 30)),
                false,
            ),
            PROOF,
            opts.clone(),
            "expired",
            false,
        ),
        (
            "another issuer",
            sign(
                &signing,
                &header(),
                &with(claims(), "iss", json!("did:example:other")),
                false,
            ),
            PROOF,
            opts.clone(),
            "issuer",
            false,
        ),
        (
            "a missing claim",
            sign(
                &signing,
                &header(),
                &with(claims(), "jti", Value::Null),
                false,
            ),
            PROOF,
            opts.clone(),
            "jti",
            false,
        ),
        (
            "before its nbf",
            sign(
                &signing,
                &header(),
                &with(claims(), "nbf", json!(now + 30)),
                false,
            ),
            PROOF,
            opts.clone(),
            "not yet valid",
            false,
        ),
        (
            "an nbf that is not a number",
            sign(
                &signing,
                &header(),
                &with(claims(), "nbf", json!("soon")),
                false,
            ),
            PROOF,
            opts.clone(),
            "claims",
            false,
        ),
        (
            "another key under the right kid",
            sign(&forger, &header(), &claims(), false),
            PROOF,
            opts.clone(),
            "signature",
            true,
        ),
        (
            "a payload changed after signing",
            tampered,
            PROOF,
            opts.clone(),
            "signature",
            true,
        ),
        (
            "a kid the JWKS does not hold",
            sign(
                &signing,
                &header_with("ES256", "qwed-attestation+jwt", Some("other")),
                &claims(),
                false,
            ),
            PROOF,
            opts.clone(),
            "kid",
            true,
        ),
        (
            "no kid",
            sign(
                &signing,
                &header_with("ES256", "qwed-attestation+jwt", None),
                &claims(),
                false,
            ),
            PROOF,
            opts.clone(),
            "no key",
            false,
        ),
        (
            "not a QWED attestation",
            sign(
                &signing,
                &header_with("ES256", "JWT", Some(KID)),
                &claims(),
                false,
            ),
            PROOF,
            opts.clone(),
            "not a QWED attestation",
            false,
        ),
        (
            "alg none",
            format!(
                "{}.{}.x",
                b64_json(&header_with("none", "qwed-attestation+jwt", Some(KID))),
                parts[1]
            ),
            PROOF,
            opts.clone(),
            "ES256",
            false,
        ),
        (
            "alg HS256",
            format!(
                "{}.{}.{}",
                b64_json(&header_with("HS256", "qwed-attestation+jwt", Some(KID))),
                parts[1],
                parts[2]
            ),
            PROOF,
            opts.clone(),
            "ES256",
            false,
        ),
        (
            "no token",
            String::new(),
            PROOF,
            opts.clone(),
            "no attestation",
            false,
        ),
        (
            "no proof_ref",
            genuine.clone(),
            "",
            opts.clone(),
            "no proof_ref",
            false,
        ),
        (
            "not a JWT",
            "not.a.jwt".into(),
            PROOF,
            opts.clone(),
            "not a JWT",
            false,
        ),
        (
            "two segments",
            "a.b".into(),
            PROOF,
            opts.clone(),
            "not a JWT",
            false,
        ),
        (
            "not base64",
            "%%.%%.%%".into(),
            PROOF,
            opts.clone(),
            "not a JWT",
            false,
        ),
        (
            "a header that is not an object",
            format!("W10.{}.{}", parts[1], parts[2]),
            PROOF,
            opts.clone(),
            "not a JWT",
            false,
        ),
        (
            "a signature that is no base64",
            format!("{}.{}.A", parts[0], parts[1]),
            PROOF,
            opts.clone(),
            "not a JWT",
            false,
        ),
        (
            "a signature of the wrong length",
            format!(
                "{}.{}.{}",
                parts[0],
                parts[1],
                URL_SAFE_NO_PAD.encode(b"short")
            ),
            PROOF,
            opts.clone(),
            "signature",
            true,
        ),
    ];
    for (name, token, proof_ref, options, fragment, mismatch) in cases {
        let error = verify_attestation(&token, &jwks, proof_ref, &options).expect_err(name);
        assert!(
            error.to_string().contains(fragment),
            "{name}: {error} does not mention {fragment:?}"
        );
        assert_eq!(
            matches!(error, AttestationError::KeyMismatch(_)),
            mismatch,
            "{name}: {error:?}"
        );
    }
}

#[test]
fn expiry_is_reached_at_exp_and_leeway_allows_skew() {
    let (signing, jwks) = key("genuine", KID);
    let exp = now() + 100;
    let token = sign(
        &signing,
        &header(),
        &with(claims(), "exp", json!(exp)),
        false,
    );
    let at = |seconds: i64| UNIX_EPOCH + Duration::from_secs(seconds as u64);

    // Expired from the second exp names, as PyJWT.
    assert!(verify_attestation(
        &token,
        &jwks,
        PROOF,
        &AttestationOptions::new().now(at(exp - 1))
    )
    .is_ok());
    rejected(
        verify_attestation(
            &token,
            &jwks,
            PROOF,
            &AttestationOptions::new().now(at(exp)),
        ),
        "expired",
    );
    let skewed = AttestationOptions::new()
        .now(at(exp + 30))
        .leeway(Duration::from_secs(60));
    assert!(verify_attestation(&token, &jwks, PROOF, &skewed).is_ok());

    let early = sign(
        &signing,
        &header(),
        &with(claims(), "nbf", json!(exp - 50)),
        false,
    );
    let skewed = AttestationOptions::new()
        .now(at(exp - 80))
        .leeway(Duration::from_secs(60));
    assert!(verify_attestation(&early, &jwks, PROOF, &skewed).is_ok());
}

#[test]
fn a_sub_second_leeway_counts_in_full() {
    // #513 review: a leeway of 1.5 s was 1 s.
    let (signing, jwks) = key("genuine", KID);
    let exp = now() + 100;
    let token = sign(
        &signing,
        &header(),
        &with(with(claims(), "exp", json!(exp)), "nbf", json!(exp - 50)),
        false,
    );
    let expiry = UNIX_EPOCH + Duration::from_secs(exp as u64);
    let not_before = UNIX_EPOCH + Duration::from_secs((exp - 50) as u64);
    let (late, early) = (
        expiry + Duration::from_millis(1200),
        not_before - Duration::from_millis(1200),
    );
    let within = |at, leeway_ms| {
        AttestationOptions::new()
            .now(at)
            .leeway(Duration::from_millis(leeway_ms))
    };

    assert!(verify_attestation(&token, &jwks, PROOF, &within(late, 1500)).is_ok());
    assert!(verify_attestation(&token, &jwks, PROOF, &within(early, 1500)).is_ok());
    // A microsecond: Windows keeps SystemTime in 100 ns steps.
    let just_before = AttestationOptions::new().now(expiry - Duration::from_micros(1));
    assert!(verify_attestation(&token, &jwks, PROOF, &just_before).is_ok());
    rejected(
        verify_attestation(&token, &jwks, PROOF, &within(late, 1000)),
        "expired",
    );
    rejected(
        verify_attestation(&token, &jwks, PROOF, &within(early, 1000)),
        "not yet valid",
    );
}

#[test]
fn jwks_keys_that_cannot_verify() {
    let (signing, jwks) = key("genuine", KID);
    let token = sign(&signing, &header(), &claims(), false);
    let good = serde_json::to_value(&jwks.keys[0]).unwrap();
    let jwks_of =
        |key: Value| -> Jwks { serde_json::from_value(json!({ "keys": [key] })).unwrap() };

    for (name, keys, fragment) in [
        (
            "P-384",
            jwks_of(with(good.clone(), "crv", json!("P-384"))),
            "ES256 P-256",
        ),
        (
            "RSA",
            jwks_of(json!({"kty": "RSA", "kid": KID})),
            "ES256 P-256",
        ),
        (
            "another alg",
            jwks_of(with(good.clone(), "alg", json!("ES384"))),
            "ES256 P-256",
        ),
        (
            "off the curve",
            jwks_of(with(
                good.clone(),
                "y",
                json!(URL_SAFE_NO_PAD.encode([0u8; 32])),
            )),
            "unusable",
        ),
        (
            "bad coordinates",
            jwks_of(with(good.clone(), "x", json!("not-a-coordinate"))),
            "unusable",
        ),
    ] {
        let error =
            verify_attestation(&token, &keys, PROOF, &AttestationOptions::new()).expect_err(name);
        assert!(error.to_string().contains(fragment), "{name}: {error}");
        assert!(
            matches!(error, AttestationError::Rejected(_)),
            "{name}: {error:?}"
        );
    }
    // An empty JWKS may be out of date.
    let error = verify_attestation(&token, &Jwks::default(), PROOF, &AttestationOptions::new())
        .unwrap_err();
    assert!(
        matches!(error, AttestationError::KeyMismatch(_)),
        "{error:?}"
    );
}

#[test]
fn the_attested_admission_is_returned_and_checked_when_given() {
    // #321: a route that decides an admission signs it as qwed.admission.
    let (signing, jwks) = key("genuine", KID);
    let mut signed = claims();
    signed["qwed"]["admission"] = json!("BLOCKED");
    let token = sign(&signing, &header(), &signed, false);

    for options in [
        AttestationOptions::new(),
        AttestationOptions::new().admission("BLOCKED"),
    ] {
        let verified = verify_attestation(&token, &jwks, PROOF, &options).unwrap();
        assert_eq!(verified.qwed.admission.as_deref(), Some("BLOCKED"));
    }
    let error = verify_attestation(
        &token,
        &jwks,
        PROOF,
        &AttestationOptions::new().admission("ADMIT"),
    )
    .unwrap_err();
    assert!(error.to_string().contains("another admission"), "{error}");

    let verified = verify_attestation(&token, &jwks, PROOF, &AttestationOptions::new()).unwrap();
    assert!(check_admission(&verified, Some("BLOCKED")).is_ok());
    assert!(check_admission(&verified, None).is_err());
    let unsigned = sign(&signing, &header(), &claims(), false);
    let verified = verify_attestation(&unsigned, &jwks, PROOF, &AttestationOptions::new()).unwrap();
    assert!(check_admission(&verified, None).is_ok());
    assert!(check_admission(&verified, Some("ADMIT")).is_err());
}
