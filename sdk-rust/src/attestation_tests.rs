//! The client's key cache (#319): unit tests, since they move the cache's
//! clock. Tokens are signed here at run time; none is stored.

use super::*;
use p256::ecdsa::{signature::Signer, SigningKey};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PROOF: &str = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const KID: &str = "did:qwed:node:local#test-key";

fn key(label: &str, kid: &str) -> (SigningKey, Jwks) {
    let signing = SigningKey::from_slice(&Sha256::digest(label.as_bytes())).unwrap();
    let point = signing.verifying_key().to_sec1_point(false);
    let jwks = serde_json::from_value(json!({"keys": [{
        "kty": "EC", "crv": "P-256", "kid": kid, "alg": "ES256",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    }]}))
    .unwrap();
    (signing, jwks)
}

fn answer(signing: &SigningKey) -> VerificationResponse {
    answer_with(signing, None, None)
}

/// A VERIFIED answer whose token signs `signed` as its admission, carrying
/// `carried` as its own (each none when `None`).
fn answer_with(
    signing: &SigningKey,
    signed: Option<&str>,
    carried: Option<&str>,
) -> VerificationResponse {
    let now = (unix_nanos(SystemTime::now()) / NANOS) as i64;
    let header = json!({"alg": "ES256", "typ": TOKEN_TYPE, "kid": KID});
    let mut claims = json!({
        "iss": DEFAULT_ISSUER, "sub": "s", "iat": now, "exp": now + 3600, "jti": "att_test",
        "qwed": {"result": {"status": "VERIFIED"}, "proof_hash": PROOF},
    });
    if let Some(admission) = signed {
        claims["qwed"]["admission"] = json!(admission);
    }
    let encode = |value: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap());
    let input = format!("{}.{}", encode(&header), encode(&claims));
    let signature: Signature = signing.sign(input.as_bytes());
    let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    let mut response = json!({"status": "VERIFIED", "proof_ref": PROOF, "attestation": token});
    if let Some(admission) = carried {
        response["admission"] = json!(admission);
    }
    serde_json::from_value(response).unwrap()
}

/// A key server on a local port: `respond` gives the n-th request's status
/// and body (n from 1), after `delay`. Returns the base URL and the request
/// count.
async fn key_server(
    delay: Duration,
    respond: impl Fn(usize) -> (u16, String) + Send + Sync + 'static,
) -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let count = Arc::new(AtomicUsize::new(0));
    let (respond, served) = (Arc::new(respond), Arc::clone(&count));
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let (respond, served) = (Arc::clone(&respond), Arc::clone(&served));
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buffer[..n]),
                    }
                }
                assert!(request.starts_with(format!("GET {JWKS_PATH} ").as_bytes()));
                let n = served.fetch_add(1, Ordering::SeqCst) + 1;
                tokio::time::sleep(delay).await;
                let (status, body) = respond(n);
                let reply = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (url, count)
}

fn body(jwks: &Jwks) -> String {
    serde_json::to_string(jwks).unwrap()
}

fn client(url: &str) -> QWEDClient {
    QWEDClient::with_options("k", url, Duration::from_secs(5))
}

/// Move the cache's clock back by `seconds`: what it holds was fetched and
/// attempted that long ago.
fn age(client: &QWEDClient, seconds: u64) {
    let mut cache = client.jwks.state();
    let ago = Instant::now()
        .checked_sub(Duration::from_secs(seconds))
        .unwrap();
    cache.fetched_at = cache.fetched_at.map(|_| ago);
    cache.attempted_at = cache.attempted_at.map(|_| ago);
}

#[tokio::test]
async fn the_client_verifies_and_reuses_the_jwks() {
    let (signing, jwks) = key("genuine", KID);
    let served = body(&jwks);
    let (url, count) = key_server(Duration::ZERO, move |_| (200, served.clone())).await;
    let client = client(&url);
    let response = answer(&signing);

    for _ in 0..2 {
        let claims = client
            .verify_attestation(&response, &AttestationOptions::new())
            .await
            .unwrap();
        assert_eq!(claims.qwed.proof_hash, PROOF);
    }
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(client.get_jwks(false).await.unwrap(), jwks);
}

#[tokio::test]
async fn the_client_refetches_for_a_new_key_but_not_within_30_seconds() {
    // A rotated key (an unknown kid) and a restart with a new ephemeral key
    // under the same kid (a signature the cached key does not verify).
    let (signing, jwks) = key("genuine", KID);
    for stale in [
        key("before", "did:qwed:node:local#old").1,
        key("before", KID).1,
    ] {
        let (stale, fresh) = (body(&stale), body(&jwks));
        let (url, count) = key_server(Duration::ZERO, move |n| {
            (200, if n == 1 { stale.clone() } else { fresh.clone() })
        })
        .await;
        let client = client(&url);
        let response = answer(&signing);
        let options = AttestationOptions::new();

        for _ in 0..2 {
            let error = client
                .verify_attestation(&response, &options)
                .await
                .unwrap_err();
            assert!(
                matches!(error, AttestationError::KeyMismatch(_)),
                "{error:?}"
            );
        }
        assert_eq!(count.load(Ordering::SeqCst), 1, "fetches within 30 s");

        age(&client, 60); // still within the five-minute cache
        assert!(client.verify_attestation(&response, &options).await.is_ok());
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn the_client_tries_keys_another_caller_fetched_meanwhile() {
    // One caller checks the old keys while another refreshes them: it
    // retries with the new keys, without a fetch, although the last fetch
    // was just now.
    let (_, jwks) = key("genuine", KID);
    let (url, count) = key_server(Duration::ZERO, |_| (503, "down".into())).await;
    let client = client(&url);
    let (current, used) = (Arc::new(jwks), Arc::new(key("before", KID).1));
    {
        let mut cache = client.jwks.state();
        cache.jwks = Some(Arc::clone(&current));
        cache.fetched_at = Some(Instant::now());
        cache.attempted_at = Some(Instant::now());
    }

    let newer = client.jwks_after_mismatch(&used).await.unwrap().unwrap();

    assert!(Arc::ptr_eq(&newer, &current));
    assert_eq!(count.load(Ordering::SeqCst), 0);
    assert!(client
        .jwks_after_mismatch(&current)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn a_failed_fetch_is_shared_for_30_seconds() {
    let (signing, jwks) = key("genuine", KID);
    let served = body(&jwks);
    let (url, count) = key_server(Duration::from_millis(50), move |n| {
        if n == 1 {
            (503, "down".into())
        } else {
            (200, served.clone())
        }
    })
    .await;
    let client = client(&url);
    let response = answer(&signing);
    let options = AttestationOptions::new();

    // Callers queued behind the failing fetch, and those after it, get its
    // failure without a request each.
    let (a, b, c, d) = tokio::join!(
        client.verify_attestation(&response, &options),
        client.verify_attestation(&response, &options),
        client.verify_attestation(&response, &options),
        client.verify_attestation(&response, &options),
    );
    for result in [a, b, c, d] {
        let error = result.unwrap_err();
        assert!(
            matches!(&error, AttestationError::KeysUnavailable(m) if m.contains("503")),
            "{error:?}"
        );
    }
    assert_eq!(count.load(Ordering::SeqCst), 1);

    age(&client, 31);
    assert!(client.verify_attestation(&response, &options).await.is_ok());
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_failed_refresh_after_a_key_mismatch_is_keys_unavailable() {
    let (signing, _) = key("genuine", KID);
    let stale = body(&key("before", KID).1);
    let (url, count) = key_server(Duration::ZERO, move |n| {
        if n == 1 {
            (200, stale.clone())
        } else {
            (503, "down".into())
        }
    })
    .await;
    let client = client(&url);
    client.get_jwks(false).await.unwrap();
    age(&client, 60);

    let response = answer(&signing);

    // Then, within the 30 s, the refresh's failure, not a missing key, and
    // no request (#513 review).
    for _ in 0..2 {
        let error = client
            .verify_attestation(&response, &AttestationOptions::new())
            .await
            .unwrap_err();
        assert!(
            matches!(error, AttestationError::KeysUnavailable(_)),
            "{error:?}"
        );
    }
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_slow_failure_is_shared_for_the_full_30_seconds() {
    // #513 review: the 30 s counted from the start of a fetch, so one that
    // took 30 s to fail was already past them. Now they count from its end.
    let (url, _) = key_server(Duration::from_millis(200), |_| (503, "down".into())).await;
    let client = client(&url);
    let began = Instant::now();

    assert!(client.get_jwks(false).await.is_err());

    let ended = client.jwks.state().attempted_at.unwrap();
    assert!(
        ended >= began + Duration::from_millis(200),
        "recorded at the start"
    );
}

#[tokio::test]
async fn a_caller_dropped_mid_fetch_records_nothing() {
    // #513 review: a dropped caller moved the 30 s window on, so the next
    // caller could not fetch a rotated key.
    let (signing, jwks) = key("genuine", KID);
    let served = body(&jwks);
    let (url, count) = key_server(Duration::from_millis(300), move |_| (200, served.clone())).await;
    let client = client(&url);
    {
        let mut cache = client.jwks.state();
        cache.jwks = Some(Arc::new(key("before", KID).1));
        cache.fetched_at = Some(Instant::now());
        cache.attempted_at = Some(Instant::now());
    }
    age(&client, 60);
    let response = answer(&signing);
    let options = AttestationOptions::new();

    let dropped = tokio::time::timeout(
        Duration::from_millis(30),
        client.verify_attestation(&response, &options),
    )
    .await;

    assert!(dropped.is_err(), "the caller was not dropped");
    assert!(!within(client.jwks.state().attempted_at, JWKS_MIN_REFRESH));
    // The cached key is the old one, so this verifies only through a fetch
    // the dropped caller did not hold back.
    assert!(client.verify_attestation(&response, &options).await.is_ok());
    assert!(count.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn fresh_keys_do_not_wait_for_a_fetch_in_flight() {
    // #513 review: a refresh after a key mismatch held up every caller,
    // though the keys they needed were cached and fresh.
    let (_, jwks) = key("genuine", KID);
    let served = body(&jwks);
    let (url, _) = key_server(Duration::from_millis(300), move |_| (200, served.clone())).await;
    let client = client(&url);
    let current = Arc::new(jwks);
    {
        let mut cache = client.jwks.state();
        cache.jwks = Some(Arc::clone(&current));
        cache.fetched_at = Some(Instant::now());
        cache.attempted_at = Instant::now().checked_sub(Duration::from_secs(60));
    }

    let (refreshed, waited) = tokio::join!(client.jwks_after_mismatch(&current), async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let began = Instant::now();
        assert!(client.get_jwks(false).await.is_ok());
        began.elapsed()
    });

    assert!(refreshed.unwrap().is_some());
    assert!(
        waited < Duration::from_millis(200),
        "waited {waited:?} for the refresh"
    );
}

#[tokio::test]
async fn concurrent_callers_share_one_fetch() {
    let (signing, jwks) = key("genuine", KID);
    let served = body(&jwks);
    let (url, count) = key_server(Duration::from_millis(50), move |_| (200, served.clone())).await;
    let client = client(&url);
    let response = answer(&signing);
    let options = AttestationOptions::new();

    let (a, b, c, d) = tokio::join!(
        client.verify_attestation(&response, &options),
        client.verify_attestation(&response, &options),
        client.verify_attestation(&response, &options),
        client.verify_attestation(&response, &options),
    );

    assert!(a.is_ok() && b.is_ok() && c.is_ok() && d.is_ok());
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unreadable_keys_are_unavailable_and_a_refresh_asks_again() {
    let (url, count) = key_server(Duration::ZERO, |_| (200, "not json".into())).await;
    let client = client(&url);

    let error = client.get_jwks(false).await.unwrap_err();
    assert!(
        matches!(error, AttestationError::KeysUnavailable(_)),
        "{error:?}"
    );
    // Within the 30 s, the same failure without a request; refresh asks.
    assert_eq!(client.get_jwks(false).await.unwrap_err(), error);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(client.get_jwks(true).await.is_err());
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_client_checks_the_answer_before_fetching_keys() {
    let (url, count) = key_server(Duration::ZERO, |_| (503, "down".into())).await;
    let client = client(&url);

    for json in [
        json!({"status": "VERIFIED", "proof_ref": PROOF}),
        json!({"status": "VERIFIED", "attestation": "t"}),
        json!({"status": "VERIFIED", "attestation": "", "proof_ref": PROOF}),
    ] {
        let response: VerificationResponse = serde_json::from_value(json).unwrap();
        let error = client
            .verify_attestation(&response, &AttestationOptions::new())
            .await
            .unwrap_err();
        assert!(
            matches!(&error, AttestationError::Rejected(m) if m.starts_with("no ")),
            "{error:?}"
        );
    }
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_client_checks_the_attested_admission() {
    // #321: the answer's admission must be the one the token signs.
    let (signing, jwks) = key("genuine", KID);
    let served = body(&jwks);
    let (url, _) = key_server(Duration::ZERO, move |_| (200, served.clone())).await;
    let client = client(&url);
    let options = AttestationOptions::new();

    for (signed, carried, ok) in [
        (Some("ADMIT"), Some("ADMIT"), true),
        (Some("BLOCKED"), Some("BLOCKED"), true),
        (None, None, true),
        (Some("BLOCKED"), Some("ADMIT"), false), // an answer edited to say ADMIT
        (None, Some("ADMIT"), false),            // a token that signs no admission
        (Some("ADMIT"), None, false),            // an answer that dropped its admission
        (Some("ADMIT"), Some("SOMETHING_NEW"), false), // parsed as Admission::Unknown
    ] {
        let verified = client
            .verify_attestation(&answer_with(&signing, signed, carried), &options)
            .await;
        match verified {
            Ok(claims) if ok => assert_eq!(claims.qwed.admission.as_deref(), signed),
            Err(AttestationError::Rejected(reason)) if !ok => {
                assert!(reason.contains("another admission"), "{reason}")
            }
            other => panic!("{signed:?} {carried:?}: {other:?}"),
        }
    }
}

#[test]
fn times_before_the_epoch_are_negative() {
    assert_eq!(unix_nanos(UNIX_EPOCH - Duration::from_secs(5)), -5 * NANOS);
}
