package qwed

// #319: the Go SDK verifies attestations.
//
// Tokens are signed at test time with a key generated here, shaped as the
// server issues them (ES256, typ qwed-attestation+jwt, kid naming the key);
// none is stored in the repository.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testProof = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	testQuery = "2+2=4"
	testKid   = "did:qwed:node:local#test-key"
)

type testKey struct {
	private *ecdsa.PrivateKey
	jwks    *JWKS
}

func newTestKey(t *testing.T) testKey {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{private: private, jwks: &JWKS{Keys: []JWK{jwkOf(&private.PublicKey, testKid)}}}
}

func jwkOf(public *ecdsa.PublicKey, kid string) JWK {
	return JWK{
		Kty: "EC", Crv: "P-256", Kid: kid, Alg: "ES256", Use: "sig",
		X: b64(public.X.FillBytes(make([]byte, 32))),
		Y: b64(public.Y.FillBytes(make([]byte, 32))),
	}
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func b64JSON(t *testing.T, value interface{}) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b64(data)
}

func defaultHeader() map[string]interface{} {
	return map[string]interface{}{"alg": "ES256", "typ": "qwed-attestation+jwt", "kid": testKid}
}

// sign signs header.claims with key; highS gives the other valid signature,
// (r, n - s), which the server's own library may produce.
func sign(t *testing.T, key *ecdsa.PrivateKey, header, claims map[string]interface{}, highS bool) string {
	t.Helper()
	input := b64JSON(t, header) + "." + b64JSON(t, claims)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	n := elliptic.P256().Params().N
	half := new(big.Int).Rsh(n, 1)
	if highS != (s.Cmp(half) > 0) {
		s = new(big.Int).Sub(n, s)
	}
	return input + "." + b64(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

func testClaims(overrides map[string]interface{}) map[string]interface{} {
	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iss": "did:qwed:node:local",
		"sub": StatementHash(testQuery),
		"iat": now,
		"exp": now + 3600,
		"jti": "att_test",
		"qwed": map[string]interface{}{
			"version":    "1.0",
			"result":     map[string]interface{}{"status": "VERIFIED", "verified": true, "engine": "math", "confidence": 1},
			"query_hash": StatementHash(testQuery),
			"proof_hash": testProof,
		},
	}
	for name, value := range overrides {
		if value == nil {
			delete(claims, name)
		} else {
			claims[name] = value
		}
	}
	return claims
}

func mustReject(t *testing.T, err error, want error, fragment string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want an error wrapping %v", err, want)
	}
	if fragment != "" && !strings.Contains(err.Error(), fragment) {
		t.Fatalf("got %q, want it to mention %q", err, fragment)
	}
}

// ============================================================================
// VerifyAttestation
// ============================================================================

func TestAGenuineAttestationVerifies(t *testing.T) {
	key := newTestKey(t)
	for _, highS := range []bool{false, true} {
		token := sign(t, key.private, defaultHeader(), testClaims(nil), highS)

		claims, err := VerifyAttestation(token, key.jwks, testProof, AttestationOptions{Query: testQuery})

		if err != nil {
			t.Fatalf("highS=%v: %v", highS, err)
		}
		if claims.QWED.ProofHash != testProof || claims.QWED.Result.Status != "VERIFIED" || claims.Issuer != DefaultIssuer {
			t.Fatalf("claims: %+v", claims)
		}
	}
}

func TestStatementHashIsTheServersQueryHash(t *testing.T) {
	// sha256("2+2=4"), as Python's hashlib and the server's query_hash give it.
	want := "sha256:ccb87154d21d3d96a3835bcdba1aa5f3481a06d34a84f437a7ba312bef8c8b43"
	if got := StatementHash(testQuery); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestRefusals(t *testing.T) {
	key := newTestKey(t)
	forger := newTestKey(t)
	now := time.Now().Unix()
	genuine := sign(t, key.private, defaultHeader(), testClaims(nil), false)
	parts := strings.Split(genuine, ".")

	cases := []struct {
		name     string
		token    string
		proofRef string
		opts     AttestationOptions
		want     error
		fragment string
	}{
		{"another answer's token", genuine, "sha256:" + strings.Repeat("f", 64), AttestationOptions{}, ErrAttestation, "another answer"},
		{"another statement", genuine, testProof, AttestationOptions{Query: "2+2=5"}, ErrAttestation, "another statement"},
		{"not VERIFIED", sign(t, key.private, defaultHeader(), testClaims(map[string]interface{}{
			"qwed": map[string]interface{}{"result": map[string]interface{}{"status": "BLOCKED"}, "proof_hash": testProof},
		}), false), testProof, AttestationOptions{}, ErrAttestation, "VERIFIED"},
		{"expired", sign(t, key.private, defaultHeader(), testClaims(map[string]interface{}{"exp": now - 30}), false),
			testProof, AttestationOptions{}, ErrAttestation, "expired"},
		{"another issuer", sign(t, key.private, defaultHeader(), testClaims(map[string]interface{}{"iss": "did:example:other"}), false),
			testProof, AttestationOptions{}, ErrAttestation, "issuer"},
		{"a missing claim", sign(t, key.private, defaultHeader(), testClaims(map[string]interface{}{"jti": nil}), false),
			testProof, AttestationOptions{}, ErrAttestation, "jti"},
		{"before its nbf", sign(t, key.private, defaultHeader(), testClaims(map[string]interface{}{"nbf": now + 30}), false),
			testProof, AttestationOptions{}, ErrAttestation, "not yet valid"},
		{"an nbf that is not a number", sign(t, key.private, defaultHeader(), testClaims(map[string]interface{}{"nbf": "soon"}), false),
			testProof, AttestationOptions{}, ErrAttestation, "claims"},
		{"another key under the right kid", sign(t, forger.private, defaultHeader(), testClaims(nil), false),
			testProof, AttestationOptions{}, ErrKeyMismatch, "signature"},
		{"a payload changed after signing", parts[0] + "." + b64JSON(t, testClaims(map[string]interface{}{"jti": "att_other"})) + "." + parts[2],
			testProof, AttestationOptions{}, ErrKeyMismatch, "signature"},
		{"a kid the JWKS does not hold", sign(t, key.private, map[string]interface{}{"alg": "ES256", "typ": "qwed-attestation+jwt", "kid": "other"}, testClaims(nil), false),
			testProof, AttestationOptions{}, ErrKeyMismatch, "kid"},
		{"no kid", sign(t, key.private, map[string]interface{}{"alg": "ES256", "typ": "qwed-attestation+jwt"}, testClaims(nil), false),
			testProof, AttestationOptions{}, ErrAttestation, "no key"},
		{"not a QWED attestation", sign(t, key.private, map[string]interface{}{"alg": "ES256", "typ": "JWT", "kid": testKid}, testClaims(nil), false),
			testProof, AttestationOptions{}, ErrAttestation, "not a QWED attestation"},
		{"alg none", b64JSON(t, map[string]interface{}{"alg": "none", "typ": "qwed-attestation+jwt", "kid": testKid}) + "." + parts[1] + ".x",
			testProof, AttestationOptions{}, ErrAttestation, "ES256"},
		{"alg HS256", b64JSON(t, map[string]interface{}{"alg": "HS256", "typ": "qwed-attestation+jwt", "kid": testKid}) + "." + parts[1] + "." + parts[2],
			testProof, AttestationOptions{}, ErrAttestation, "ES256"},
		{"no token", "", testProof, AttestationOptions{}, ErrAttestation, "no attestation"},
		{"no proof_ref", genuine, "", AttestationOptions{}, ErrAttestation, "no proof_ref"},
		{"not a JWT", "not.a.jwt", testProof, AttestationOptions{}, ErrAttestation, "not a JWT"},
		{"two segments", "a.b", testProof, AttestationOptions{}, ErrAttestation, "not a JWT"},
		{"not base64", "%%.%%.%%", testProof, AttestationOptions{}, ErrAttestation, "not a JWT"},
		{"a header that is not an object", "W10." + parts[1] + "." + parts[2], testProof, AttestationOptions{}, ErrAttestation, "not a JWT"},
		{"a signature that is no base64", parts[0] + "." + parts[1] + ".A", testProof, AttestationOptions{}, ErrAttestation, "not a JWT"},
		{"a signature of the wrong length", parts[0] + "." + parts[1] + "." + b64([]byte("short")), testProof, AttestationOptions{}, ErrKeyMismatch, "signature"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := VerifyAttestation(tc.token, key.jwks, tc.proofRef, tc.opts)
			if claims != nil {
				t.Fatalf("verified: %+v", claims)
			}
			mustReject(t, err, tc.want, tc.fragment)
		})
	}
}

func TestExpiryLeewayAndBoundary(t *testing.T) {
	key := newTestKey(t)
	exp := time.Now().Unix() + 100
	token := sign(t, key.private, defaultHeader(), testClaims(map[string]interface{}{"exp": exp}), false)
	at := func(seconds int64) func() time.Time { return func() time.Time { return time.Unix(seconds, 0) } }

	// Expired from the second exp names, as PyJWT.
	if _, err := VerifyAttestation(token, key.jwks, testProof, AttestationOptions{Now: at(exp - 1)}); err != nil {
		t.Fatalf("a second before exp: %v", err)
	}
	_, err := VerifyAttestation(token, key.jwks, testProof, AttestationOptions{Now: at(exp)})
	mustReject(t, err, ErrAttestation, "expired")
	if _, err := VerifyAttestation(token, key.jwks, testProof, AttestationOptions{Now: at(exp + 30), Leeway: time.Minute}); err != nil {
		t.Fatalf("within the leeway: %v", err)
	}

	nbf := sign(t, key.private, defaultHeader(), testClaims(map[string]interface{}{"nbf": exp - 50}), false)
	if _, err := VerifyAttestation(nbf, key.jwks, testProof, AttestationOptions{Now: at(exp - 80), Leeway: time.Minute}); err != nil {
		t.Fatalf("nbf within the leeway: %v", err)
	}
}

func TestASubSecondLeewayCountsInFull(t *testing.T) {
	// #513 review: a leeway of 1.5 s was 1 s.
	key := newTestKey(t)
	exp := time.Now().Unix() + 100
	token := sign(t, key.private, defaultHeader(), testClaims(map[string]interface{}{"exp": exp, "nbf": exp - 50}), false)
	at := func(t time.Time) func() time.Time { return func() time.Time { return t } }
	expiry, notBefore := time.Unix(exp, 0), time.Unix(exp-50, 0)

	ok := []AttestationOptions{
		{Now: at(expiry.Add(1200 * time.Millisecond)), Leeway: 1500 * time.Millisecond},
		{Now: at(notBefore.Add(-1200 * time.Millisecond)), Leeway: 1500 * time.Millisecond},
		{Now: at(expiry.Add(-time.Nanosecond))},
	}
	for _, opts := range ok {
		if _, err := VerifyAttestation(token, key.jwks, testProof, opts); err != nil {
			t.Fatalf("%v", err)
		}
	}
	_, err := VerifyAttestation(token, key.jwks, testProof, AttestationOptions{Now: at(expiry.Add(1200 * time.Millisecond)), Leeway: time.Second})
	mustReject(t, err, ErrAttestation, "expired")
	_, err = VerifyAttestation(token, key.jwks, testProof, AttestationOptions{Now: at(notBefore.Add(-1200 * time.Millisecond)), Leeway: time.Second})
	mustReject(t, err, ErrAttestation, "not yet valid")
}

func TestJWKSKeysThatCannotVerify(t *testing.T) {
	key := newTestKey(t)
	token := sign(t, key.private, defaultHeader(), testClaims(nil), false)
	good := key.jwks.Keys[0]
	offCurve := good
	offCurve.Y = b64(make([]byte, 32))

	for name, tc := range map[string]struct {
		jwks     *JWKS
		want     error
		fragment string
	}{
		"P-384":           {&JWKS{Keys: []JWK{{Kty: "EC", Crv: "P-384", Kid: testKid, X: good.X, Y: good.Y}}}, ErrAttestation, "ES256 P-256"},
		"RSA":             {&JWKS{Keys: []JWK{{Kty: "RSA", Kid: testKid}}}, ErrAttestation, "ES256 P-256"},
		"off the curve":   {&JWKS{Keys: []JWK{offCurve}}, ErrAttestation, "unusable"},
		"bad coordinates": {&JWKS{Keys: []JWK{{Kty: "EC", Crv: "P-256", Kid: testKid, X: "not-a-coordinate", Y: good.Y}}}, ErrAttestation, "unusable"},
		// {} and {"keys": null} from the server: out of date, so a refetch may
		// help (#513 review).
		"no key list": {&JWKS{}, ErrKeyMismatch, "kid"},
		"nil":         {nil, ErrAttestation, "no JWKS"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyAttestation(token, tc.jwks, testProof, AttestationOptions{})
			mustReject(t, err, tc.want, tc.fragment)
		})
	}
}

// ============================================================================
// The client
// ============================================================================

type keyServer struct {
	fetches atomic.Int32
	mu      sync.Mutex
	respond func(n int32) (int, interface{})
	delay   time.Duration
	started chan struct{} // when set, told of each request as it arrives
}

func (k *keyServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != JWKSPath {
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		n := k.fetches.Add(1)
		if k.started != nil {
			k.started <- struct{}{}
		}
		time.Sleep(k.delay)
		k.mu.Lock()
		status, body := k.respond(n)
		k.mu.Unlock()
		w.WriteHeader(status)
		if text, ok := body.(string); ok {
			w.Write([]byte(text))
			return
		}
		json.NewEncoder(w).Encode(body)
	}
}

// fakeClock is a clock the test, or the key server, moves.
type fakeClock struct{ ns atomic.Int64 }

func (f *fakeClock) now() time.Time           { return time.Unix(0, f.ns.Load()) }
func (f *fakeClock) advance(by time.Duration) { f.ns.Add(int64(by)) }

// clockClient is a client of server on a clock the test moves.
func clockClient(server *httptest.Server) (*Client, *fakeClock) {
	clock := &fakeClock{}
	clock.ns.Store(time.Now().UnixNano())
	client := NewClient("k", WithBaseURL(server.URL))
	client.now = clock.now
	return client, clock
}

// answer is a VERIFIED answer carrying token, and no admission, as the
// tokens here sign none unless a test says otherwise.
func answer(token string) *VerificationResponse {
	return &VerificationResponse{Status: StatusVerified, ProofRef: testProof, Attestation: token}
}

func TestTheClientVerifiesAndReusesTheJWKS(t *testing.T) {
	key := newTestKey(t)
	keys := &keyServer{respond: func(int32) (int, interface{}) { return 200, key.jwks }}
	server := httptest.NewServer(keys.handler(t))
	defer server.Close()
	client, _ := clockClient(server)
	resp := answer(sign(t, key.private, defaultHeader(), testClaims(nil), false))

	for i := 0; i < 2; i++ {
		claims, err := client.VerifyAttestation(context.Background(), resp, AttestationOptions{Query: testQuery})
		if err != nil || claims.QWED.ProofHash != testProof {
			t.Fatalf("%v %+v", err, claims)
		}
	}
	if got := keys.fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1", got)
	}
}

func TestTheClientRefetchesForANewKeyButNotWithin30Seconds(t *testing.T) {
	// A rotated key (an unknown kid) and a restart with a new ephemeral key
	// under the same kid (a signature the cached key does not verify).
	key := newTestKey(t)
	before := newTestKey(t)
	rotated := &JWKS{Keys: []JWK{jwkOf(&before.private.PublicKey, "did:qwed:node:local#old")}}
	for name, stale := range map[string]*JWKS{"unknown kid": rotated, "replaced key": before.jwks} {
		t.Run(name, func(t *testing.T) {
			keys := &keyServer{respond: func(n int32) (int, interface{}) {
				if n == 1 {
					return 200, stale
				}
				return 200, key.jwks
			}}
			server := httptest.NewServer(keys.handler(t))
			defer server.Close()
			client, now := clockClient(server)
			resp := answer(sign(t, key.private, defaultHeader(), testClaims(nil), false))

			_, err := client.VerifyAttestation(context.Background(), resp, AttestationOptions{})
			mustReject(t, err, ErrKeyMismatch, "")
			_, err = client.VerifyAttestation(context.Background(), resp, AttestationOptions{})
			mustReject(t, err, ErrKeyMismatch, "")
			if got := keys.fetches.Load(); got != 1 {
				t.Fatalf("fetches within 30 s = %d, want 1", got)
			}

			now.advance(time.Minute) // still within the five-minute cache
			if _, err := client.VerifyAttestation(context.Background(), resp, AttestationOptions{}); err != nil {
				t.Fatal(err)
			}
			if got := keys.fetches.Load(); got != 2 {
				t.Fatalf("fetches = %d, want 2", got)
			}
		})
	}
}

func TestTheClientTriesKeysAnotherCallerFetchedMeanwhile(t *testing.T) {
	// One caller checks the old keys while another refreshes them: it
	// retries with the new keys, without a fetch, although the last fetch was
	// just now.
	key := newTestKey(t)
	before := newTestKey(t)
	keys := &keyServer{respond: func(int32) (int, interface{}) { return 200, key.jwks }}
	server := httptest.NewServer(keys.handler(t))
	defer server.Close()
	client, _ := clockClient(server)
	client.jwks, client.jwksFetchedAt, client.jwksAttemptedAt = key.jwks, client.clock(), client.clock()
	token := sign(t, key.private, defaultHeader(), testClaims(nil), false)

	newer, err := client.jwksAfterMismatch(context.Background(), before.jwks)

	if err != nil || newer != key.jwks {
		t.Fatalf("got %v %v, want the cached keys", newer, err)
	}
	if _, err := VerifyAttestation(token, newer, testProof, AttestationOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := keys.fetches.Load(); got != 0 {
		t.Fatalf("fetches = %d, want 0", got)
	}
}

func TestAFailedFetchIsSharedFor30Seconds(t *testing.T) {
	key := newTestKey(t)
	keys := &keyServer{delay: 50 * time.Millisecond, respond: func(n int32) (int, interface{}) {
		if n == 1 {
			return 503, "down"
		}
		return 200, key.jwks
	}}
	server := httptest.NewServer(keys.handler(t))
	defer server.Close()
	client, now := clockClient(server)
	resp := answer(sign(t, key.private, defaultHeader(), testClaims(nil), false))

	// Callers queued behind the failing fetch, and those after it, get its
	// failure without a request each.
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = client.VerifyAttestation(context.Background(), resp, AttestationOptions{})
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		mustReject(t, err, ErrKeysUnavailable, "503")
	}
	if got := keys.fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1", got)
	}

	now.advance(31 * time.Second)
	if _, err := client.VerifyAttestation(context.Background(), resp, AttestationOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := keys.fetches.Load(); got != 2 {
		t.Fatalf("fetches = %d, want 2", got)
	}
}

func TestAFailedRefreshAfterAKeyMismatchIsKeysUnavailable(t *testing.T) {
	key := newTestKey(t)
	before := newTestKey(t)
	keys := &keyServer{respond: func(int32) (int, interface{}) { return 503, "down" }}
	server := httptest.NewServer(keys.handler(t))
	defer server.Close()
	client := NewClient("k", WithBaseURL(server.URL)) // the real clock
	// Keys cached a minute ago: past the 30 s, within the five minutes.
	client.jwks = before.jwks
	client.jwksFetchedAt = time.Now().Add(-time.Minute)
	client.jwksAttemptedAt = client.jwksFetchedAt
	resp := answer(sign(t, key.private, defaultHeader(), testClaims(nil), false))

	_, err := client.VerifyAttestation(context.Background(), resp, AttestationOptions{})

	mustReject(t, err, ErrKeysUnavailable, "503")
	// Within the next 30 s the refresh's failure, not a missing key, and no
	// request (#513 review).
	_, err = client.VerifyAttestation(context.Background(), resp, AttestationOptions{})
	mustReject(t, err, ErrKeysUnavailable, "503")
	if got := keys.fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1", got)
	}
}

func TestASlowFailureIsSharedForTheFull30Seconds(t *testing.T) {
	// #513 review: the 30 s counted from the start of a fetch, so one that
	// took 30 s to fail was already past them.
	key := newTestKey(t)
	var clock *fakeClock
	keys := &keyServer{respond: func(n int32) (int, interface{}) {
		if n == 1 {
			clock.advance(40 * time.Second) // the fetch takes 40 s to fail
			return 503, "down"
		}
		return 200, key.jwks
	}}
	server := httptest.NewServer(keys.handler(t))
	defer server.Close()
	client, clock := clockClient(server)
	resp := answer(sign(t, key.private, defaultHeader(), testClaims(nil), false))

	_, err := client.VerifyAttestation(context.Background(), resp, AttestationOptions{})
	mustReject(t, err, ErrKeysUnavailable, "503")
	_, err = client.VerifyAttestation(context.Background(), resp, AttestationOptions{})
	mustReject(t, err, ErrKeysUnavailable, "503")
	if got := keys.fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1", got)
	}
}

func TestACancelledCallerDoesNotExtendACachedFailure(t *testing.T) {
	// #513 review: a cancelled caller moved the 30 s window on and left the
	// old failure in place, so a recovered server was not asked again.
	key := newTestKey(t)
	keys := &keyServer{respond: func(n int32) (int, interface{}) {
		if n == 1 {
			return 503, "down"
		}
		return 200, key.jwks
	}}
	server := httptest.NewServer(keys.handler(t))
	defer server.Close()
	client, clock := clockClient(server)
	if _, err := client.GetJWKS(context.Background(), false); !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("got %v", err)
	}
	clock.advance(31 * time.Second)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := client.GetJWKS(cancelled, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("the cancelled caller: %v", err)
	}
	if _, err := client.GetJWKS(context.Background(), false); err != nil {
		t.Fatalf("the next caller: %v", err)
	}
}

func TestAWaitingCallerStopsWithItsContext(t *testing.T) {
	// #513 review: a caller waiting for another's fetch waited for all of it.
	key := newTestKey(t)
	keys := &keyServer{delay: 300 * time.Millisecond, started: make(chan struct{}, 1),
		respond: func(int32) (int, interface{}) { return 200, key.jwks }}
	server := httptest.NewServer(keys.handler(t))
	defer server.Close()
	client, _ := clockClient(server)
	done := make(chan error, 1)
	go func() {
		_, err := client.GetJWKS(context.Background(), false)
		done <- err
	}()
	<-keys.started

	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	began := time.Now()
	_, err := client.GetJWKS(short, false)

	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("got %v", err)
	}
	if waited := time.Since(began); waited > 200*time.Millisecond {
		t.Fatalf("waited %v for another caller's fetch", waited)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestFreshKeysDoNotWaitForAFetchInFlight(t *testing.T) {
	// #513 review: a refresh after a key mismatch held up every caller,
	// though the keys they needed were cached and fresh.
	key := newTestKey(t)
	keys := &keyServer{delay: 300 * time.Millisecond, started: make(chan struct{}, 1),
		respond: func(int32) (int, interface{}) { return 200, key.jwks }}
	server := httptest.NewServer(keys.handler(t))
	defer server.Close()
	client, clock := clockClient(server)
	client.jwks, client.jwksFetchedAt = key.jwks, clock.now()
	client.jwksAttemptedAt = clock.now().Add(-time.Minute)
	refreshed := make(chan error, 1)
	go func() {
		_, err := client.jwksAfterMismatch(context.Background(), key.jwks)
		refreshed <- err
	}()
	<-keys.started

	began := time.Now()
	jwks, err := client.GetJWKS(context.Background(), false)

	if err != nil || len(jwks.Keys) != 1 {
		t.Fatalf("%v %v", jwks, err)
	}
	if waited := time.Since(began); waited > 200*time.Millisecond {
		t.Fatalf("waited %v for the refresh", waited)
	}
	if err := <-refreshed; err != nil {
		t.Fatal(err)
	}
}

func TestGetJWKSReturnsACopy(t *testing.T) {
	// #513 review: changing the returned keys changed the keys the client
	// trusts.
	key := newTestKey(t)
	keys := &keyServer{respond: func(int32) (int, interface{}) { return 200, key.jwks }}
	server := httptest.NewServer(keys.handler(t))
	defer server.Close()
	client, _ := clockClient(server)
	resp := answer(sign(t, key.private, defaultHeader(), testClaims(nil), false))

	got, err := client.GetJWKS(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	got.Keys[0].X = b64(make([]byte, 32))
	got.Keys = nil

	if _, err := client.VerifyAttestation(context.Background(), resp, AttestationOptions{}); err != nil {
		t.Fatalf("the cached keys changed: %v", err)
	}
}

func TestConcurrentCallersShareOneFetch(t *testing.T) {
	key := newTestKey(t)
	keys := &keyServer{delay: 50 * time.Millisecond, respond: func(int32) (int, interface{}) { return 200, key.jwks }}
	server := httptest.NewServer(keys.handler(t))
	defer server.Close()
	client, _ := clockClient(server)
	resp := answer(sign(t, key.private, defaultHeader(), testClaims(nil), false))

	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = client.VerifyAttestation(context.Background(), resp, AttestationOptions{})
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := keys.fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1", got)
	}
}

func TestUnreadableKeysAreUnavailable(t *testing.T) {
	keys := &keyServer{respond: func(int32) (int, interface{}) { return 200, "not json" }}
	server := httptest.NewServer(keys.handler(t))
	defer server.Close()
	client, _ := clockClient(server)

	_, err := client.GetJWKS(context.Background(), false)

	mustReject(t, err, ErrKeysUnavailable, "")
}

func TestACancelledCallerDoesNotFailTheOthers(t *testing.T) {
	// The caller's own cancellation says nothing about the server.
	key := newTestKey(t)
	keys := &keyServer{respond: func(int32) (int, interface{}) { return 200, key.jwks }}
	server := httptest.NewServer(keys.handler(t))
	defer server.Close()
	client, _ := clockClient(server)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := client.GetJWKS(cancelled, false); !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("got %v", err)
	}
	if _, err := client.GetJWKS(context.Background(), false); err != nil {
		t.Fatalf("the next caller: %v", err)
	}
}

func TestTheClientChecksTheAnswerBeforeFetchingKeys(t *testing.T) {
	keys := &keyServer{respond: func(int32) (int, interface{}) { return 503, "down" }}
	server := httptest.NewServer(keys.handler(t))
	defer server.Close()
	client, _ := clockClient(server)

	for name, resp := range map[string]*VerificationResponse{
		"no answer":    nil,
		"no token":     {Status: StatusVerified, ProofRef: testProof},
		"no proof_ref": {Status: StatusVerified, Attestation: "t"},
	} {
		_, err := client.VerifyAttestation(context.Background(), resp, AttestationOptions{})
		mustReject(t, err, ErrAttestation, "no ")
		if errors.Is(err, ErrKeysUnavailable) {
			t.Fatalf("%s: fetched keys: %v", name, err)
		}
	}
	if got := keys.fetches.Load(); got != 0 {
		t.Fatalf("fetches = %d, want 0", got)
	}
}

// ============================================================================
// The attested admission (#321)
// ============================================================================

// withAdmission are testClaims whose qwed claims sign admission ("" for none).
func withAdmission(admission string) map[string]interface{} {
	claims := testClaims(nil)
	if admission != "" {
		claims["qwed"].(map[string]interface{})["admission"] = admission
	}
	return claims
}

func TestTheClientChecksTheAttestedAdmission(t *testing.T) {
	key := newTestKey(t)
	keys := &keyServer{respond: func(int32) (int, interface{}) { return 200, key.jwks }}
	server := httptest.NewServer(keys.handler(t))
	defer server.Close()
	client, _ := clockClient(server)

	for _, tc := range []struct {
		name, signed string
		carried      Admission
		ok           bool
	}{
		{"ADMIT signed and carried", "ADMIT", AdmissionAdmit, true},
		{"BLOCKED signed and carried", "BLOCKED", AdmissionBlocked, true},
		{"none signed, none carried", "", "", true},
		{"an answer edited to say ADMIT", "BLOCKED", AdmissionAdmit, false},
		{"a token that signs no admission", "", AdmissionAdmit, false},
		{"an answer that dropped its admission", "ADMIT", "", false},
		{"an admission this SDK does not know", "ADMIT", AdmissionUnknown, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := answer(sign(t, key.private, defaultHeader(), withAdmission(tc.signed), false))
			resp.Admission = tc.carried

			claims, err := client.VerifyAttestation(context.Background(), resp, AttestationOptions{})

			if tc.ok {
				if err != nil || claims.QWED.Admission != tc.signed {
					t.Fatalf("%v %+v", err, claims)
				}
				return
			}
			mustReject(t, err, ErrAttestation, "another admission")
		})
	}
}

func TestVerifyAttestationChecksAnAdmissionGivenToIt(t *testing.T) {
	key := newTestKey(t)
	token := sign(t, key.private, defaultHeader(), withAdmission("BLOCKED"), false)

	for _, admission := range []string{"BLOCKED", ""} {
		claims, err := VerifyAttestation(token, key.jwks, testProof, AttestationOptions{Admission: admission})
		if err != nil || claims.QWED.Admission != "BLOCKED" {
			t.Fatalf("%q: %v %+v", admission, err, claims)
		}
	}
	_, err := VerifyAttestation(token, key.jwks, testProof, AttestationOptions{Admission: "ADMIT"})
	mustReject(t, err, ErrAttestation, "another admission")
	mustReject(t, CheckAdmission(nil, ""), ErrAttestation, "another admission")
}
