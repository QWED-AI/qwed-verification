package qwed

// Verify a QWED attestation (#319).
//
// A VERIFIED answer from a QWED server carries Attestation: an ES256 JWT the
// server signed after checking the verdict. Verifying it shows that server
// issued a VERIFIED verdict for this answer's ProofRef (and, when you pass
// it, for this statement). It covers only what the token signs: the status,
// ProofRef, statement hash and, on a route that decides one, the admission;
// not other fields of the response such as AgentMessage. What is checked:
//
//   - the signature, with the key the token header's kid names in the
//     server's JWKS (GET /.well-known/jwks.json);
//   - the issuer, and that the token has not expired (nor is used before any
//     nbf it carries);
//   - that it attests a VERIFIED result;
//   - that its proof_hash is the answer's ProofRef, so it is this answer's
//     token;
//   - optionally, that its query_hash is the SHA-256 of the statement the
//     verdict covers;
//   - on a route that decides an admission, the token signs it too
//     (qwed.admission, #321): the client checks it is the answer's
//     Admission, so the server's ADMIT or BLOCKED is verified as well.
//
// A token says the server reached the verdict and, where it signs one, the
// admission; act on the admission (IsAdmitted). Fetching the JWKS from the server you
// asked trusts that server's TLS; to verify offline or against a pinned key,
// call VerifyAttestation with the JWKS you hold.

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const (
	// DefaultIssuer is the issuer a QWED server signs as.
	DefaultIssuer = "did:qwed:node:local"
	// JWKSPath is where a QWED server publishes its attestation keys.
	JWKSPath  = "/.well-known/jwks.json"
	tokenType = "qwed-attestation+jwt"

	// How long a fetched JWKS is reused, as the server's Cache-Control says.
	jwksMaxAge = 5 * time.Minute
	// The least time since the last attempt to fetch the JWKS before another:
	// after a token none of the cached keys verifies (a key rotation or a
	// restart with a new ephemeral key is picked up within this, but a stream
	// of forged tokens cannot turn each one into a request), and after a
	// failed fetch, whose failure every caller gets meanwhile instead of a
	// request each.
	jwksMinRefresh = 30 * time.Second
)

var (
	// ErrAttestation is wrapped by every error VerifyAttestation and
	// Client.VerifyAttestation return: the attestation does not verify, or
	// does not attest this answer. Test with errors.Is.
	ErrAttestation = errors.New("qwed: attestation rejected")
	// ErrKeyMismatch: no key in the JWKS verifies the token, so fetching the
	// JWKS again may help (the key rotated, or the server restarted with a
	// new ephemeral key under the same kid). It wraps ErrAttestation.
	ErrKeyMismatch = fmt.Errorf("%w: no key in the JWKS verifies it", ErrAttestation)
	// ErrKeysUnavailable: the server's keys could not be fetched, so nothing
	// can be verified. The client asks again at most once every 30 seconds.
	// It wraps ErrAttestation.
	ErrKeysUnavailable = fmt.Errorf("%w: attestation keys unavailable", ErrAttestation)
)

func rejected(reason string) error {
	return fmt.Errorf("%w: %s", ErrAttestation, reason)
}

func keyMismatch(reason string) error {
	return fmt.Errorf("%w: %s", ErrKeyMismatch, reason)
}

// JWK is one public key of a JWKS.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

// JWKS is a set of public keys, as a QWED server publishes at JWKSPath.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// AttestedResult is the verdict a token attests.
type AttestedResult struct {
	Status     string  `json:"status"`
	Verified   bool    `json:"verified"`
	Engine     string  `json:"engine,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

// QWEDClaims are the token's qwed claims.
type QWEDClaims struct {
	Version   string         `json:"version,omitempty"`
	Result    AttestedResult `json:"result"`
	QueryHash string         `json:"query_hash,omitempty"`
	ProofHash string         `json:"proof_hash"`
	// Admission is the server's admission, ADMIT or BLOCKED, on a route that
	// decides one (#321); empty otherwise.
	Admission string `json:"admission,omitempty"`
}

// AttestationClaims are a verified token's claims. Times are Unix seconds.
type AttestationClaims struct {
	Issuer    string     `json:"iss"`
	Subject   string     `json:"sub"`
	IssuedAt  int64      `json:"iat"`
	Expiry    int64      `json:"exp"`
	NotBefore *int64     `json:"nbf,omitempty"`
	ID        string     `json:"jti"`
	QWED      QWEDClaims `json:"qwed"`
}

// AttestationOptions configures a verification. The zero value checks the
// default issuer with no leeway and no statement.
type AttestationOptions struct {
	// Query, when not empty, must be the statement the verdict covers: the
	// query you sent (for natural language, the translated expression the
	// server reports).
	Query string
	// Issuer defaults to DefaultIssuer.
	Issuer string
	// Leeway is the clock skew allowed on expiry and nbf.
	Leeway time.Duration
	// Admission, when not empty, is the admission the token must sign: the
	// answer's Admission (#321). See CheckAdmission.
	Admission string
	// Now is the current time (tests); time.Now when nil.
	Now func() time.Time
}

// StatementHash is the query_hash a token carries for statement.
func StatementHash(statement string) string {
	sum := sha256.Sum256([]byte(statement))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CheckAdmission returns an error, wrapping ErrAttestation, unless the
// verified claims sign admission: the answer's Admission (#321), or empty for
// an answer that carries none, whose token must then sign none.
func CheckAdmission(claims *AttestationClaims, admission string) error {
	if claims == nil || claims.QWED.Admission != admission {
		return rejected("attestation is for another admission (admission differs)")
	}
	return nil
}

// requireAnswer returns an error unless there is a token and a proof_ref to
// bind it to; checked before any key is fetched.
func requireAnswer(token, proofRef string) error {
	if token == "" {
		return rejected("no attestation")
	}
	if proofRef == "" {
		return rejected("no proof_ref to bind the attestation to")
	}
	return nil
}

// jsonSegment decodes a token segment that must be a JSON object, and
// returns its bytes and its fields.
func jsonSegment(segment string) ([]byte, map[string]json.RawMessage, error) {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return nil, nil, rejected("not a JWT")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, nil, rejected("not a JWT")
	}
	return raw, fields, nil
}

func stringField(fields map[string]json.RawMessage, name string) (string, bool) {
	var value string
	if raw, ok := fields[name]; ok && json.Unmarshal(raw, &value) == nil {
		return value, true
	}
	return "", false
}

// publicKey is the ECDSA P-256 key jwk holds.
func publicKey(jwk JWK) (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || (jwk.Alg != "" && jwk.Alg != "ES256") {
		return nil, rejected("JWKS key is not an ES256 P-256 key")
	}
	x, errX := base64.RawURLEncoding.DecodeString(jwk.X)
	y, errY := base64.RawURLEncoding.DecodeString(jwk.Y)
	if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
		return nil, rejected("JWKS key is unusable")
	}
	// crypto/ecdh refuses a point that is not on the curve.
	point := append(append([]byte{4}, x...), y...)
	if _, err := ecdh.P256().NewPublicKey(point); err != nil {
		return nil, rejected("JWKS key is unusable")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
}

// VerifyAttestation verifies token as the attestation of the answer whose
// proof_ref is proofRef, against jwks, and returns its claims. Every error
// wraps ErrAttestation; one that fetching the JWKS again may cure wraps
// ErrKeyMismatch.
func VerifyAttestation(token string, jwks *JWKS, proofRef string, opts AttestationOptions) (*AttestationClaims, error) {
	if err := requireAnswer(token, proofRef); err != nil {
		return nil, err
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, rejected("not a JWT")
	}
	_, header, err := jsonSegment(parts[0])
	if err != nil {
		return nil, err
	}
	// Only ES256: a token that names another algorithm, including "none" or
	// an HMAC one, is refused before any key is used.
	if alg, _ := stringField(header, "alg"); alg != "ES256" {
		return nil, rejected("not signed with ES256")
	}
	if typ, _ := stringField(header, "typ"); typ != tokenType {
		return nil, rejected("token is not a QWED attestation")
	}
	kid, _ := stringField(header, "kid")
	if kid == "" {
		return nil, rejected("token header names no key (kid)")
	}
	if jwks == nil {
		return nil, rejected("no JWKS")
	}
	var key *ecdsa.PublicKey
	for _, jwk := range jwks.Keys {
		if jwk.Kid == kid {
			if key, err = publicKey(jwk); err != nil {
				return nil, err
			}
			break
		}
	}
	if key == nil {
		return nil, keyMismatch("no JWKS key matches the token's kid")
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, rejected("not a JWT")
	}
	// JWS ES256 is the raw r || s pair, 64 bytes.
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(signature) != 64 || !ecdsa.Verify(key, digest[:],
		new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return nil, keyMismatch("signature does not verify")
	}

	// From here on the header and claims are verified.
	raw, payload, err := jsonSegment(parts[1])
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"iss", "sub", "iat", "exp", "jti"} {
		if value, ok := payload[name]; !ok || string(value) == "null" {
			return nil, rejected("claims do not verify (no " + name + ")")
		}
	}
	var claims AttestationClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, rejected("claims do not verify")
	}
	issuer := opts.Issuer
	if issuer == "" {
		issuer = DefaultIssuer
	}
	if claims.Issuer != issuer {
		return nil, rejected("claims do not verify (issuer differs)")
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	// As RFC 7519, PyJWT and the TypeScript SDK: expired once now reaches
	// exp, and not valid while now is before an nbf the token carries. The
	// leeway counts in full, a fraction of a second included.
	current := now()
	if !current.Before(time.Unix(claims.Expiry, 0).Add(opts.Leeway)) {
		return nil, rejected("attestation has expired")
	}
	if claims.NotBefore != nil && current.Add(opts.Leeway).Before(time.Unix(*claims.NotBefore, 0)) {
		return nil, rejected("attestation is not yet valid (nbf)")
	}
	if claims.QWED.Result.Status != string(StatusVerified) {
		return nil, rejected("attestation does not attest a VERIFIED result")
	}
	if claims.QWED.ProofHash != proofRef {
		return nil, rejected("attestation is for another answer (proof_ref differs)")
	}
	if opts.Query != "" && claims.QWED.QueryHash != StatementHash(opts.Query) {
		return nil, rejected("attestation is for another statement (query differs)")
	}
	if opts.Admission != "" {
		if err := CheckAdmission(&claims, opts.Admission); err != nil {
			return nil, err
		}
	}
	return &claims, nil
}

// ============================================================================
// The client's keys
// ============================================================================

func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *Client) slot() chan struct{} {
	c.jwksSlotOnce.Do(func() { c.jwksSlot = make(chan struct{}, 1) })
	return c.jwksSlot
}

// acquireFetch waits for the one fetch slot, or until ctx ends.
func (c *Client) acquireFetch(ctx context.Context) error {
	select {
	case c.slot() <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%w: %w", ErrKeysUnavailable, ctx.Err())
	}
}

func (c *Client) releaseFetch() { <-c.slot() }

// cached returns the keys if they are fresh, and the last fetch's failure
// if it ended less than 30 seconds ago.
func (c *Client) cached() (fresh *JWKS, recentErr error) {
	c.jwksMu.Lock()
	defer c.jwksMu.Unlock()
	now := c.clock()
	if c.jwks != nil && now.Sub(c.jwksFetchedAt) <= jwksMaxAge {
		fresh = c.jwks
	}
	if c.jwksErr != nil && now.Sub(c.jwksAttemptedAt) < jwksMinRefresh {
		recentErr = c.jwksErr
	}
	return fresh, recentErr
}

// fetchJWKS fetches the keys; the caller holds the fetch slot.
func (c *Client) fetchJWKS(ctx context.Context) (*JWKS, error) {
	jwks, err := c.requestJWKS(ctx)
	c.jwksMu.Lock()
	defer c.jwksMu.Unlock()
	// The attempt is recorded when the fetch ends, so a slow failure is
	// still shared for the full 30 seconds. The caller's own cancellation
	// says nothing about the server, so it changes nothing.
	if err != nil {
		if ctx.Err() == nil {
			c.jwksErr, c.jwksAttemptedAt = err, c.clock()
		}
		return nil, err
	}
	now := c.clock()
	c.jwks, c.jwksErr, c.jwksFetchedAt, c.jwksAttemptedAt = jwks, nil, now, now
	return jwks, nil
}

func (c *Client) requestJWKS(ctx context.Context) (*JWKS, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+JWKSPath, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeysUnavailable, err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeysUnavailable, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeysUnavailable, err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%w: HTTP %d", ErrKeysUnavailable, resp.StatusCode)
	}
	var jwks JWKS
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeysUnavailable, err)
	}
	return &jwks, nil
}

// cachedJWKS returns the keys the client holds, fetching them when they are
// missing or past their age (or when refresh). Fresh keys are returned
// without waiting for a fetch in flight.
func (c *Client) cachedJWKS(ctx context.Context, refresh bool) (*JWKS, error) {
	if !refresh {
		if fresh, _ := c.cached(); fresh != nil {
			return fresh, nil
		}
	}
	if err := c.acquireFetch(ctx); err != nil {
		return nil, err
	}
	defer c.releaseFetch()
	if !refresh {
		// Callers that waited get what the fetch before them got.
		fresh, recentErr := c.cached()
		if fresh != nil {
			return fresh, nil
		}
		if recentErr != nil {
			return nil, recentErr
		}
	}
	return c.fetchJWKS(ctx)
}

// GetJWKS returns a copy of the server's attestation keys (GET
// /.well-known/jwks.json, no API key), reused for five minutes as the
// server's Cache-Control says. Callers that need keys while a fetch is in
// flight wait for it, or until their context ends, and share what it got. A
// failed fetch's error, which wraps ErrKeysUnavailable, is returned again
// for 30 seconds without a request, unless refresh. Keys past their age are
// not used instead: a key the server has since withdrawn would still verify.
func (c *Client) GetJWKS(ctx context.Context, refresh bool) (*JWKS, error) {
	jwks, err := c.cachedJWKS(ctx, refresh)
	if err != nil {
		return nil, err
	}
	// A copy: changing it does not change the keys the client trusts.
	return &JWKS{Keys: append([]JWK(nil), jwks.Keys...)}, nil
}

// jwksAfterMismatch returns the keys to try once more after none in used
// verified a token: those another caller fetched meanwhile, else a fresh
// fetch if the last one ended at least 30 seconds ago. Within those 30
// seconds it returns the last fetch's failure if it failed, else nil.
func (c *Client) jwksAfterMismatch(ctx context.Context, used *JWKS) (*JWKS, error) {
	if err := c.acquireFetch(ctx); err != nil {
		return nil, err
	}
	defer c.releaseFetch()
	c.jwksMu.Lock()
	current, lastErr := c.jwks, c.jwksErr
	recent := c.clock().Sub(c.jwksAttemptedAt) < jwksMinRefresh
	c.jwksMu.Unlock()
	if current != nil && current != used {
		return current, nil
	}
	if recent {
		// A refresh that just failed is reported as such, not as a token
		// whose key is missing.
		return nil, lastErr
	}
	return c.fetchJWKS(ctx)
}

// VerifyAttestation verifies resp's attestation against this server's keys
// and returns its claims. Every error wraps ErrAttestation: the token does
// not verify or is not this answer's (its ProofRef, and the Admission it
// carries, which the token must sign, none if it carries none, #321), or
// (ErrKeysUnavailable) the keys could not be fetched. To verify against keys you pinned, call the package's
// VerifyAttestation with your JWKS.
func (c *Client) VerifyAttestation(ctx context.Context, resp *VerificationResponse, opts AttestationOptions) (*AttestationClaims, error) {
	if resp == nil {
		return nil, rejected("no answer")
	}
	// A missing token or proof_ref is refused before any key is fetched.
	if err := requireAnswer(resp.Attestation, resp.ProofRef); err != nil {
		return nil, err
	}
	if opts.Now == nil {
		opts.Now = c.clock
	}
	jwks, err := c.cachedJWKS(ctx, false)
	if err != nil {
		return nil, err
	}
	claims, err := VerifyAttestation(resp.Attestation, jwks, resp.ProofRef, opts)
	if errors.Is(err, ErrKeyMismatch) {
		// The key may have rotated, or the server restarted with a new key
		// under the same kid, since the JWKS was cached: try the keys once
		// more.
		newer, fetchErr := c.jwksAfterMismatch(ctx, jwks)
		if fetchErr != nil {
			return nil, fetchErr
		}
		if newer == nil {
			return nil, err
		}
		claims, err = VerifyAttestation(resp.Attestation, newer, resp.ProofRef, opts)
	}
	if err != nil {
		return nil, err
	}
	// The token signs the server's admission where the route decides one
	// (#321): the answer's admission must be that one.
	if err := CheckAdmission(claims, string(resp.Admission)); err != nil {
		return nil, err
	}
	return claims, nil
}
