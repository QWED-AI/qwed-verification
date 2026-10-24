"""Verify a QWED attestation (#319).

A VERIFIED answer from a QWED server carries ``attestation``: an ES256 JWT
the server signed after checking the verdict. Verifying it shows the answer
came from that server and was not changed:

- the signature, with the key the token header's ``kid`` names in the
  server's JWKS (``GET /.well-known/jwks.json``);
- the issuer, and that the token has not expired;
- that it attests a VERIFIED result;
- that its ``proof_hash`` is the answer's ``proof_ref``, so it is this
  answer's token;
- optionally, that its ``query_hash`` is the SHA-256 of the statement the
  verdict covers: the query you sent (for natural language, the translated
  expression the server reports).

A token says the server reached the verdict; whether to act on it is still
the answer's ``admission``. Fetching the JWKS from the server you asked
trusts that server's TLS; to verify offline or against a pinned key, pass
the JWKS you hold.
"""

import hashlib
from collections.abc import Mapping
from typing import Any

import jwt

# The issuer a QWED server signs as.
DEFAULT_ISSUER = "did:qwed:node:local"
TOKEN_TYPE = "qwed-attestation+jwt"
JWKS_PATH = "/.well-known/jwks.json"


class AttestationError(Exception):
    """The attestation does not verify, or does not attest this answer."""


class UnknownKeyError(AttestationError):
    """No key in the JWKS has the token's kid: the key may have rotated
    since the JWKS was fetched."""


def _key_for(header: Mapping[str, Any], jwks: Mapping[str, Any]) -> Any:
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise AttestationError("token header names no key (kid)")
    keys = jwks.get("keys") if isinstance(jwks, Mapping) else None
    if not isinstance(keys, list):
        raise AttestationError("JWKS has no keys")
    for jwk in keys:
        if isinstance(jwk, Mapping) and jwk.get("kid") == kid:
            if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or jwk.get("alg", "ES256") != "ES256":
                raise AttestationError("JWKS key is not an ES256 P-256 key")
            try:
                return jwt.PyJWK(dict(jwk), algorithm="ES256").key
            except jwt.PyJWTError as exc:
                raise AttestationError("JWKS key is unusable") from exc
    raise UnknownKeyError("no JWKS key matches the token's kid")


def statement_hash(statement: str) -> str:
    """The ``query_hash`` a token carries for ``statement``."""
    return "sha256:" + hashlib.sha256(statement.encode()).hexdigest()


def verify_attestation(
    token: str,
    jwks: Mapping[str, Any],
    *,
    proof_ref: str,
    query: str | None = None,
    issuer: str = DEFAULT_ISSUER,
    leeway: int = 0,
) -> dict[str, Any]:
    """Verify ``token`` as the attestation of the answer whose ``proof_ref``
    is given, and return its claims; raise AttestationError otherwise.

    ``query``, when given, must be the statement the verdict covers.
    ``leeway`` is the clock skew allowed on expiry, in seconds.
    """
    if not isinstance(token, str) or not token:
        raise AttestationError("no attestation")
    if not isinstance(proof_ref, str) or not proof_ref:
        raise AttestationError("no proof_ref to bind the attestation to")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise AttestationError("attestation is not a JWT") from exc
    # Only ES256: a token that names another algorithm, including "none" or
    # an HMAC one keyed with the public key, is refused before any key is used.
    if header.get("alg") != "ES256":
        raise AttestationError("attestation is not signed with ES256")
    if header.get("typ") != TOKEN_TYPE:
        raise AttestationError("token is not a QWED attestation")
    key = _key_for(header, jwks)
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=["ES256"],
            issuer=issuer,
            leeway=leeway,
            options={"require": ["iss", "sub", "iat", "exp", "jti"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AttestationError("attestation has expired") from exc
    except jwt.PyJWTError as exc:
        raise AttestationError("attestation signature or claims do not verify") from exc

    qwed = claims.get("qwed")
    result = qwed.get("result") if isinstance(qwed, Mapping) else None
    if not isinstance(result, Mapping) or result.get("status") != "VERIFIED":
        raise AttestationError("attestation does not attest a VERIFIED result")
    if qwed.get("proof_hash") != proof_ref:
        raise AttestationError("attestation is for another answer (proof_ref differs)")
    if query is not None and qwed.get("query_hash") != statement_hash(query):
        raise AttestationError("attestation is for another statement (query differs)")
    return claims
