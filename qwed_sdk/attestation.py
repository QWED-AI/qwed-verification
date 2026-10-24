"""Verify a QWED attestation (#319).

A VERIFIED answer from a QWED server carries ``attestation``: an ES256 JWT
the server signed after checking the verdict. Verifying it shows that server
issued a VERIFIED verdict for this answer's ``proof_ref`` (and, when you pass
it, for this statement). It covers only what the token signs: the status,
``proof_ref`` and statement hash, not other fields of the response such as
``admission`` or ``agent_message``. What is checked:

- the signature, with the key the token header's ``kid`` names in the
  server's JWKS (``GET /.well-known/jwks.json``);
- the issuer, and that the token has not expired (nor is used before any
  ``nbf`` it carries);
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

import base64
import hashlib
import json
from collections.abc import Mapping
from typing import Any

import jwt

# The issuer a QWED server signs as.
DEFAULT_ISSUER = "did:qwed:node:local"
TOKEN_TYPE = "qwed-attestation+jwt"
JWKS_PATH = "/.well-known/jwks.json"


class AttestationError(Exception):
    """The attestation does not verify, or does not attest this answer."""


class KeyMismatchError(AttestationError):
    """The JWKS held may not have the key that signed the token, so fetching
    it again may help: the signature does not verify with the key the kid
    names, which also happens when a server restarted with a new ephemeral
    key under the same kid."""


class UnknownKeyError(KeyMismatchError):
    """No key in the JWKS has the token's kid: the key may have rotated
    since the JWKS was fetched."""


def require_answer(token: Any, proof_ref: Any) -> None:
    """Raise AttestationError unless there is a token and a proof_ref to
    bind it to; checked before any key is fetched."""
    if not isinstance(token, str) or not token:
        raise AttestationError("no attestation")
    if not isinstance(proof_ref, str) or not proof_ref:
        raise AttestationError("no proof_ref to bind the attestation to")


def _kid_of(token: str) -> Any:
    """The ``kid`` the token's header names, read before verification only
    to choose the key that then verifies it; nothing else from the header
    is used until the signature has been checked."""
    try:
        segment = token.split(".")[0]
        header = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except (ValueError, TypeError) as exc:
        raise AttestationError("attestation is not a JWT") from exc
    if not isinstance(header, dict):
        raise AttestationError("attestation is not a JWT")
    return header.get("kid")


def _key_for(kid: Any, jwks: Mapping[str, Any]) -> Any:
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
    require_answer(token, proof_ref)
    key = _key_for(_kid_of(token), jwks)
    try:
        # algorithms=["ES256"] refuses a token naming any other algorithm,
        # "none" or an HMAC one keyed with the public key included, before
        # the key is used. iat is required but not compared with the clock:
        # expiry is what bounds a token, and a client whose clock is behind
        # the server's would otherwise refuse a token just issued.
        decoded = jwt.decode_complete(
            token,
            key,
            algorithms=["ES256"],
            issuer=issuer,
            leeway=leeway,
            options={"require": ["iss", "sub", "iat", "exp", "jti"], "verify_iat": False},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AttestationError("attestation has expired") from exc
    except jwt.ImmatureSignatureError as exc:
        raise AttestationError("attestation is not yet valid (nbf)") from exc
    except jwt.InvalidAlgorithmError as exc:
        raise AttestationError("attestation is not signed with ES256") from exc
    except jwt.InvalidSignatureError as exc:
        raise KeyMismatchError("attestation signature does not verify") from exc
    except jwt.PyJWTError as exc:
        raise AttestationError("attestation signature or claims do not verify") from exc

    # From here on the header and claims are verified.
    if decoded["header"].get("typ") != TOKEN_TYPE:
        raise AttestationError("token is not a QWED attestation")
    claims = decoded["payload"]
    qwed = claims.get("qwed")
    result = qwed.get("result") if isinstance(qwed, Mapping) else None
    if not isinstance(result, Mapping) or result.get("status") != "VERIFIED":
        raise AttestationError("attestation does not attest a VERIFIED result")
    if qwed.get("proof_hash") != proof_ref:
        raise AttestationError("attestation is for another answer (proof_ref differs)")
    if query is not None and qwed.get("query_hash") != statement_hash(query):
        raise AttestationError("attestation is for another statement (query differs)")
    return claims
