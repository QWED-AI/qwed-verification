"""Verify a QWED attestation (#319).

A VERIFIED answer from a QWED server carries ``attestation``: an ES256 JWT
the server signed after checking the verdict. Verifying it shows that server
issued a VERIFIED verdict for this answer's ``proof_ref`` (and, when you pass
it, for this statement). It covers only what the token signs: the status,
``proof_ref``, statement hash and, on a route that decides one, the
admission; not other fields of the response such as ``agent_message``. What
is checked:

- the signature, with an ES256 key in the server's JWKS
  (``GET /.well-known/jwks.json``), and that the verified header's ``kid``
  names that key;
- the issuer, and that the token has not expired (nor is used before any
  ``nbf`` it carries);
- that it attests a VERIFIED result;
- that its ``proof_hash`` is the answer's ``proof_ref``, so it is this
  answer's token;
- optionally, that its ``query_hash`` is the SHA-256 of the statement the
  verdict covers: the query you sent (for natural language, the translated
  expression the server reports);
- on a route that decides an admission, the token signs it too
  (``qwed.admission``, #321): the client checks it is the answer's
  ``admission``, so the server's ADMIT or BLOCKED is verified as well.

A token says the server reached the verdict and, where it signs one, the
admission; act on the admission. Fetching the JWKS from the server you asked
trusts that server's TLS; to verify offline or against a pinned key, pass
the JWKS you hold.

A Verification Context document the server issued (spec v1.1) carries its
own ``attestation``, a token of type ``qwed-context+jwt`` that signs every
other field of the document; ``verify_document_attestation`` checks it
(#319).
"""

import hashlib
from collections.abc import Mapping
from typing import Any

import jwt

# The issuer a QWED server signs as.
DEFAULT_ISSUER = "did:qwed:node:local"
TOKEN_TYPE = "qwed-attestation+jwt"
CONTEXT_TOKEN_TYPE = "qwed-context+jwt"
JWKS_PATH = "/.well-known/jwks.json"


class AttestationError(Exception):
    """The attestation does not verify, or does not attest this answer."""


class KeyMismatchError(AttestationError):
    """No key in the JWKS held verifies the token's signature, so fetching
    the JWKS again may help: the key may have rotated, or the server
    restarted with a new ephemeral key under the same kid."""


class KeysUnavailableError(AttestationError):
    """The server's keys could not be fetched, so nothing can be verified;
    the clients ask again at most once every 30 seconds."""


def require_answer(token: Any, proof_ref: Any) -> None:
    """Raise AttestationError unless there is a token and a proof_ref to
    bind it to; checked before any key is fetched."""
    if not isinstance(token, str) or not token:
        raise AttestationError("no attestation")
    if not isinstance(proof_ref, str) or not proof_ref:
        raise AttestationError("no proof_ref to bind the attestation to")


def _es256_keys(jwks: Mapping[str, Any]) -> list[tuple[Any, Any]]:
    """The usable ES256 P-256 keys in ``jwks``, each with its kid. Keys of
    any other type, and broken ones, are skipped. A JWKS with no ES256 key
    may be out of date; one whose only ES256 keys are broken is refused."""
    keys = jwks.get("keys") if isinstance(jwks, Mapping) else None
    if not isinstance(keys, list):
        raise AttestationError("JWKS has no keys")
    found, unusable = [], False
    for jwk in keys:
        if not isinstance(jwk, Mapping) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" \
                or jwk.get("alg", "ES256") != "ES256":
            continue
        try:
            found.append((jwk.get("kid"), jwt.PyJWK(dict(jwk), algorithm="ES256").key))
        except jwt.PyJWTError:
            unusable = True
    if not found and unusable:
        raise AttestationError("JWKS key is unusable")
    if not found:
        raise KeyMismatchError("JWKS has no ES256 P-256 key")
    return found


def _decode(token: str, key: Any, *, issuer: str, leeway: int) -> dict[str, Any] | None:
    """The verified header and claims, or None if ``key`` did not sign the
    token. Every other failure raises AttestationError."""
    try:
        # algorithms=["ES256"] refuses a token naming any other algorithm,
        # "none" or an HMAC one keyed with the public key included, before
        # the key is used. iat is required but not compared with the clock:
        # expiry is what bounds a token, and a client whose clock is behind
        # the server's would otherwise refuse a token just issued.
        # jwt.decode_complete is exported only from PyJWT 2.10; the PyJWT
        # class has it from 2.0, and the floor is 2.8 (#517 review).
        return jwt.PyJWT().decode_complete(
            token,
            key,
            algorithms=["ES256"],
            issuer=issuer,
            leeway=leeway,
            options={"require": ["iss", "sub", "iat", "exp", "jti"], "verify_iat": False},
        )
    except jwt.InvalidSignatureError:
        return None
    except jwt.ExpiredSignatureError as exc:
        raise AttestationError("attestation has expired") from exc
    except jwt.ImmatureSignatureError as exc:
        raise AttestationError("attestation is not yet valid (nbf)") from exc
    except jwt.InvalidAlgorithmError as exc:
        raise AttestationError("attestation is not signed with ES256") from exc
    except jwt.DecodeError as exc:
        raise AttestationError("attestation is not a JWT") from exc
    except jwt.PyJWTError as exc:
        raise AttestationError("attestation signature or claims do not verify") from exc
    except RecursionError as exc:
        # A header or payload nested too deeply for the JSON parser.
        raise AttestationError("attestation is not a JWT") from exc


def check_admission(claims: Mapping[str, Any], admission: str | None) -> None:
    """Raise AttestationError unless the verified ``claims`` sign
    ``admission``: the answer's ``admission`` (#321), or None for an answer
    that carries none, whose token must then sign none."""
    qwed = claims.get("qwed")
    signed = qwed.get("admission") if isinstance(qwed, Mapping) else None
    if signed != admission:
        raise AttestationError("attestation is for another admission (admission differs)")


# verify_attestation's ``admission`` when the caller gives none: not checked.
# None is a value, the admission of an answer that carries none (#514 review).
_UNCHECKED: Any = object()


def _verified_claims(
    token: str, jwks: Mapping[str, Any], *, issuer: str, leeway: int, token_type: str,
) -> dict[str, Any]:
    """The claims of ``token``, verified with a key in ``jwks`` and of type
    ``token_type``; raise AttestationError otherwise."""
    # A compact JWT is base64url, so ASCII. PyJWT encodes the token as UTF-8
    # first, and an unpaired surrogate raised UnicodeEncodeError, not an
    # AttestationError (#523 review).
    if not token.isascii():
        raise AttestationError("attestation is not a JWT")
    # Nothing from the token is read before its signature verifies: each
    # ES256 key the JWKS holds (one, or two during a rotation) is tried, and
    # the verified header must then name the key that verified it.
    for kid, key in _es256_keys(jwks):
        decoded = _decode(token, key, issuer=issuer, leeway=leeway)
        if decoded is not None:
            break
    else:
        raise KeyMismatchError("attestation signature does not verify with any JWKS key")

    # From here on the header and claims are verified.
    header = decoded["header"]
    if not isinstance(header.get("kid"), str) or not header["kid"]:
        raise AttestationError("token header names no key (kid)")
    if header["kid"] != kid:
        raise AttestationError("token header's kid does not name the key that signed it")
    if header.get("typ") != token_type:
        raise AttestationError(f"token is not a QWED attestation of type {token_type}")
    # A QWED server names no critical extension; one it does not understand
    # must not be ignored (RFC 7515 section 4.1.11). PyJWT before 2.12 does
    # not refuse them itself, and the floor is 2.8 (#517 review).
    if "crit" in header:
        raise AttestationError("token names a critical header extension this client does not support")
    return decoded["payload"]


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
    admission: str | None = _UNCHECKED,
) -> dict[str, Any]:
    """Verify ``token`` as the attestation of the answer whose ``proof_ref``
    is given, and return its claims; raise AttestationError otherwise.

    ``query``, when given, must be the statement the verdict covers.
    ``leeway`` is the clock skew allowed on expiry, in seconds.
    ``admission``, when given, must be the admission the token signs (the
    answer's ``admission``, #321): ``None`` too, for an answer that carries
    none, whose token must then sign none. See ``check_admission``.
    """
    require_answer(token, proof_ref)
    claims = _verified_claims(token, jwks, issuer=issuer, leeway=leeway, token_type=TOKEN_TYPE)
    qwed = claims.get("qwed")
    result = qwed.get("result") if isinstance(qwed, Mapping) else None
    if not isinstance(result, Mapping) or result.get("status") != "VERIFIED":
        raise AttestationError("attestation does not attest a VERIFIED result")
    if qwed.get("proof_hash") != proof_ref:
        raise AttestationError("attestation is for another answer (proof_ref differs)")
    if query is not None and qwed.get("query_hash") != statement_hash(query):
        raise AttestationError("attestation is for another statement (query differs)")
    if admission is not _UNCHECKED:
        check_admission(claims, admission)
    return claims


def document_attestation(document: Any) -> str | None:
    """The ``attestation`` a Verification Context document carries, or None
    if it carries none (a v1.0 document, or not a document)."""
    token = document.get("attestation") if isinstance(document, Mapping) else None
    return token if isinstance(token, str) and token else None


def verify_document_attestation(
    document: Mapping[str, Any],
    jwks: Mapping[str, Any],
    *,
    issuer: str = DEFAULT_ISSUER,
    leeway: int = 0,
) -> dict[str, Any]:
    """Verify the ``attestation`` of a Verification Context ``document``
    (spec v1.1) and return its claims; raise AttestationError otherwise
    (#319).

    The token must verify with a key in ``jwks``, be a document's
    (``qwed-context+jwt``, ``qwed.version`` "1.1"), and sign this document:
    the hash of all of it but the token (as ``sub`` and
    ``qwed.document_hash``), and its verdict, admission and ``proof_ref``. It shows
    the server issued this document unchanged; it adds nothing to the
    verdict or the admission, and does not check the schema or that
    ``proof_ref`` resolves (the server's validate and resolve, and the
    ``qwed context`` commands, do).
    """
    # Imported here: qwed_new is the same distribution, but loading it is
    # needed only for a document.
    from qwed_new.core.verification_context import document_attestation_mismatch

    token = document_attestation(document)
    if token is None:
        raise AttestationError("no attestation")
    claims = _verified_claims(token, jwks, issuer=issuer, leeway=leeway, token_type=CONTEXT_TOKEN_TYPE)
    mismatch = document_attestation_mismatch(document, claims)
    if mismatch is not None:
        raise AttestationError(mismatch)
    return claims
