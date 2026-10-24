"""The server's public attestation key, as a JWKS (#319).

Every VERIFIED response carries its attestation, an ES256 JWT. A consumer
checks it with the key published here: the token header's ``kid`` names the
key, and the token's ``iss`` is the issuer below. Public, with no key
material beyond the public key, so it needs no API key.

With a generated ("ephemeral") key this shows the current process's key,
which changes on a restart and differs between replicas; configure
``QWED_SIGNING_KEY`` or ``QWED_SIGNING_KEY_FILE`` for a key that does not.
Kept out of api/main.py, which is at the size limit of the deterministic
security scan.
"""

from typing import Any

from fastapi import APIRouter, HTTPException, Response

from qwed_new.core.attestation import get_attestation_service

router = APIRouter(tags=["Attestation"])

# Short, so a rotated key reaches consumers within minutes.
_CACHE_CONTROL = "public, max-age=300"


@router.get(
    "/.well-known/jwks.json",
    responses={503: {"description": "Attestation key unavailable"}},
)
def attestation_jwks(response: Response) -> dict[str, Any]:
    """The public key that verifies the server's attestations (RFC 7517)."""
    try:
        service = get_attestation_service()
        info = service.get_issuer_info()
    except (RuntimeError, ValueError):
        # AttestationConfigError (a RuntimeError), or no crypto package. The
        # key is loaded at startup, so this is not expected; never say why,
        # and never serve a key that is not the one in use.
        raise HTTPException(status_code=503, detail="attestation key unavailable") from None
    keys = [{**jwk, "alg": "ES256", "use": "sig"} for jwk in info["public_keys"]]
    response.headers["Cache-Control"] = _CACHE_CONTROL
    return {"keys": keys}
