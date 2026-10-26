"""Sign a Verification Context document (#319).

A document's ``proof_ref`` is an unkeyed commitment: anyone can build a
document whose ``proof_ref`` resolves. ``attest_document`` adds what only
the server can: its signature over every other field of the document, as
a v1.1 document's ``attestation``. A consumer verifies it with a key in the
server's JWKS (``qwed_sdk.attestation.verify_document_attestation``).
"""

import copy
from typing import Any, Dict, Mapping, Optional

from .attestation import CONTEXT_TOKEN_TYPE, get_attestation_service
from .verification_context import (
    ATTESTED_SPEC_VERSION,
    SPEC_VERSION,
    VerificationContextValidationError,
    compute_document_hash,
    document_attestation_mismatch,
    validate_document,
)

# Why a document's attestation is refused, as validate and resolve report
# it (#319): it has none, or it does not verify or is not this document's.
ATTESTATION_REQUIRED = "attestation_required"
ATTESTATION_INVALID = "attestation_invalid"


def attest_document(document: Mapping[str, Any]) -> Dict[str, Any]:
    """The v1.1 form of a valid v1.0 ``document``, signed by this server.

    The document is checked first (VerificationContextValidationError if
    it is not valid v1.0), then its version becomes 1.1 and the server
    signs its ``compute_document_hash`` with its verdict, admission and
    ``proof_ref``. The signature authenticates the document as this
    server's; it adds nothing to the verdict or the admission. A failure to
    sign raises (the service's error, or ValueError), and is not a document
    without a signature.
    """
    validate_document(document)
    if document.get("spec_version") != SPEC_VERSION:
        raise VerificationContextValidationError(
            f"only a v{SPEC_VERSION} document can be attested"
        )
    signed = copy.deepcopy(dict(document))
    signed["spec_version"] = ATTESTED_SPEC_VERSION
    context = signed["context"]
    signed["attestation"] = get_attestation_service().create_context_attestation(
        document_hash=compute_document_hash(signed),
        verdict=signed["verdict"],
        admission=context["decision"]["admission"],
        proof_ref=context["evidence"]["proof_ref"],
    )
    validate_document(signed)
    return signed


def document_attestation_refusal(document: Any) -> Optional[str]:
    """None if ``document`` carries an attestation that this server's key
    verifies and that signs this document; otherwise why not,
    ATTESTATION_REQUIRED or ATTESTATION_INVALID (#319).

    The checks are those of spec v1.1 section 4, as the SDK makes them
    (``qwed_sdk.attestation.verify_document_attestation``), against this
    server's key rather than a JWKS. A document this server signed with a
    key it no longer holds (a restart without a configured key, or a
    rotation) is ATTESTATION_INVALID. The service's own failure to load its
    key raises.
    """
    token = document.get("attestation") if isinstance(document, Mapping) else None
    if not isinstance(token, str) or not token:
        return ATTESTATION_REQUIRED
    is_valid, claims, _error = get_attestation_service().verify_attestation(
        token, token_type=CONTEXT_TOKEN_TYPE,
    )
    if not is_valid or document_attestation_mismatch(document, claims) is not None:
        return ATTESTATION_INVALID
    return None
