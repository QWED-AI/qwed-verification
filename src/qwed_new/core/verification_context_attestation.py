"""Sign a Verification Context document (#319).

A document's ``proof_ref`` is an unkeyed commitment: anyone can build a
document whose ``proof_ref`` resolves. ``attest_document`` adds what only
the server can: its signature over the whole document, as a v1.1 document's
``attestation``. A consumer verifies it with a key in the server's JWKS
(``qwed_sdk.attestation.verify_document_attestation``).
"""

import copy
from typing import Any, Dict, Mapping

from .attestation import get_attestation_service
from .verification_context import (
    ATTESTED_SPEC_VERSION,
    SPEC_VERSION,
    VerificationContextValidationError,
    compute_document_hash,
    validate_document,
)


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
