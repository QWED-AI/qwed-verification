import jwt
import time
import json
import hashlib
from typing import Dict, Any, Optional

class AttestationGuard:
    """
    Generates cryptographic proofs (JWTs) for verification results.
    Acts as a 'Digital Notary' for AI safety checks.
    """
    def __init__(self, secret_key: str = "default-dev-secret-do-not-use-in-prod"):
        self.secret = secret_key

    def sign_verification(self, input_query: str, guard_result: Dict[str, Any], engine: str = "QWED-Deterministic-v1") -> str:
        """
        Creates a JWT attesting that a specific verification occurred.
        Source: QWED Features list.
        """
        # Create a hash of the input query to link it to the result without storing PII
        query_hash = hashlib.sha256(input_query.encode('utf-8')).hexdigest()
        
        payload = {
            "timestamp": time.time(),
            "query_hash": query_hash,
            "verification_result": guard_result.get("verified", False),
            "engine": engine,
            "details": guard_result,
            "iss": "qwed-attestation-service"
        }
        
        # Sign with HS256 (HMAC with SHA-256)
        token = jwt.encode(payload, self.secret, algorithm="HS256")
        return token

    def verify_attestation(self, token: str) -> Dict[str, Any]:
        """
        Verifies a QWED attestation token.
        """
        try:
            return jwt.decode(token, self.secret, algorithms=["HS256"])
        except jwt.InvalidTokenError as e:
            return {"valid": False, "error": f"Invalid signature or token: {str(e)}"}
