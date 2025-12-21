"""
Cryptographic Audit Logger for QWED.
Provides tamper-proof audit logging with HMAC signatures and hash chains.

SOC 2 / GDPR Compliance Features:
- Immutable audit trail
- Cryptographic integrity verification
- Raw LLM output preservation
- Timestamp verification
"""

import hashlib
import hmac
import json
import logging
import os
from typing import Any, Dict, Optional
from datetime import datetime
from sqlmodel import Session

from qwed_new.core.models import VerificationLog
from qwed_new.core.database import engine

logger = logging.getLogger(__name__)

# Secret key for HMAC - MUST be set in production via environment variable
AUDIT_SECRET_KEY = os.environ.get("QWED_AUDIT_SECRET_KEY", "dev_only_change_in_production")
if AUDIT_SECRET_KEY == "dev_only_change_in_production":
    logger.warning("⚠️ QWED_AUDIT_SECRET_KEY not set! Using insecure default. Set this in production!")



class AuditLogger:
    """
    Cryptographic audit logger with tamper-proof guarantees.
    
    Features:
    - HMAC-SHA256 signatures for each log entry
    - Hash chain linking entries together
    - Raw LLM output preservation
    - Cryptographic verification methods
    """
    
    def __init__(self, secret_key: str = AUDIT_SECRET_KEY):
        self.secret_key = secret_key.encode('utf-8')
        self.last_hash = None  # For hash chain
    
    def log_verification(
        self,
        organization_id: int,
        user_id: Optional[int],
        query: str,
        result: Dict[str, Any],
        is_verified: bool,
        domain: str,
        raw_llm_output: Optional[str] = None
    ) -> str:
        """
        Log a verification event with cryptographic signature.
        
        Returns:
            log_id: The ID of the created log entry
        """
        timestamp = datetime.utcnow()
        
        # Prepare data for hashing
        log_data = {
            "organization_id": organization_id,
            "user_id": user_id,
            "query": query,
            "result": result,
            "is_verified": is_verified,
            "domain": domain,
            "timestamp": timestamp.isoformat(),
            "previous_hash": self.last_hash
        }
        
        # Generate hash of this entry
        entry_hash = self._compute_hash(log_data)
        
        # Generate HMAC signature
        signature = self._compute_hmac(entry_hash)
        
        # Store in database
        with Session(engine) as session:
            log_entry = VerificationLog(
                organization_id=organization_id,
                user_id=user_id,
                query=query,
                result=json.dumps(result),
                is_verified=is_verified,
                domain=domain,
                timestamp=timestamp,
                # Crypto fields (these need to be added to the model)
                entry_hash=entry_hash,
                hmac_signature=signature,
                previous_hash=self.last_hash,
                raw_llm_output=raw_llm_output
            )
            session.add(log_entry)
            session.commit()
            session.refresh(log_entry)
            
            # Update last hash for chain
            self.last_hash = entry_hash
            
            logger.info(f"Audit log created: {log_entry.id} with hash {entry_hash[:16]}...")
            return str(log_entry.id)
    
    def _compute_hash(self, data: Dict[str, Any]) -> str:
        """Compute SHA-256 hash of log data."""
        # Serialize to canonical JSON (sorted keys)
        canonical_json = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()
    
    def _compute_hmac(self, message: str) -> str:
        """Compute HMAC-SHA256 signature."""
        return hmac.new(
            self.secret_key,
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    
    def verify_log_entry(self, log_id: int, session: Session) -> Dict[str, Any]:
        """
        Verify the cryptographic integrity of a log entry.
        
        Returns:
            {
                "valid": bool,
                "checks": {
                    "hash_valid": bool,
                    "signature_valid": bool,
                    "chain_valid": bool
                },
                "errors": list[str]
            }
        """
        log_entry = session.get(VerificationLog, log_id)
        if not log_entry:
            return {
                "valid": False,
                "checks": {},
                "errors": ["Log entry not found"]
            }
        
        errors = []
        
        # 1. Verify hash
        reconstructed_data = {
            "organization_id": log_entry.organization_id,
            "user_id": log_entry.user_id,
            "query": log_entry.query,
            "result": json.loads(log_entry.result),
            "is_verified": log_entry.is_verified,
            "domain": log_entry.domain,
            "timestamp": log_entry.timestamp.isoformat(),
            "previous_hash": log_entry.previous_hash
        }
        expected_hash = self._compute_hash(reconstructed_data)
        hash_valid = (expected_hash == log_entry.entry_hash)
        
        if not hash_valid:
            errors.append(f"Hash mismatch: expected {expected_hash[:16]}, got {log_entry.entry_hash[:16]}")
        
        # 2. Verify HMAC signature
        expected_signature = self._compute_hmac(log_entry.entry_hash)
        signature_valid = (expected_signature == log_entry.hmac_signature)
        
        if not signature_valid:
            errors.append("HMAC signature invalid")
        
        # 3. Verify chain (check if previous log's hash matches)
        chain_valid = True
        if log_entry.previous_hash:
            # Find previous log entry
            from sqlmodel import select
            prev_log = session.exec(
                select(VerificationLog)
                .where(VerificationLog.id < log_id)
                .order_by(VerificationLog.id.desc())
            ).first()
            
            if prev_log and prev_log.entry_hash != log_entry.previous_hash:
                chain_valid = False
                errors.append("Hash chain broken: previous hash doesn't match")
        
        is_valid = hash_valid and signature_valid and chain_valid
        
        return {
            "valid": is_valid,
            "checks": {
                "hash_valid": hash_valid,
                "signature_valid": signature_valid,
                "chain_valid": chain_valid
            },
            "errors": errors,
            "log_id": log_id,
            "timestamp": log_entry.timestamp.isoformat()
        }
    
    def verify_audit_trail(
        self,
        organization_id: int,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Verify the entire audit trail for an organization.
        
        Returns:
            {
                "valid": bool,
                "total_entries": int,
                "verified_entries": int,
                "failed_entries": list[int],
                "errors": list[str]
            }
        """
        with Session(engine) as session:
            from sqlmodel import select
            
            query = select(VerificationLog).where(
                VerificationLog.organization_id == organization_id
            )
            
            if start_date:
                query = query.where(VerificationLog.timestamp >= start_date)
            if end_date:
                query = query.where(VerificationLog.timestamp <= end_date)
            
            logs = session.exec(query.order_by(VerificationLog.id)).all()
            
            total = len(logs)
            verified = 0
            failed = []
            errors = []
            
            for log in logs:
                result = self.verify_log_entry(log.id, session)
                if result["valid"]:
                    verified += 1
                else:
                    failed.append(log.id)
                    errors.extend(result["errors"])
            
            return {
                "valid": (verified == total),
                "total_entries": total,
                "verified_entries": verified,
                "failed_entries": failed,
                "errors": errors,
                "organization_id": organization_id
            }


class SecurityError(Exception):
    """Raised when cryptographic verification fails."""
    pass
