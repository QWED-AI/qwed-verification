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
from datetime import datetime
from typing import Any, Dict, Optional

from sqlmodel import Session, select

from qwed_new.core.database import engine
from qwed_new.core.models import VerificationLog

logger = logging.getLogger(__name__)

AUDIT_SECRET_ENV_VAR = "QWED_AUDIT_SECRET_KEY"


class AuditLogger:
    """
    Cryptographic audit logger with tamper-proof guarantees.

    Features:
    - HMAC-SHA256 signatures for each log entry
    - Hash chain linking entries together
    - Raw LLM output preservation
    - Cryptographic verification methods
    """

    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = self._resolve_secret_key(secret_key)
        self.last_hash = None
        self._last_hash_by_org: Dict[int, Optional[str]] = {}

    def log_verification(
        self,
        organization_id: int,
        user_id: Optional[int],
        query: str,
        result: Dict[str, Any],
        is_verified: bool,
        domain: str,
        raw_llm_output: Optional[str] = None,
    ) -> str:
        """
        Log a verification event with cryptographic signature.

        Returns:
            log_id: The ID of the created log entry
        """
        timestamp = datetime.utcnow()

        with Session(engine) as session:
            self._prepare_append_session(session)
            latest_log = self._get_latest_log(
                session,
                organization_id=organization_id,
                for_update=True,
            )
            previous_hash = self._extract_persisted_hash(latest_log)
            known_hash = self._last_hash_by_org.get(organization_id, previous_hash)
            if known_hash != previous_hash:
                raise SecurityError(
                    "Audit chain continuity mismatch: in-memory chain head does not match persisted audit trail"
                )

            log_data = {
                "organization_id": organization_id,
                "user_id": user_id,
                "query": query,
                "result": result,
                "is_verified": is_verified,
                "domain": domain,
                "timestamp": timestamp.isoformat(),
                "previous_hash": previous_hash,
                "raw_llm_output": raw_llm_output,
            }

            entry_hash = self._compute_hash(log_data)
            signature = self._compute_hmac(entry_hash)

            log_entry = VerificationLog(
                organization_id=organization_id,
                user_id=user_id,
                query=query,
                result=json.dumps(result),
                is_verified=is_verified,
                domain=domain,
                timestamp=timestamp,
                entry_hash=entry_hash,
                hmac_signature=signature,
                previous_hash=previous_hash,
                raw_llm_output=raw_llm_output,
            )
            session.add(log_entry)
            session.commit()
            session.refresh(log_entry)

            self._last_hash_by_org[organization_id] = entry_hash
            self.last_hash = entry_hash

            logger.info("Audit log created: %s with hash %s...", log_entry.id, entry_hash[:16])
            return str(log_entry.id)

    def _compute_hash(self, data: Dict[str, Any]) -> str:
        """Compute SHA-256 hash of log data."""
        canonical_json = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def _compute_hmac(self, message: str) -> str:
        """Compute HMAC-SHA256 signature."""
        return hmac.new(
            self.secret_key,
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _resolve_secret_key(self, secret_key: Optional[str]) -> bytes:
        """Resolve the audit signing key or fail closed."""
        configured_secret = secret_key if secret_key is not None else os.environ.get(AUDIT_SECRET_ENV_VAR)
        if not configured_secret:
            raise SecurityError(
                f"{AUDIT_SECRET_ENV_VAR} must be set before AuditLogger can initialize"
            )
        return configured_secret.encode("utf-8")

    def _prepare_append_session(self, session: Session) -> None:
        """Prepare a write session so chain-head validation and append stay serialized."""
        bind = session.get_bind()
        if bind is not None and bind.dialect.name == "sqlite":
            session.connection(execution_options={"sqlite_txn_mode": "IMMEDIATE"})

    def _get_latest_log(
        self,
        session: Session,
        organization_id: int,
        *,
        for_update: bool = False,
    ) -> Optional[VerificationLog]:
        """Return the latest persisted audit log entry for an organization, if any."""
        statement = (
            select(VerificationLog)
            .where(VerificationLog.organization_id == organization_id)
            .order_by(VerificationLog.id.desc())
        )
        bind = session.get_bind()
        if (
            for_update
            and bind is not None
            and bind.dialect.name != "sqlite"
        ):
            statement = statement.with_for_update()
        return self._run_select(session, statement).first()

    def _run_select(self, session: Session, statement):
        """Execute a SQLModel select statement."""
        return getattr(session, "exec")(statement)

    def _extract_persisted_hash(
        self,
        latest_log: Optional[VerificationLog],
    ) -> Optional[str]:
        """Return the latest persisted hash or fail if chain continuity is invalid."""
        if latest_log is None:
            return None
        if not latest_log.entry_hash:
            raise SecurityError(
                "Persisted audit trail is missing the latest entry hash; chain continuity cannot be established"
            )
        return latest_log.entry_hash

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
                "errors": ["Log entry not found"],
            }

        errors = []
        hash_valid, signature_valid = self._verify_hash_and_signature(log_entry, errors)
        prev_log = self._run_select(
            session,
            select(VerificationLog)
            .where(VerificationLog.organization_id == log_entry.organization_id)
            .where(VerificationLog.id < log_id)
            .order_by(VerificationLog.id.desc()),
        ).first()
        chain_valid = self._verify_chain_link(log_entry, prev_log, errors)

        is_valid = hash_valid and signature_valid and chain_valid

        return {
            "valid": is_valid,
            "checks": {
                "hash_valid": hash_valid,
                "signature_valid": signature_valid,
                "chain_valid": chain_valid,
            },
            "errors": errors,
            "log_id": log_id,
            "timestamp": log_entry.timestamp.isoformat(),
        }

    def _reconstruct_log_data(self, log_entry: VerificationLog) -> Dict[str, Any]:
        """Rebuild the canonical payload for integrity verification."""
        return {
            "organization_id": log_entry.organization_id,
            "user_id": log_entry.user_id,
            "query": log_entry.query,
            "result": json.loads(log_entry.result),
            "is_verified": log_entry.is_verified,
            "domain": log_entry.domain,
            "timestamp": log_entry.timestamp.isoformat(),
            "previous_hash": log_entry.previous_hash,
            "raw_llm_output": log_entry.raw_llm_output,
        }

    def _verify_hash_and_signature(
        self,
        log_entry: VerificationLog,
        errors: list[str],
    ) -> tuple[bool, bool]:
        """Verify the stored hash and HMAC for one audit row."""
        reconstructed_data = self._reconstruct_log_data(log_entry)
        expected_hash = self._compute_hash(reconstructed_data)
        hash_present = bool(log_entry.entry_hash)
        hash_valid = hash_present and expected_hash == log_entry.entry_hash

        if not hash_valid:
            if not hash_present:
                errors.append("Hash missing from audit entry")
            else:
                errors.append(
                    f"Hash mismatch: expected {expected_hash[:16]}, got {log_entry.entry_hash[:16]}"
                )

        if not hash_present:
            signature_valid = False
        else:
            expected_signature = self._compute_hmac(log_entry.entry_hash)
            signature_valid = hmac.compare_digest(
                expected_signature,
                log_entry.hmac_signature or "",
            )

        if not signature_valid:
            errors.append("HMAC signature invalid")

        return hash_valid, signature_valid

    def _verify_chain_link(
        self,
        log_entry: VerificationLog,
        prev_log: Optional[VerificationLog],
        errors: list[str],
    ) -> bool:
        """Verify that one audit entry links to the correct previous entry."""
        if prev_log is None:
            if log_entry.previous_hash is not None:
                errors.append("Hash chain broken: genesis entry must not reference a previous hash")
                return False
            return True

        if not prev_log.entry_hash:
            errors.append("Hash chain broken: previous entry is missing its hash")
            return False

        if prev_log.entry_hash != log_entry.previous_hash:
            errors.append("Hash chain broken: previous hash doesn't match")
            return False

        return True

    def verify_audit_trail(
        self,
        organization_id: int,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
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
            query = select(VerificationLog).where(
                VerificationLog.organization_id == organization_id
            )

            if start_date:
                query = query.where(VerificationLog.timestamp >= start_date)
            if end_date:
                query = query.where(VerificationLog.timestamp <= end_date)

            logs = self._run_select(session, query.order_by(VerificationLog.id)).all()

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
                "valid": verified == total,
                "total_entries": total,
                "verified_entries": verified,
                "failed_entries": failed,
                "errors": errors,
                "organization_id": organization_id,
            }


class SecurityError(Exception):
    """Raised when cryptographic verification fails."""
