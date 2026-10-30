"""
Compliance Export Module for QWED.
Exports audit and security data, as CSV and JSON.

Features:
- Audit trail exports
- Security activity summary (computed from records; not a SOC 2 report)
- Security event reports
- Organization-specific data exports
- GDPR right-to-access compliance
"""

import csv
import io
import logging
from collections import Counter
from typing import Dict, Any, Optional
from datetime import datetime, timedelta, timezone
from sqlmodel import Session, select

from qwed_new.core.models import (
    VerificationLog,
    SecurityEvent,
    Organization,
    User,
    ApiKey
)
from qwed_new.core.audit_export import EXPORT_MAX_ROWS, as_utc, audit_csv, newest_logs
from qwed_new.core.audit_logger import get_audit_logger
from qwed_new.core.database import engine
from qwed_new.core.diagnostics import compute_proof_ref

logger = logging.getLogger(__name__)

# The audit-trail check lists at most this many errors in a report.
_MAX_REPORTED_ERRORS = 20

_NOT_EVERY_REQUEST = "It does not show that every request was recorded."


def _trail_scope(start_date: Optional[datetime], end_date: Optional[datetime]) -> str:
    """What the audit-trail check covered: the whole chain when no start or
    end was given (#521), otherwise the period."""
    if start_date is None and end_date is None:
        return (
            "Signature and hash-chain check of every audit entry recorded for "
            f"the organisation. {_NOT_EVERY_REQUEST}"
        )
    return (
        "Signature and hash-chain check of the audit entries recorded in "
        f"the period. {_NOT_EVERY_REQUEST}"
    )


class ComplianceExporter:
    """
    Generates audit exports, a security activity summary, and GDPR data exports.
    """
    
    @staticmethod
    def export_period(
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> tuple[datetime, datetime]:
        """The export's period with its defaults applied, in UTC: without
        ``end_date`` it ends now; without ``start_date`` it starts 30 days
        before its end. A time without a zone is read as UTC."""
        end_date = as_utc(end_date) or datetime.now(timezone.utc)
        start_date = as_utc(start_date) or end_date - timedelta(days=30)
        return start_date, end_date

    def export_audit_trail(
        self,
        organization_id: int,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        max_rows: int = EXPORT_MAX_ROWS,
    ) -> tuple[str, bool]:
        """The audit trail of a period as CSV, newest first, and whether rows
        were left out (#508).

        The period is ``export_period``'s. At most ``max_rows`` rows, the
        newest; the flag is True when more matched. The columns are
        ``AUDIT_CSV_HEADER`` (core/audit_export.py), the same as
        ``GET /audit/export``: the stored verdict and admission, the caller
        and the entry hash, with nothing cut.
        """
        start_date, end_date = self.export_period(start_date, end_date)
        with Session(engine) as session:
            logs, truncated = newest_logs(session, organization_id, start_date, end_date, max_rows)
            return audit_csv(logs), truncated

    def export_audit_trail_csv(
        self,
        organization_id: int,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> str:
        """``export_audit_trail`` without the truncation flag."""
        return self.export_audit_trail(organization_id, start_date, end_date)[0]

    def export_security_events_csv(
        self,
        organization_id: int,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> str:
        """
        Export security events as CSV.
        
        Returns:
            CSV string
        """
        if not start_date:
            start_date = datetime.now(timezone.utc) - timedelta(days=30)
        if not end_date:
            end_date = datetime.now(timezone.utc)
        
        with Session(engine) as session:
            query = select(SecurityEvent).where(
                SecurityEvent.organization_id == organization_id,
                SecurityEvent.timestamp >= start_date,
                SecurityEvent.timestamp <= end_date
            ).order_by(SecurityEvent.timestamp.desc())
            
            events = session.exec(query).all()
            
            # Generate CSV
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Header
            writer.writerow([
                'ID', 'Timestamp', 'Event Type', 'Severity',
                'Security Layer', 'Reason', 'Query Preview'
            ])
            
            # Data rows
            for event in events:
                writer.writerow([
                    event.id,
                    event.timestamp.isoformat(),
                    event.event_type,
                    event.severity,
                    event.security_layer or 'N/A',
                    event.reason[:100],
                    event.query[:50] + '...' if len(event.query) > 50 else event.query
                ])
            
            return output.getvalue()
    
    def generate_soc2_report(
        self,
        organization_id: int,
        period_days: int = 90
    ) -> Dict[str, Any]:
        """
        Generate a security activity summary (JSON) for one organisation.

        Every value is read or computed from the server's records; nothing
        is a fixed claim (#476). It is not a SOC 2 report: that is an
        auditor's attestation over a period, which the server cannot issue.
        The method and its route keep their old names for compatibility.

        Returns:
            Dictionary with activity counts and the audit-trail check
        """
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=period_days)
        
        with Session(engine) as session:
            # Get organization
            org = session.get(Organization, organization_id)
            if not org:
                raise ValueError(f"Organization {organization_id} not found")
            
            # Verification metrics
            verification_count = session.exec(
                select(VerificationLog).where(
                    VerificationLog.organization_id == organization_id,
                    VerificationLog.timestamp >= start_date
                )
            ).all()
            
            # Security events
            security_events = session.exec(
                select(SecurityEvent).where(
                    SecurityEvent.organization_id == organization_id,
                    SecurityEvent.timestamp >= start_date
                )
            ).all()
            
            # Counted by the types actually written, not an assumed "BLOCKED".
            events_by_type = dict(sorted(Counter(e.event_type for e in security_events).items()))

            # Users
            users = session.exec(
                select(User).where(User.organization_id == organization_id)
            ).all()
            
            # API keys
            api_keys = session.exec(
                select(ApiKey).where(ApiKey.organization_id == organization_id)
            ).all()
            active_keys = [k for k in api_keys if k.is_active]
            
            return {
                "report_type": "Security activity summary",
                "disclaimer": (
                    "Generated by the QWED server from its own records. "
                    "It is not a SOC 2 report or an auditor's attestation."
                ),
                "organization": {
                    "id": org.id,
                    "name": org.display_name,
                    "tier": org.tier
                },
                "period": {
                    "start": start_date.isoformat(),
                    "end": end_date.isoformat(),
                    "days": period_days
                },
                "metrics": {
                    "total_verifications": len(verification_count),
                    "security_events_detected": len(security_events),
                    "security_events_by_type": events_by_type,
                    "active_users": len([u for u in users if u.is_active]),
                    "active_api_keys": len(active_keys)
                },
                "audit_trail": self.audit_trail_check(organization_id, start_date, end_date),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "report_version": "2.0"
            }

    @staticmethod
    def audit_trail_check(
        organization_id: int,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Verify the organisation's audit entries in the period (#476).

        Used by the activity summary and by GET /admin/compliance/verify-trail
        (#485). A missing start or end leaves that side of the period open, so
        with neither the whole chain is checked. ``first_failed_entry_id`` is
        the lowest id that failed its signature or chain check.

        VERIFIED only when there are entries and every one checks out
        (signature and chain), and then with a proof_ref over the evidence
        (the range checked and its head hash). It covers the entries that
        were recorded; it cannot show that every request wrote one. Fails
        closed: if the check cannot run (for example QWED_AUDIT_SECRET_KEY is unset), the result
        is NOT_VERIFIED.
        """
        scope = _trail_scope(start_date, end_date)
        try:
            trail = get_audit_logger().verify_audit_trail(
                organization_id, start_date=start_date, end_date=end_date
            )
        except Exception as exc:  # noqa: BLE001 - any failure reports NOT_VERIFIED
            logger.warning("Audit trail check failed for org %s: %s", organization_id, type(exc).__name__)
            # Same keys as a completed check. The counts are unknown, so they
            # are None rather than 0, which would read as "no entries".
            return {
                "status": "NOT_VERIFIED",
                "proof_ref": None,
                "evidence": None,
                "scope": scope,
                "total_entries": None,
                "verified_entries": None,
                "failed_entries": None,
                "first_failed_entry_id": None,
                "legacy_entries": None,
                "errors": [f"The audit trail could not be checked ({type(exc).__name__})."],
                "total_errors": 1,
                "errors_truncated": False,
            }

        evidence = None
        proof_ref = None
        if trail["total_entries"] == 0:
            status = "NO_ENTRIES"
        elif trail["valid"] and trail.get("head_hash"):
            # VERIFIED only with a proof_ref (QWED_RULES.md section 14), bound
            # to the range checked: the head hash commits to every entry in it.
            status = "VERIFIED"
            evidence = {
                "organization_id": organization_id,
                "period_start": start_date.isoformat() if start_date else None,
                "period_end": end_date.isoformat() if end_date else None,
                "first_entry_id": trail["first_entry_id"],
                "last_entry_id": trail["last_entry_id"],
                "entries": trail["total_entries"],
                "head_hash": trail["head_hash"],
            }
            proof_ref = compute_proof_ref(evidence)
        else:
            status = "NOT_VERIFIED"
        return {
            "status": status,
            "proof_ref": proof_ref,
            "evidence": evidence,
            "scope": scope,
            "total_entries": trail["total_entries"],
            "verified_entries": trail["verified_entries"],
            "failed_entries": len(trail["failed_entries"]),
            "first_failed_entry_id": min(trail["failed_entries"], default=None),
            "legacy_entries": len(trail.get("legacy_entries", [])),
            "errors": trail["errors"][:_MAX_REPORTED_ERRORS],
            "total_errors": len(trail["errors"]),
            "errors_truncated": len(trail["errors"]) > _MAX_REPORTED_ERRORS,
        }
    
    def export_gdpr_data(
        self,
        organization_id: int
    ) -> Dict[str, Any]:
        """
        GDPR Article 15 - Right of Access.
        Export all data associated with an organization.
        
        Returns:
            Complete data export
        """
        with Session(engine) as session:
            org = session.get(Organization, organization_id)
            if not org:
                raise ValueError(f"Organization {organization_id} not found")
            
            # Get all users
            users = session.exec(
                select(User).where(User.organization_id == organization_id)
            ).all()
            
            # Get all verification logs
            logs = session.exec(
                select(VerificationLog).where(
                    VerificationLog.organization_id == organization_id
                )
            ).all()
            
            # Get all security events
            events = session.exec(
                select(SecurityEvent).where(
                    SecurityEvent.organization_id == organization_id
                )
            ).all()
            
            # Get all API keys
            api_keys = session.exec(
                select(ApiKey).where(
                    ApiKey.organization_id == organization_id
                )
            ).all()
            
            return {
                "export_type": "GDPR Article 15 - Right of Access",
                "organization": {
                    "id": org.id,
                    "name": org.display_name,
                    "tier": org.tier,
                    "created_at": org.created_at.isoformat(),
                    "is_active": org.is_active
                },
                "users": [
                    {
                        "id": u.id,
                        "email": u.email,
                        "role": u.role,
                        "created_at": u.created_at.isoformat(),
                        "is_active": u.is_active
                    } for u in users
                ],
                "verification_logs": [
                    {
                        "id": log.id,
                        "query": log.query,
                        "domain": log.domain,
                        "is_verified": log.is_verified,
                        "timestamp": log.timestamp.isoformat()
                    } for log in logs
                ],
                "security_events": [
                    {
                        "id": e.id,
                        "event_type": e.event_type,
                        "reason": e.reason,
                        "severity": e.severity,
                        "timestamp": e.timestamp.isoformat()
                    } for e in events
                ],
                "api_keys": [
                    {
                        "id": k.id,
                        "name": k.name,
                        "preview": k.key_preview,
                        "created_at": k.created_at.isoformat(),
                        "is_active": k.is_active
                    } for k in api_keys
                ],
                "export_date": datetime.now(timezone.utc).isoformat(),
                "retention_notice": "Data retained per GDPR requirements"
            }
