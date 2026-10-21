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
from qwed_new.core.audit_logger import get_audit_logger
from qwed_new.core.database import engine

logger = logging.getLogger(__name__)

# The audit-trail check lists at most this many errors in a report.
_MAX_REPORTED_ERRORS = 20


class ComplianceExporter:
    """
    Generates audit exports, a security activity summary, and GDPR data exports.
    """
    
    def export_audit_trail_csv(
        self,
        organization_id: int,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> str:
        """
        Export audit trail as CSV for analysis.
        
        Returns:
            CSV string
        """
        if not start_date:
            start_date = datetime.now(timezone.utc) - timedelta(days=30)
        if not end_date:
            end_date = datetime.now(timezone.utc)
        
        with Session(engine) as session:
            query = select(VerificationLog).where(
                VerificationLog.organization_id == organization_id,
                VerificationLog.timestamp >= start_date,
                VerificationLog.timestamp <= end_date
            ).order_by(VerificationLog.timestamp.desc())
            
            logs = session.exec(query).all()
            
            # Generate CSV
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Header
            writer.writerow([
                'ID', 'Timestamp', 'User ID', 'Query', 'Domain',
                'Is Verified', 'HMAC Signature', 'Chain Status'
            ])
            
            # Data rows
            for log in logs:
                writer.writerow([
                    log.id,
                    log.timestamp.isoformat(),
                    log.user_id or 'N/A',
                    log.query[:100]+ '...' if len(log.query) > 100 else log.query,
                    log.domain,
                    'Yes' if log.is_verified else 'No',
                    log.hmac_signature[:16] + '...' if log.hmac_signature else 'N/A',
                    # Presence of a hash only: the export does not re-check
                    # integrity. Use /admin/compliance/verify for that.
                    'Chained' if log.entry_hash else 'Legacy'
                ])
            
            return output.getvalue()
    
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
                "audit_trail": self._audit_trail_check(organization_id, start_date, end_date),
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "report_version": "2.0"
            }

    @staticmethod
    def _audit_trail_check(
        organization_id: int, start_date: datetime, end_date: datetime
    ) -> Dict[str, Any]:
        """Verify the organisation's audit entries in the period (#476).

        VERIFIED only when there are entries and every one checks out
        (signature and chain). It covers the entries that were recorded; it
        cannot show that every request wrote one. Fails closed: if the check
        cannot run (for example QWED_AUDIT_SECRET_KEY is unset), the result
        is NOT_VERIFIED.
        """
        scope = (
            "Signature and hash-chain check of the audit entries recorded in "
            "the period. It does not show that every request was recorded."
        )
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
                "scope": scope,
                "total_entries": None,
                "verified_entries": None,
                "failed_entries": None,
                "legacy_entries": None,
                "errors": [f"The audit trail could not be checked ({type(exc).__name__})."],
                "total_errors": 1,
                "errors_truncated": False,
            }

        if trail["total_entries"] == 0:
            status = "NO_ENTRIES"
        elif trail["valid"]:
            status = "VERIFIED"
        else:
            status = "NOT_VERIFIED"
        return {
            "status": status,
            "scope": scope,
            "total_entries": trail["total_entries"],
            "verified_entries": trail["verified_entries"],
            "failed_entries": len(trail["failed_entries"]),
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
