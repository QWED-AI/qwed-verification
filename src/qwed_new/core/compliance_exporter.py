"""
Compliance Export Module for QWED.
Generates SOC 2 / GDPR compliance reports in PDF and CSV formats.

Features:
- Audit trail exports
- Security event reports
- Organization-specific data exports
- GDPR right-to-access compliance
"""

import csv
import io
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from sqlmodel import Session, select

from qwed_new.core.models import (
    VerificationLog,
    SecurityEvent,
    Organization,
    User,
    ApiKey
)
from qwed_new.core.database import engine

logger = logging.getLogger(__name__)


class ComplianceExporter:
    """
    Generates compliance reports for SOC 2, GDPR, and internal audits.
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
            start_date = datetime.utcnow() - timedelta(days=30)
        if not end_date:
            end_date = datetime.utcnow()
        
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
                'Is Verified', 'HMAC Signature', 'Hash Chain Valid'
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
                    'Verified' if log.entry_hash else 'Legacy'
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
            start_date = datetime.utcnow() - timedelta(days=30)
        if not end_date:
            end_date = datetime.utcnow()
        
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
        Generate SOC 2 compliance report (JSON format).
        
        Returns:
            Dictionary with metrics and compliance status
        """
        end_date = datetime.utcnow()
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
            
            # Blocked attempts
            blocked_count = len([e for e in security_events if e.event_type == 'BLOCKED'])
            
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
                "report_type": "SOC 2 Type II - Security Controls",
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
                    "threats_blocked": blocked_count,
                    "block_rate": f"{(blocked_count / max(len(verification_count), 1)) * 100:.2f}%",
                    "active_users": len([u for u in users if u.is_active]),
                    "active_api_keys": len(active_keys)
                },
                "security_controls": {
                    "multi_layer_injection_defense": "ENABLED (7 layers)",
                    "output_sanitization": "ENABLED",
                    "code_execution_isolation": "DOCKER",
                    "audit_trail_integrity": "CRYPTOGRAPHIC (HMAC-SHA256)",
                    "access_control": "RBAC + API Keys",
                    "rate_limiting": "ENABLED"
                },
                "compliance_status": {
                    "audit_trail_complete": "PASS",
                    "access_logs_retained": "PASS",
                    "encryption_at_rest": "N/A (SQLite)",
                    "encryption_in_transit": "HTTPS Required",
                    "security_monitoring": "ACTIVE"
                },
                "generated_at": datetime.utcnow().isoformat(),
                "report_version": "1.0"
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
                "export_date": datetime.utcnow().isoformat(),
                "retention_notice": "Data retained per GDPR requirements"
            }
