"""
Alerting Module for QWED.
Sends security alerts via Slack, email, or other channels.

Features:
- Slack webhook integration
- Email alerts (SMTP)
- Alert throttling/deduplication
- Severity-based routing
"""

import os
import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from collections import defaultdict

try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger(__name__)


class AlertManager:
    """
    Manages security alerts and notifications.
    """
    
    def __init__(self):
        # Configuration (should be in environment variables)
        self.slack_webhook_url = os.getenv("SLACK_WEBHOOK_URL")
        self.smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.alert_email_to = os.getenv("ALERT_EMAIL_TO", "security@qwed.tech")
        
        # Alert throttling (prevent spam)
        self.recent_alerts = defaultdict(list)  # alert_key -> [timestamps]
        self.throttle_minutes = 15  # Don't repeat same alert within 15 min
    
    def send_alert(
        self,
        title: str,
        message: str,
        severity: str = "medium",
        organization_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Send security alert via configured channels.
        
        Args:
            title: Alert title
            message: Alert message
            severity: low, medium, high, critical
            organization_id: Affected organization
            details: Additional context
        """
        # Check throttling
        alert_key = f"{title}:{organization_id}"
        if self._is_throttled(alert_key):
            logger.info(f"Alert throttled: {title}")
            return
        
        # Format alert
        alert_data = {
            "title": title,
            "message": message,
            "severity": severity.upper(),
            "organization_id": organization_id,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details or {}
        }
        
        # Send via all configured channels
        if severity in ["high", "critical"]:
            self._send_slack(alert_data)
            self._send_email(alert_data)
        elif severity == "medium":
            self._send_slack(alert_data)
        
        # Track alert
        self.recent_alerts[alert_key].append(datetime.utcnow())
        logger.info(f"Alert sent: {title} (severity: {severity})")
    
    def _is_throttled(self, alert_key: str) -> bool:
        """Check if alert should be throttled."""
        cutoff = datetime.utcnow() - timedelta(minutes=self.throttle_minutes)
        recent = [t for t in self.recent_alerts[alert_key] if t > cutoff]
        self.recent_alerts[alert_key] = recent
        return len(recent) > 0
    
    def _send_slack(self, alert_data: Dict[str, Any]):
        """Send alert to Slack via webhook."""
        if not self.slack_webhook_url or not requests:
            logger.warning("Slack webhook not configured or requests library missing")
            return
        
        # Format Slack message
        severity_emoji = {
            "LOW": ":information_source:",
            "MEDIUM": ":warning:",
            "HIGH": ":rotating_light:",
            "CRITICAL": ":fire:"
        }
        
        emoji = severity_emoji.get(alert_data["severity"], ":bell:")
        
        slack_message = {
            "text": f"{emoji} *Security Alert: {alert_data['title']}*",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji} {alert_data['title']}"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Severity:*\n{alert_data['severity']}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Org ID:*\n{alert_data['organization_id'] or 'N/A'}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Time:*\n{alert_data['timestamp']}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Message:*\n{alert_data['message']}"
                    }
                }
            ]
        }
        
        # Add details if present
        if alert_data["details"]:
            details_text = "\n".join([f"• {k}: {v}" for k, v in alert_data["details"].items()])
            slack_message["blocks"].append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Details:*\n{details_text}"
                }
            })
        
        try:
            response = requests.post(
                self.slack_webhook_url,
                json=slack_message,
                timeout=5
            )
            response.raise_for_status()
            logger.info("Slack alert sent successfully")
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
    
    def _send_email(self, alert_data: Dict[str, Any]):
        """Send alert via email."""
        if not self.smtp_user or not self.smtp_password:
            logger.warning("Email not configured (SMTP credentials missing)")
            return
        
        # Create email
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"[QWED Security] {alert_data['severity']}: {alert_data['title']}"
        msg['From'] = self.smtp_user
        msg['To'] = self.alert_email_to
        
        # HTML body
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <h2 style="color: {'#d9534f' if alert_data['severity'] == 'CRITICAL' else '#f0ad4e'};">
                Security Alert: {alert_data['title']}
            </h2>
            <p><strong>Severity:</strong> {alert_data['severity']}</p>
            <p><strong>Organization ID:</strong> {alert_data['organization_id'] or 'N/A'}</p>
            <p><strong>Timestamp:</strong> {alert_data['timestamp']}</p>
            <hr>
            <h3>Message:</h3>
            <p>{alert_data['message']}</p>
        """
        
        if alert_data["details"]:
            html_body += "<h3>Details:</h3><ul>"
            for k, v in alert_data["details"].items():
                html_body += f"<li><strong>{k}:</strong> {v}</li>"
            html_body += "</ul>"
        
        html_body += """
            <hr>
            <p style="color: #666; font-size: 12px;">
                This is an automated security alert from QWED.<br>
                Do not reply to this email.
            </p>
        </body>
        </html>
        """
        
        html_part = MIMEText(html_body, 'html')
        msg.attach(html_part)
        
        # Send email
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            logger.info(f"Email alert sent to {self.alert_email_to}")
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")


# Global alert manager instance
alert_manager = AlertManager()
