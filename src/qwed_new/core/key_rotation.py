"""
API Key Rotation and Management Module.
Handles key expiration, rotation, and lifecycle management.

Features:
- Automatic key expiration checks
- Key rotation logic
- Notification triggers for expiring keys
"""

import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Tuple
from sqlmodel import select

from qwed_new.core.models import ApiKey, User
from qwed_new.core.database import engine
from sqlmodel import Session
from qwed_new.core.alerting import alert_manager

logger = logging.getLogger(__name__)

KEY_EXPIRY_DAYS = 90
ROTATION_WINDOW_DAYS = 7  # Warn 7 days before expiry

class KeyManager:
    """
    Manages API key lifecycle, rotation, and security.
    """
    
    def create_key(
        self, 
        organization_id: int, 
        user_id: Optional[int] = None,
        name: Optional[str] = None,
        expires_in_days: int = KEY_EXPIRY_DAYS
    ) -> Tuple[ApiKey, str]:
        """
        Create a new API key.
        Returns (ApiKey object, raw_key_string).
        """
        # Generate secure random key
        raw_key = f"qwed_live_{secrets.token_urlsafe(32)}"
        
        # Hash for storage
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        key_preview = f"{raw_key[:10]}...{raw_key[-4:]}"
        
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
        
        with Session(engine) as session:
            api_key = ApiKey(
                key_hash=key_hash,
                key_preview=key_preview,
                organization_id=organization_id,
                user_id=user_id,
                name=name,
                expires_at=expires_at,
                rotation_required=False
            )
            session.add(api_key)
            session.commit()
            session.refresh(api_key)
            
            logger.info(f"Created API key {api_key.id} for Org {organization_id}")
            return api_key, raw_key

    def rotate_key(self, old_key_id: int) -> Tuple[Optional[ApiKey], Optional[str]]:
        """
        Rotate an existing key: create new one, mark old as revoked.
        """
        with Session(engine) as session:
            old_key = session.get(ApiKey, old_key_id)
            if not old_key:
                return None, None
            
            # Create new key with same ownership
            new_key, raw_new_key = self.create_key(
                organization_id=old_key.organization_id,
                user_id=old_key.user_id,
                name=f"{old_key.name} (Rotated)",
                expires_in_days=KEY_EXPIRY_DAYS
            )
            
            # Revoke old key
            old_key.is_active = False
            old_key.revoked_at = datetime.utcnow()
            session.add(old_key)
            session.commit()
            
            logger.info(f"Rotated key {old_key_id} -> {new_key.id}")
            return new_key, raw_new_key

    def check_expiring_keys(self):
        """
        Check for keys expiring soon and send alerts.
        Should be run as a background task.
        """
        warning_threshold = datetime.utcnow() + timedelta(days=ROTATION_WINDOW_DAYS)
        
        with Session(engine) as session:
            # Find active keys expiring soon
            expiring_keys = session.exec(
                select(ApiKey).where(
                    ApiKey.is_active == True,
                    ApiKey.expires_at <= warning_threshold,
                    ApiKey.expires_at > datetime.utcnow()
                )
            ).all()
            
            for key in expiring_keys:
                # Trigger alert
                alert_manager.send_alert(
                    title="API Key Expiring Soon",
                    message=f"API Key {key.key_preview} expires on {key.expires_at}",
                    severity="medium",
                    organization_id=key.organization_id,
                    details={
                        "key_id": key.id,
                        "expires_at": str(key.expires_at),
                        "days_remaining": (key.expires_at - datetime.utcnow()).days
                    }
                )
                
                # Mark for rotation
                if not key.rotation_required:
                    key.rotation_required = True
                    session.add(key)
            
            session.commit()

key_manager = KeyManager()
