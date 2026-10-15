"""
API Key Rotation and Management Module.
Handles key expiration, rotation, and lifecycle management.

Features:
- Automatic key expiration checks
- Key rotation logic
- Notification triggers for expiring keys
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from sqlalchemy import update
from sqlmodel import Session, select

from qwed_new.auth.security import generate_api_key, mask_api_key
from qwed_new.core.alerting import alert_manager
from qwed_new.core.database import engine
from qwed_new.core.models import ApiKey

logger = logging.getLogger(__name__)

KEY_EXPIRY_DAYS = 90
ROTATION_WINDOW_DAYS = 7  # Warn 7 days before expiry


def _as_utc(value: datetime) -> datetime:
    """Interpret a naive timestamp as UTC. Older SQLModel/SQLite can read
    expires_at back without a tzinfo, so arithmetic against a timezone-aware
    now() would raise TypeError — normalise first."""
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value

class KeyManager:
    """
    Manages API key lifecycle, rotation, and security.
    """
    
    def _build_key(
        self,
        organization_id: int,
        user_id: Optional[int],
        name: Optional[str],
        expires_in_days: int,
    ) -> Tuple[ApiKey, str]:
        """Build an unsaved ApiKey and its raw secret. The caller adds and
        commits it, so create and rotate can share one transaction."""
        # Generate via the single centralized generator (issue #366) so the
        # v2 checksummed format can't drift from a second inline copy.
        raw_key, key_hash = generate_api_key()
        api_key = ApiKey(
            key_hash=key_hash,
            key_preview=mask_api_key(raw_key),
            organization_id=organization_id,
            user_id=user_id,
            name=name,
            expires_at=datetime.now(timezone.utc) + timedelta(days=expires_in_days),
            rotation_required=False,
        )
        return api_key, raw_key

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
        api_key, raw_key = self._build_key(organization_id, user_id, name, expires_in_days)
        with Session(engine) as session:
            session.add(api_key)
            session.commit()
            session.refresh(api_key)

            logger.info(f"Created API key {api_key.id} for Org {organization_id}")
            return api_key, raw_key

    def rotate_key(self, old_key_id: int) -> Tuple[Optional[ApiKey], Optional[str]]:
        """
        Rotate an existing key: revoke the old one and mint a replacement, both
        in one transaction.

        The revoke is an atomic conditional update (revoke only if the key is
        still active and not already revoked), so two concurrent rotations of the
        same key cannot both mint a replacement — only the one that flips
        is_active wins, and the loser (or a request for an already inactive or
        revoked key) mints nothing and returns (None, None). Revoke and create
        commit together, so a failure to mint the replacement rolls the revoke
        back rather than leaving the account with no active key (#452).
        """
        now = datetime.now(timezone.utc)
        with Session(engine) as session:
            # Claim the rotation. The WHERE clause is the race guard: of two
            # concurrent rotations, exactly one update matches a row.
            result = session.execute(
                update(ApiKey)
                .where(
                    ApiKey.id == old_key_id,
                    ApiKey.is_active.is_(True),
                    ApiKey.revoked_at.is_(None),
                )
                .values(is_active=False, revoked_at=now)
            )
            if result.rowcount == 0:
                # No such key, already inactive/revoked, or a concurrent rotation
                # already claimed it. Nothing committed, so nothing changes.
                return None, None
            old_key = session.get(ApiKey, old_key_id)

            # Mint the replacement in the SAME transaction, so revoke + create
            # succeed or roll back together.
            new_key, raw_new_key = self._build_key(
                old_key.organization_id, old_key.user_id,
                f"{old_key.name} (Rotated)", KEY_EXPIRY_DAYS,
            )
            session.add(new_key)
            session.commit()
            session.refresh(new_key)

        logger.info("Rotated key %d -> %d", int(old_key_id), int(new_key.id))
        return new_key, raw_new_key

    def check_expiring_keys(self):
        """
        Check for keys expiring soon and send alerts.
        Should be run as a background task.
        """
        warning_threshold = datetime.now(timezone.utc) + timedelta(days=ROTATION_WINDOW_DAYS)
        
        with Session(engine) as session:
            # Find active keys expiring soon
            expiring_keys = session.exec(
                select(ApiKey).where(
                    ApiKey.is_active == True,
                    ApiKey.expires_at <= warning_threshold,
                    ApiKey.expires_at > datetime.now(timezone.utc)
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
                        "days_remaining": (_as_utc(key.expires_at) - datetime.now(timezone.utc)).days
                    }
                )
                
                # Mark for rotation
                if not key.rotation_required:
                    key.rotation_required = True
                    session.add(key)
            
            session.commit()

key_manager = KeyManager()
