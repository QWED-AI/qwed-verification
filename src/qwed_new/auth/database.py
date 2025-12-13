"""
In-memory database for authentication.
TODO: Replace with PostgreSQL/SQLite for production.
"""
from datetime import datetime
from typing import Optional, List
import uuid

# In-memory storage (replace with real DB later)
organizations_db = {}
users_db = {}
api_keys_db = {}

# Indexes for fast lookups
users_by_email = {}
api_keys_by_hash = {}

def create_organization(name: str, subscription_tier: str = "free") -> dict:
    """Create a new organization."""
    org_id = str(uuid.uuid4())
    org = {
        "id": org_id,
        "name": name,
        "subscription_tier": subscription_tier,
        "created_at": datetime.utcnow()
    }
    organizations_db[org_id] = org
    return org

def create_user(email: str, password_hash: str, org_id: str, role: str = "member") -> dict:
    """Create a new user."""
    user_id = str(uuid.uuid4())
    user = {
        "id": user_id,
        "email": email,
        "password_hash": password_hash,
        "org_id": org_id,
        "role": role,
        "created_at": datetime.utcnow(),
        "is_active": True
    }
    users_db[user_id] = user
    users_by_email[email] = user
    return user

def get_user_by_email(email: str) -> Optional[dict]:
    """Get user by email."""
    return users_by_email.get(email)

def get_user_by_id(user_id: str) -> Optional[dict]:
    """Get user by ID."""
    return users_db.get(user_id)

def create_api_key(key_hash: str, user_id: str, org_id: str, name: str) -> dict:
    """Create a new API key."""
    key_id = str(uuid.uuid4())
    api_key = {
        "id": key_id,
        "key_hash": key_hash,
        "user_id": user_id,
        "org_id": org_id,
        "name": name,
        "created_at": datetime.utcnow(),
        "last_used_at": None,
        "revoked_at": None
    }
    api_keys_db[key_id] = api_key
    api_keys_by_hash[key_hash] = api_key
    return api_key

def get_api_key_by_hash(key_hash: str) -> Optional[dict]:
    """Get API key by hash."""
    return api_keys_by_hash.get(key_hash)

def get_user_api_keys(user_id: str) -> List[dict]:
    """Get all API keys for a user."""
    return [key for key in api_keys_db.values() if key["user_id"] == user_id]

def revoke_api_key(key_id: str) -> bool:
    """Revoke an API key."""
    if key_id in api_keys_db:
        api_keys_db[key_id]["revoked_at"] = datetime.utcnow()
        return True
    return False

def update_api_key_last_used(key_hash: str):
    """Update the last_used_at timestamp for an API key."""
    if key_hash in api_keys_by_hash:
        api_keys_by_hash[key_hash]["last_used_at"] = datetime.utcnow()
