"""
Role-Based Access Control (RBAC) Module for QWED.
Provides middleware and decorators for permission management.

Roles:
- Admin: Full access to organization data and settings
- Member: Can run verifications and view own history
- Viewer: Read-only access to history
"""

import logging
from functools import wraps
from typing import List, Optional, Callable
from fastapi import HTTPException, Request, Depends
from qwed_new.core.models import User
from qwed_new.core.database import get_session

logger = logging.getLogger(__name__)

# Role definitions
ROLES = {
    "admin": ["*"],
    "member": ["verify:execute", "history:read", "keys:read"],
    "viewer": ["history:read"]
}

class RBACMiddleware:
    """
    Middleware for enforcing role-based access control.
    """
    
    @staticmethod
    def check_permission(user: User, required_permission: str) -> bool:
        """
        Check if user has the required permission.
        """
        if not user or not user.is_active:
            return False
            
        user_role = user.role.lower()
        if user_role not in ROLES:
            return False
            
        allowed_permissions = ROLES[user_role]
        
        # Admin has all permissions
        if "*" in allowed_permissions:
            return True
            
        return required_permission in allowed_permissions

def require_role(allowed_roles: List[str]):
    """
    Decorator to require specific roles for an endpoint.
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract user from request state (set by auth middleware)
            # Note: This assumes request is the first arg or in kwargs
            request = kwargs.get('request')
            if not request:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break
            
            if not request:
                logger.warning("RBAC: Could not find Request object")
                raise HTTPException(status_code=500, detail="Internal Server Error")
                
            user = getattr(request.state, "user", None)
            if not user:
                raise HTTPException(status_code=401, detail="Not authenticated")
                
            if user.role not in allowed_roles:
                raise HTTPException(
                    status_code=403, 
                    detail=f"Insufficient permissions. Required: {allowed_roles}"
                )
                
            return await func(*args, **kwargs)
        return wrapper
    return decorator

def require_permission(permission: str):
    """
    Decorator to require a specific permission.
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = kwargs.get('request')
            if not request:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break
            
            if not request:
                raise HTTPException(status_code=500, detail="Internal Server Error")
                
            user = getattr(request.state, "user", None)
            if not user:
                raise HTTPException(status_code=401, detail="Not authenticated")
                
            if not RBACMiddleware.check_permission(user, permission):
                raise HTTPException(
                    status_code=403, 
                    detail=f"Missing permission: {permission}"
                )
                
            return await func(*args, **kwargs)
        return wrapper
    return decorator
