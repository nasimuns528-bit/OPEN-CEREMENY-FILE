"""
Dependencies re-export for backwards compatibility.
Points to app.security.dependencies and app.core.database.
"""
from app.core.database import get_db
from app.security.dependencies import (
    bearer_scheme,
    get_client_ip,
    get_current_user,
    require_role,
)

__all__ = [
    "bearer_scheme",
    "get_current_user",
    "require_role",
    "get_client_ip",
    "get_db",
]
