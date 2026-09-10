"""
Router re-export for auth.
Points to app.api.auth for backwards compatibility.
"""
from app.api.auth import router

__all__ = ["router"]
