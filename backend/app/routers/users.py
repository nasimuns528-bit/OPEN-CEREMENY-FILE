"""
Router re-export for users.
Points to app.api.users for backwards compatibility.
"""
from app.api.users import router

__all__ = ["router"]
