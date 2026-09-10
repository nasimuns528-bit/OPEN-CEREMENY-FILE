"""
Database module re-export.
Points to app.core.database for backwards compatibility.
"""
from app.core.database import (
    engine,
    AsyncSessionLocal,
    Base,
    get_db,
)

__all__ = ["engine", "AsyncSessionLocal", "Base", "get_db"]
