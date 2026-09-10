"""
VisionTrust Configuration Re-export
Points to app.core.config for backwards compatibility.
"""
from app.core.config import Settings, get_settings

__all__ = ["Settings", "get_settings"]
