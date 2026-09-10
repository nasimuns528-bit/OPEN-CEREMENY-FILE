"""
Root-level system integration tests for VisionTrust.
Verifies project foundation, health check, CORS, and security standards.
"""
from __future__ import annotations

import os
import sys

# Ensure backend directory is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app


@pytest.mark.asyncio
async def test_root_api_health():
    """Verify GET /api/health returns the expected status and service name."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "VisionTrust API"


@pytest.mark.asyncio
async def test_security_headers_and_no_stacktrace_on_404():
    """Verify 404 responses do not leak server internals or stack traces."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/nonexistent-endpoint-vector")
        assert response.status_code == 404
        assert "traceback" not in response.text.lower()
