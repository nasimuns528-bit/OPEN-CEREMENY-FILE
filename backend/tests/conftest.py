"""
Pytest configuration and fixtures for VisionTrust backend tests.
Uses an in-memory SQLite database so tests run without a real PostgreSQL server.
"""
from __future__ import annotations

import os
from typing import AsyncGenerator

# ── Set test environment BEFORE any app imports ──────────────────────────────
# pydantic-settings reads these on first import of app.config
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("DATABASE_SYNC_URL", "sqlite:///./test_alembic.db")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-key-not-for-production-use")
os.environ.setdefault("FIRST_ADMIN_PASSWORD", "AdminTestPass1")

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.database import Base, get_db
from app.main import app

# ── In-memory async SQLite for tests ──────────────────────────────────────────
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)

TestSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)



@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_database():
    """Create all tables once per test session."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield a fresh DB session per test, rolled back after each test."""
    async with TestSessionLocal() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Yield an AsyncClient with the test DB session injected."""
    async def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c

    app.dependency_overrides.clear()


# ── Convenience helpers ────────────────────────────────────────────────────────

async def register_user(
    client: AsyncClient,
    username: str = "testuser",
    email: str = "test@example.com",
    password: str = "TestPass1",
    role: str = "contributor",
) -> dict:
    resp = await client.post(
        "/api/v1/auth/register",
        json={"username": username, "email": email, "password": password, "role": role},
    )
    return resp


async def login_user(
    client: AsyncClient,
    username: str = "testuser",
    password: str = "TestPass1",
) -> dict:
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )
    return resp
