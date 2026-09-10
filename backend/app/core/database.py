"""
Database engine, session factory, and base declarative model.
Uses SQLAlchemy 2.0 async engine backed by asyncpg for production.
When DATABASE_URL is SQLite (tests), uses StaticPool for in-memory sharing.
Alembic uses the separate sync DATABASE_SYNC_URL in env.py.
"""
from __future__ import annotations

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings

settings = get_settings()

_is_sqlite = settings.database_url.startswith("sqlite")

if _is_sqlite:
    # In-memory SQLite for tests: use StaticPool so all connections share
    # the same in-memory database. Pool size args are invalid for SQLite.
    engine = create_async_engine(
        settings.database_url,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
else:
    # PostgreSQL production engine
    engine = create_async_engine(
        settings.database_url,
        echo=settings.environment == "development",
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async DB session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
