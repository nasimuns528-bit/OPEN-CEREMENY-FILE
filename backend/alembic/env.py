"""
Alembic environment configuration.
Uses synchronous psycopg2 connection for migrations.
Async SQLAlchemy is used by the application at runtime.
"""
from __future__ import annotations

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

# Import all models so Alembic autogenerate detects them
from app.database import Base
import app.models  # noqa: F401

# Alembic Config object
config = context.config

# Read sync URL from environment (overrides alembic.ini placeholder)
sync_url = os.environ.get("DATABASE_SYNC_URL")
if sync_url:
    config.set_main_option("sqlalchemy.url", sync_url)

# Logging setup from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode without a live DB connection."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode with a live DB connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
