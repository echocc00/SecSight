"""Alembic 环境 — async SQLAlchemy + 复用 app 配置

DB URL 从 app.core.config.settings 读取 (不在 alembic.ini 硬编码),
保证与运行时一致。所有模型经 app.db.models 导入注册到 Base.metadata。
"""
from __future__ import annotations

import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# 关键: 导入所有模型让 Base.metadata 完整
from app.core.config import settings
from app.db.database import Base
from app.db import models  # noqa: F401 - 触发模型注册

config = context.config
config.set_main_option("sqlalchemy.url", settings.database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """离线模式: 生成 SQL 不连库"""
    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,  # 检测列类型变更
        compare_server_default=True,
        render_as_batch=True,  # SQLite ALTER TABLE 兼容
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """async engine 执行迁移 (asyncpg/aiosqlite)"""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
