"""数据库 engine + async session

垂直切片默认 SQLite (aiosqlite),无需 Postgres 即可本地验证。
生产切 POSTGRES_DSN。
"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


class Base(DeclarativeBase):
    """ORM 基类"""
    pass


# SQLite 用 aiosqlite;Postgres 用 asyncpg
_dsn = settings.database_url
if _dsn.startswith("postgresql"):
    _engine_kwargs = {"pool_size": 10, "max_overflow": 20}
else:
    _engine_kwargs = {}  # SQLite 不支持 pool_size

engine = create_async_engine(
    _dsn,
    echo=settings.env == "development",
    **_engine_kwargs,
)

async_session = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def get_session() -> AsyncSession:
    """FastAPI 依赖: 注入 async session"""
    async with async_session() as session:
        yield session


async def init_db() -> None:
    """建表 (开发用,生产走 alembic 迁移)"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
