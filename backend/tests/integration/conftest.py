"""Postgres 集成测试 fixture — LangGraph Checkpointer 真实中断恢复

仅在 SECSIGHT_PG_LIVE=1 且 DATABASE_URL 指向 Postgres 时运行。
CI 用 postgres:16-alpine service container。

本地跑:
  docker run -d --name pg-test -e POSTGRES_USER=secsight -e POSTGRES_PASSWORD=test_pw \
    -e POSTGRES_DB=secsight_test -p 5433:5432 postgres:16-alpine
  cd backend
  DATABASE_URL="postgresql+asyncpg://secsight:test_pw@localhost:5433/secsight_test" \
    ENABLE_CHECKPOINTER=true SECSIGHT_PG_LIVE=1 SECSIGHT_ENV=test \
    PLAYBOOKS_DIR=../playbooks py -3.12 -m pytest tests/integration/ -v
"""
from __future__ import annotations

import os
import pathlib

import pytest

_PG_LIVE = os.environ.get("SECSIGHT_PG_LIVE") == "1"
_DB_URL = os.environ.get("DATABASE_URL", "")
_IS_PG = _DB_URL.startswith("postgresql")

# 集成测试必须在 import app 前设好环境
if _PG_LIVE and _IS_PG:
    os.environ.setdefault("SECSIGHT_ENV", "test")
    os.environ.setdefault("SECSIGHT_MOCK_MODE", "true")
    os.environ.setdefault("ENABLE_CHECKPOINTER", "true")
    _ROOT = pathlib.Path(__file__).resolve().parents[2].parent
    os.environ.setdefault("PLAYBOOKS_DIR", str(_ROOT / "playbooks"))

import httpx  # noqa: E402
import pytest_asyncio  # noqa: E402

pytestmark = pytest.mark.skipif(
    not (_PG_LIVE and _IS_PG),
    reason="需真实 Postgres: 设 SECSIGHT_PG_LIVE=1 + DATABASE_URL=postgresql+asyncpg://...",
)


@pytest_asyncio.fixture(autouse=True)
async def clean_pg():
    """每个测试重建 schema + 清 checkpoint 表"""
    from sqlalchemy import text

    from app.db.database import Base, engine

    async with engine.begin() as conn:
        # checkpoint 表由 langgraph 管理,单独清
        for tbl in ("checkpoint_writes", "checkpoint_blobs", "checkpoints"):
            await conn.execute(text(f"DROP TABLE IF EXISTS {tbl} CASCADE"))
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    # 重置 checkpointer 单例 (每测试独立连接)
    from app.agents import workflow as wf_mod

    await wf_mod.close_checkpointer()
    yield
    await wf_mod.close_checkpointer()


@pytest_asyncio.fixture
async def pg_client():
    from app.main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def pg_session():
    from app.db.database import async_session

    async with async_session() as s:
        yield s
