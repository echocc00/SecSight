"""pytest 全局 fixture

关键: 必须在 import app 之前设置 DATABASE_URL / PLAYBOOKS_DIR 环境变量,
因为 app.core.config 和 app.db.database 在 import 时就创建 engine。
"""
from __future__ import annotations

import os
import pathlib
import tempfile

# ============ 必须在 import app 前设置 ============
_BACKEND_ROOT = pathlib.Path(__file__).resolve().parents[1]
_PROJECT_ROOT = _BACKEND_ROOT.parent
_TEST_DB = pathlib.Path(tempfile.gettempdir()) / "secsight_pytest.db"

os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_TEST_DB}"
os.environ["SECSIGHT_ENV"] = "test"
os.environ["SECSIGHT_MOCK_MODE"] = "true"
os.environ["PLAYBOOKS_DIR"] = str(_PROJECT_ROOT / "playbooks")

import httpx  # noqa: E402
import pytest_asyncio  # noqa: E402


@pytest_asyncio.fixture(autouse=True)
async def clean_db():
    """每个测试前重建表,保证隔离"""
    from app.db.database import Base, engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest_asyncio.fixture
async def client():
    """FastAPI ASGI 测试客户端 (不走 lifespan,表由 clean_db 建)"""
    from app.main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def db_session():
    """直接注入 async session (测仓储层)"""
    from app.db.database import async_session

    async with async_session() as session:
        yield session
