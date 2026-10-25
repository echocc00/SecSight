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
# 限流默认关闭: 全套测试共用一个 limiter 计数器,开启会让注入类测试互相踩配额。
# test_rate_limit.py 用 rate_limiter fixture 局部打开。
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")
# webhook token: 测试统一用固定值 (webhook 相关测试断言 401/403/200)
# 注意: settings.webhook_token 的 pydantic alias 是 WEBHOOK_TOKEN (无 SECSIGHT_ 前缀),
# 须按 alias 设置才会被读到 —— 与 deploy/.env.example 的 WEBHOOK_TOKEN 一致。
os.environ.setdefault("WEBHOOK_TOKEN", "test-webhook-token")
os.environ.setdefault("SECSIGHT_WEBHOOK_TOKEN", "test-webhook-token")  # 保留旧名 (仅文档语义)
os.environ.setdefault("FEISHU_APP_SECRET", "test-feishu-secret")
os.environ.setdefault("DINGTALK_APP_SECRET", "test-dingtalk-secret")

import httpx  # noqa: E402
import pytest_asyncio  # noqa: E402

# 种子用户密码 (env=test 走开发默认值,见 UserRepository.seed_defaults)
TEST_PASSWORD = "ChangeMe_123!"

# RBAC 角色 → 登录账号 (种子用户名与角色同名)
ROLE_USER = {
    "admin": "admin",
    "analyst": "analyst",
    "approver": "approver",
    "viewer": "viewer",
}


async def _seed_users() -> None:
    """每个测试前种子默认用户 (鉴权矩阵测试依赖可登录的账号)

    bcrypt 哈希每次 ~0.3s,4 用户 × 645 测试不可接受 —— 全套件共用一个
    预计算哈希 (密码固定为测试默认值,seed 逻辑一致性由 test_seed 专项覆盖)。
    """
    from app.auth.service import hash_password
    from app.core.config import settings
    from app.db.database import async_session
    from app.db.models import UserModel

    roles = ["admin", "analyst", "approver", "viewer"]
    hashed = _seed_users.__dict__.get("_hashed")
    if not hashed:
        hashed = hash_password(TEST_PASSWORD)
        _seed_users._hashed = hashed  # type: ignore[attr-defined]

    from sqlalchemy import insert

    async with async_session() as session:
        await session.execute(
            insert(UserModel),
            [
                {
                    "username": r,
                    "hashed_password": hashed,
                    "role": r,
                    "is_active": True,
                }
                for r in roles
            ],
        )
        await session.commit()
    assert settings.env == "test"  # 防止种子逻辑被误用到生产 fixture


@pytest_asyncio.fixture(autouse=True)
async def clean_db():
    """每个测试前重建表 + 种子用户,保证隔离"""
    import app.db.models  # noqa: F401  # 确保表已注册到 metadata (单文件运行时无其他模块导入)

    from app.db.database import Base, engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    await _seed_users()
    yield


@pytest_asyncio.fixture
async def client():
    """FastAPI ASGI 测试客户端 (不走 lifespan,表由 clean_db 建)"""
    from app.main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def auth_client():
    """自动携带 admin JWT 的客户端 (业务端点已要求鉴权,免每个测试手动登录)

    断言 401/403/角色差异的测试请用裸 client + login_headers(role)。
    """
    from app.main import app

    headers = await login_headers("admin")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=headers
    ) as c:
        yield c


async def login_headers(role: str = "admin") -> dict[str, str]:
    """用种子账号登录,返回 Authorization 头 (业务端点现已要求 JWT)"""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_get_app()), base_url="http://test"
    ) as c:
        r = await c.post(
            "/api/auth/login",
            json={"username": ROLE_USER[role], "password": TEST_PASSWORD},
        )
        assert r.status_code == 200, f"login failed for {role}: {r.text}"
        token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _get_app():
    from app.main import app

    return app


@pytest_asyncio.fixture
async def auth_headers():
    """admin 登录头 (最常用)"""
    return await login_headers("admin")


@pytest_asyncio.fixture
async def db_session():
    """直接注入 async session (测仓储层)"""
    from app.db.database import async_session

    async with async_session() as session:
        yield session


@pytest_asyncio.fixture
async def rate_limiter():
    """临时打开限流并清空计数器 (用完还原,避免污染其他测试)"""
    from app.core.security import limiter

    was_enabled = limiter.enabled
    limiter.enabled = True
    limiter.reset()
    yield limiter
    limiter.reset()
    limiter.enabled = was_enabled


# ============ 审批签署 helper (P0 后: 审批身份来自 JWT / IM 回调签名,不可自报) ============

# conftest 设定的各共享密钥 (与上方 env 一致,勿改)
WEBHOOK_TOKEN = "test-webhook-token"
DINGTALK_APP_SECRET = "test-dingtalk-secret"
FEISHU_APP_SECRET = "test-feishu-secret"

# 审批角色 → RBAC 登录角色 (服务端 APPROVAL_ROLE_MAP 的逆映射)
APPROVAL_ROLE_LOGIN = {
    "incident_commander": "analyst",
    "approver": "approver",
    "ciso_or_delegate": "admin",
}


async def sign_approval(
    client: httpx.AsyncClient,
    case_id: str,
    action_id: str,
    approval_role: str,
    decision: str = "approved",
    comment: str = "",
) -> httpx.Response:
    """以指定审批角色签署一个 L2 动作,返回原始响应。

    新鉴权模型下审批身份不可自报,各审批角色经 APPROVAL_ROLE_MAP 映射到
    对应 RBAC 账号走 JWT 审批端点 (与 Dashboard 同路径):
      incident_commander→analyst / approver→approver / ciso_or_delegate→admin
    IM 回调签署路径见 tests/test_notify.py (钉钉/飞书签名)。
    """
    headers = await login_headers(APPROVAL_ROLE_LOGIN[approval_role])
    return await client.post(
        f"/api/approvals/{case_id}/actions/{action_id}/approve",
        json={"decision": decision, "comment": comment},
        headers=headers,
    )


async def approve_action_with_all_roles(
    client: httpx.AsyncClient, case_id: str, action_id: str, required_roles: list[str]
) -> None:
    """按 required_roles 逐一签署 (每个角色走其映射的签署路径)"""
    for role in required_roles:
        r = await sign_approval(client, case_id, action_id, role)
        assert r.status_code == 200, f"sign {role} failed: {r.text}"
        body = r.json()
        assert body["success"] is True, f"sign {role} rejected: {body}"
