"""认证 API 路由测试: login / me / users / roles"""
from __future__ import annotations

import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def seeded_client(client):
    """带默认用户的 client (clean_db 后 seed)"""
    from app.db.database import async_session
    from app.db.repositories import UserRepository

    async with async_session() as session:
        await UserRepository(session).seed_defaults()
    yield client


class TestAuthLogin:
    @pytest.mark.asyncio
    async def test_login_admin_returns_token(self, seeded_client):
        r = await seeded_client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "ChangeMe_123!"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["token_type"] == "bearer"
        assert data["role"] == "admin"
        assert len(data["access_token"]) > 50

    @pytest.mark.asyncio
    async def test_login_wrong_password_returns_401(self, seeded_client):
        r = await seeded_client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong"},
        )
        assert r.status_code == 401
        assert "用户名或密码错误" in r.json()["detail"]

    @pytest.mark.asyncio
    async def test_login_unknown_user_returns_401(self, seeded_client):
        r = await seeded_client.post(
            "/api/auth/login",
            json={"username": "nobody", "password": "x"},
        )
        assert r.status_code == 401


class TestAuthMe:
    @pytest.mark.asyncio
    async def test_me_without_token_returns_401(self, client):
        r = await client.get("/api/auth/me")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_me_with_token_returns_user(self, seeded_client):
        token = (
            await seeded_client.post(
                "/api/auth/login",
                json={"username": "analyst", "password": "ChangeMe_123!"},
            )
        ).json()["access_token"]
        r = await seeded_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["username"] == "analyst"
        assert data["role"] == "analyst"


class TestAuthRoles:
    @pytest.mark.asyncio
    async def test_list_roles_returns_all(self, client):
        r = await client.get("/api/auth/roles")
        assert r.status_code == 200
        roles = r.json()["data"]
        assert "admin" in roles
        assert "analyst" in roles
        assert "approver" in roles
        assert "viewer" in roles
        assert "case:read" in roles["viewer"]


class TestAuthUsers:
    @pytest.mark.asyncio
    async def test_list_users_requires_admin(self, seeded_client):
        token = (
            await seeded_client.post(
                "/api/auth/login",
                json={"username": "analyst", "password": "ChangeMe_123!"},
            )
        ).json()["access_token"]
        r = await seeded_client.get("/api/auth/users", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    @pytest.mark.asyncio
    async def test_list_users_admin_sees_all(self, seeded_client):
        token = (
            await seeded_client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "ChangeMe_123!"},
            )
        ).json()["access_token"]
        r = await seeded_client.get("/api/auth/users", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        users = r.json()["data"]
        usernames = [u["username"] for u in users]
        assert "admin" in usernames
