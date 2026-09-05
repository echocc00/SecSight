"""Refresh Token 闭环 — 轮换 / 吊销 / 类型隔离 / 种子密码"""
from __future__ import annotations

import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def seeded_client(client):
    from app.db.database import async_session
    from app.db.repositories import UserRepository

    async with async_session() as session:
        await UserRepository(session).seed_defaults()
    yield client


async def _login(client, username: str = "admin") -> dict:
    resp = await client.post(
        "/api/auth/login", json={"username": username, "password": "ChangeMe_123!"}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


class TestLoginIssuesBothTokens:
    async def test_returns_access_and_refresh(self, seeded_client):
        data = await _login(seeded_client)
        assert len(data["access_token"]) > 50
        assert len(data["refresh_token"]) > 50
        assert data["access_token"] != data["refresh_token"]

    async def test_expires_in_matches_config(self, seeded_client):
        from app.auth.service import ACCESS_TOKEN_EXPIRE_MINUTES

        data = await _login(seeded_client)
        assert data["expires_in"] == ACCESS_TOKEN_EXPIRE_MINUTES * 60

    async def test_access_token_short_lived(self):
        """access 时效必须远短于 refresh,否则 refresh 机制没有意义"""
        from app.auth.service import (
            ACCESS_TOKEN_EXPIRE_MINUTES,
            REFRESH_TOKEN_EXPIRE_DAYS,
        )

        assert ACCESS_TOKEN_EXPIRE_MINUTES <= 60
        assert REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 > ACCESS_TOKEN_EXPIRE_MINUTES

    async def test_refresh_stored_as_hash_not_plaintext(self, seeded_client):
        """DB 只能存 hash: 库被读走也不能拿去续期"""
        from sqlalchemy import select

        from app.db.database import async_session
        from app.db.models import RefreshTokenModel

        data = await _login(seeded_client)
        async with async_session() as session:
            rows = (await session.execute(select(RefreshTokenModel))).scalars().all()
        assert rows
        assert all(r.token_hash != data["refresh_token"] for r in rows)


class TestRefreshRotation:
    async def test_refresh_returns_new_access(self, seeded_client):
        data = await _login(seeded_client)
        resp = await seeded_client.post(
            "/api/auth/refresh", json={"refresh_token": data["refresh_token"]}
        )
        assert resp.status_code == 200
        new = resp.json()
        assert new["refresh_token"] != data["refresh_token"]
        assert new["role"] == "admin"
        assert new["username"] == "admin"

    async def test_old_refresh_revoked_after_rotation(self, seeded_client):
        """旧 refresh 必须立即失效,否则泄露的 token 可无限续期"""
        data = await _login(seeded_client)
        first = await seeded_client.post(
            "/api/auth/refresh", json={"refresh_token": data["refresh_token"]}
        )
        assert first.status_code == 200

        replay = await seeded_client.post(
            "/api/auth/refresh", json={"refresh_token": data["refresh_token"]}
        )
        assert replay.status_code == 401

    async def test_new_access_token_works(self, seeded_client):
        data = await _login(seeded_client)
        rotated = (
            await seeded_client.post(
                "/api/auth/refresh", json={"refresh_token": data["refresh_token"]}
            )
        ).json()
        me = await seeded_client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {rotated['access_token']}"},
        )
        assert me.status_code == 200
        assert me.json()["data"]["username"] == "admin"

    async def test_garbage_refresh_rejected(self, seeded_client):
        resp = await seeded_client.post(
            "/api/auth/refresh", json={"refresh_token": "not-a-jwt"}
        )
        assert resp.status_code == 401

    async def test_access_token_rejected_as_refresh(self, seeded_client):
        """access token 不能当 refresh 用 (typ 声明隔离)"""
        data = await _login(seeded_client)
        resp = await seeded_client.post(
            "/api/auth/refresh", json={"refresh_token": data["access_token"]}
        )
        assert resp.status_code == 401

    async def test_disabled_user_cannot_refresh(self, seeded_client):
        from app.db.database import async_session
        from app.db.models import UserModel

        data = await _login(seeded_client)
        async with async_session() as session:
            user = await session.get(UserModel, "admin")
            user.is_active = False
            await session.commit()

        resp = await seeded_client.post(
            "/api/auth/refresh", json={"refresh_token": data["refresh_token"]}
        )
        assert resp.status_code == 401


class TestRefreshTokenNotUsableAsAccess:
    async def test_refresh_token_rejected_on_protected_endpoint(self, seeded_client):
        data = await _login(seeded_client)
        resp = await seeded_client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {data['refresh_token']}"},
        )
        assert resp.status_code == 401


class TestLogout:
    async def test_logout_revokes_refresh(self, seeded_client):
        data = await _login(seeded_client)
        out = await seeded_client.post(
            "/api/auth/logout", json={"refresh_token": data["refresh_token"]}
        )
        assert out.status_code == 200

        resp = await seeded_client.post(
            "/api/auth/refresh", json={"refresh_token": data["refresh_token"]}
        )
        assert resp.status_code == 401

    async def test_logout_all_revokes_every_session(self, seeded_client):
        first = await _login(seeded_client)
        second = await _login(seeded_client)

        out = await seeded_client.post(
            "/api/auth/logout-all",
            headers={"Authorization": f"Bearer {second['access_token']}"},
        )
        assert out.status_code == 200
        assert out.json()["data"]["revoked_count"] >= 2

        for tokens in (first, second):
            resp = await seeded_client.post(
                "/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
            )
            assert resp.status_code == 401

    async def test_logout_all_requires_auth(self, seeded_client):
        resp = await seeded_client.post("/api/auth/logout-all")
        assert resp.status_code == 401


class TestSeedPassword:
    async def test_production_generates_random_password(self, monkeypatch):
        """生产未配置 SEED_USER_PASSWORD 时不能落到公开的默认口令"""
        from app.auth.service import verify_password
        from app.core import config
        from app.db.database import async_session
        from app.db.repositories import UserRepository

        monkeypatch.setattr(config.settings, "env", "production")
        monkeypatch.setattr(config.settings, "seed_user_password", "")

        async with async_session() as session:
            created = await UserRepository(session).seed_defaults()
            assert created == 4
            user = await UserRepository(session).get_by_username("admin")

        assert not verify_password("ChangeMe_123!", user["hashed_password"])

    async def test_configured_password_used(self, monkeypatch):
        from app.auth.service import verify_password
        from app.core import config
        from app.db.database import async_session
        from app.db.repositories import UserRepository

        monkeypatch.setattr(config.settings, "seed_user_password", "Custom_Pass_9!")

        async with async_session() as session:
            await UserRepository(session).seed_defaults()
            user = await UserRepository(session).get_by_username("admin")

        assert verify_password("Custom_Pass_9!", user["hashed_password"])

    async def test_seed_is_idempotent(self):
        from app.db.database import async_session
        from app.db.repositories import UserRepository

        async with async_session() as session:
            repo = UserRepository(session)
            assert await repo.seed_defaults() == 4
            assert await repo.seed_defaults() == 0


class TestRefreshTokenRepositoryMaintenance:
    async def test_purge_expired_removes_stale(self, db_session):
        from datetime import datetime, timedelta

        from app.db.repositories import RefreshTokenRepository

        repo = RefreshTokenRepository(db_session)
        await repo.create(
            token_id="expired-1",
            username="admin",
            token="tok",
            expires_at=datetime.utcnow() - timedelta(days=1),
        )
        assert await repo.purge_expired() == 1
        assert await repo.get_valid("expired-1", "tok") is None
