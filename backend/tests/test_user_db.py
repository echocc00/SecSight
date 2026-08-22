"""用户存储 DB 迁移测试"""
from __future__ import annotations

import pytest

from app.auth.service import (
    Role,
    authenticate_user,
    authenticate_user_async,
    hash_password,
    verify_password,
)
from app.db.repositories import UserRepository


class TestUserRepository:
    @pytest.mark.asyncio
    async def test_create_and_get_user(self, db_session):
        repo = UserRepository(db_session)
        h = hash_password("secret123")
        await repo.create("testuser", h, "analyst", email="t@x.com")
        user = await repo.get_by_username("testuser")
        assert user["username"] == "testuser"
        assert user["role"] == "analyst"
        assert user["email"] == "t@x.com"
        assert user["is_active"] is True

    @pytest.mark.asyncio
    async def test_get_unknown_user_returns_none(self, db_session):
        repo = UserRepository(db_session)
        assert await repo.get_by_username("nobody") is None

    @pytest.mark.asyncio
    async def test_list_users(self, db_session):
        repo = UserRepository(db_session)
        await repo.create("u1", hash_password("x"), "analyst")
        await repo.create("u2", hash_password("x"), "viewer")
        users = await repo.list()
        assert len(users) >= 2

    @pytest.mark.asyncio
    async def test_update_last_login(self, db_session):
        repo = UserRepository(db_session)
        await repo.create("u1", hash_password("x"), "analyst")
        user = await repo.get_by_username("u1")
        assert user["last_login_at"] is None
        await repo.update_last_login("u1")
        user = await repo.get_by_username("u1")
        assert user["last_login_at"] is not None

    @pytest.mark.asyncio
    async def test_seed_defaults_creates_four(self, db_session):
        repo = UserRepository(db_session)
        n = await repo.seed_defaults()
        assert n == 4  # admin/analyst/approver/viewer
        # 重复种子不创建
        n2 = await repo.seed_defaults()
        assert n2 == 0


class TestAsyncAuth:
    @pytest.mark.asyncio
    async def test_db_auth_with_seeded_user(self, db_session):
        """DB 种子用户后,async 认证成功"""
        repo = UserRepository(db_session)
        await repo.seed_defaults()
        user = await authenticate_user_async("admin", "ChangeMe_123!")
        assert user is not None
        assert user["username"] == "admin"

    @pytest.mark.asyncio
    async def test_db_auth_wrong_password(self, db_session):
        repo = UserRepository(db_session)
        await repo.seed_defaults()
        user = await authenticate_user_async("admin", "wrong")
        assert user is None

    @pytest.mark.asyncio
    async def test_db_auth_unknown_user(self, db_session):
        user = await authenticate_user_async("nobody", "x")
        assert user is None

    @pytest.mark.asyncio
    async def test_falls_back_to_memory_on_db_error(self, monkeypatch):
        """DB 异常时降级内存字典"""
        import app.db.database as dbmod

        async def _raise(*a, **kw):
            raise Exception("db down")

        monkeypatch.setattr(dbmod, "async_session", _raise)
        # 内存字典有 admin
        user = await authenticate_user_async("admin", "ChangeMe_123!")
        assert user is not None


class TestMemoryAuthCompat:
    def test_memory_auth_still_works(self):
        """内存字典认证保留 (向后兼容)"""
        user = authenticate_user("admin", "ChangeMe_123!")
        assert user is not None
        assert user["username"] == "admin"
