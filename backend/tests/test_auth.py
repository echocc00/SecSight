"""认证授权测试 — JWT + 4 角色 + 权限矩阵"""
from __future__ import annotations

import pytest

from app.auth.service import (
    PERMISSIONS,
    Role,
    authenticate_user,
    create_access_token,
    decode_token,
    hash_password,
    require_permission,
    verify_password,
)


class TestPasswordHashing:
    def test_hash_and_verify(self):
        h = hash_password("secret123")
        assert h != "secret123"
        assert verify_password("secret123", h) is True

    def test_wrong_password_fails(self):
        h = hash_password("secret123")
        assert verify_password("wrong", h) is False


class TestJWT:
    def test_create_and_decode_token(self):
        token = create_access_token("alice", Role.ADMIN)
        user = decode_token(token)
        assert user.username == "alice"
        assert user.role == Role.ADMIN

    def test_invalid_token_raises(self):
        with pytest.raises(Exception):
            decode_token("invalid.token.here")


class TestPermissionMatrix:
    def test_admin_has_all_permissions(self):
        assert "user:manage" in PERMISSIONS[Role.ADMIN]
        assert "case:read" in PERMISSIONS[Role.ADMIN]

    def test_viewer_only_reads(self):
        assert PERMISSIONS[Role.VIEWER] == {"case:read"}

    def test_approver_can_approve_not_inject(self):
        assert "approval:submit" in PERMISSIONS[Role.APPROVER]
        assert "alert:inject" not in PERMISSIONS[Role.APPROVER]

    def test_analyst_can_inject_not_approve(self):
        assert "alert:inject" in PERMISSIONS[Role.ANALYST]
        assert "approval:submit" not in PERMISSIONS[Role.ANALYST]


class TestAuthenticateUser:
    def test_valid_credentials(self):
        user = authenticate_user("admin", "ChangeMe_123!")
        assert user is not None
        assert user["role"] == Role.ADMIN

    def test_wrong_password(self):
        assert authenticate_user("admin", "wrong") is None

    def test_unknown_user(self):
        assert authenticate_user("nobody", "x") is None


class TestRequirePermission:
    @pytest.mark.asyncio
    async def test_admin_passes_user_manage(self):
        token = create_access_token("admin", Role.ADMIN)
        checker = require_permission("user:manage")
        # 模拟依赖注入
        from app.auth.service import get_current_user

        # 直接调用 checker 需要当前用户,这里验证权限逻辑
        from app.auth.service import CurrentUser

        user = CurrentUser("admin", Role.ADMIN)
        assert user.has_permission("user:manage") is True

    @pytest.mark.asyncio
    async def test_viewer_blocked_from_inject(self):
        from app.auth.service import CurrentUser

        user = CurrentUser("viewer", Role.VIEWER)
        assert user.has_permission("alert:inject") is False
