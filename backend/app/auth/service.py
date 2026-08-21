"""认证与授权 — JWT + 4 角色

角色: admin / analyst / approver / viewer
权限矩阵见 docs/06-phase2-plan.md §4.2
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

# 配置
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 小时

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    APPROVER = "approver"
    VIEWER = "viewer"


# 权限矩阵 (角色 → 允许操作)
PERMISSIONS: dict[Role, set[str]] = {
    Role.ADMIN: {
        "case:read", "case:write", "alert:inject", "approval:submit",
        "playbook:manage", "user:manage", "execution:trigger",
    },
    Role.ANALYST: {
        "case:read", "case:write", "alert:inject", "playbook:manage",
    },
    Role.APPROVER: {
        "case:read", "approval:submit", "execution:trigger",
    },
    Role.VIEWER: {
        "case:read",
    },
}


class CurrentUser:
    def __init__(self, username: str, role: Role) -> None:
        self.username = username
        self.role = role

    def has_permission(self, perm: str) -> bool:
        return perm in PERMISSIONS.get(self.role, set())


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(username: str, role: Role) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "role": role.value,
        "exp": expire,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_token(token: str) -> CurrentUser:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role_str = payload.get("role")
        if not username or role_str not in [r.value for r in Role]:
            raise HTTPException(status_code=401, detail="无效 token")
        return CurrentUser(username=username, role=Role(role_str))
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"token 解码失败: {e}") from e


async def get_current_user(
    token: Annotated[str | None, Depends(oauth2_scheme)],
) -> CurrentUser:
    if not token:
        raise HTTPException(status_code=401, detail="未认证")
    return decode_token(token)


def require_permission(perm: str):
    """依赖工厂: 要求当前用户有指定权限"""

    async def checker(user: Annotated[CurrentUser, Depends(get_current_user)]) -> CurrentUser:
        if not user.has_permission(perm):
            raise HTTPException(status_code=403, detail=f"权限不足: 需要 {perm}")
        return user

    return checker


# 简化用户存储 (Phase2 后期接 DB)
# TODO: 迁移到 Postgres users 表
_DEMO_USERS: dict[str, dict] = {
    "admin": {
        "username": "admin",
        "hashed_password": hash_password("ChangeMe_123!"),
        "role": Role.ADMIN,
    },
    "analyst": {
        "username": "analyst",
        "hashed_password": hash_password("ChangeMe_123!"),
        "role": Role.ANALYST,
    },
    "approver": {
        "username": "approver",
        "hashed_password": hash_password("ChangeMe_123!"),
        "role": Role.APPROVER,
    },
    "viewer": {
        "username": "viewer",
        "hashed_password": hash_password("ChangeMe_123!"),
        "role": Role.VIEWER,
    },
}


def authenticate_user(username: str, password: str) -> dict | None:
    user = _DEMO_USERS.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return None
    return user


def get_user(username: str) -> dict | None:
    return _DEMO_USERS.get(username)


def list_users() -> list[dict]:
    return [
        {"username": u["username"], "role": u["role"].value}
        for u in _DEMO_USERS.values()
    ]
