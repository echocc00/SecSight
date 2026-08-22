"""认证 API"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.schemas import ApiResponse
from app.auth.service import (
    Role,
    create_access_token,
    get_current_user,
    list_users,
    require_permission,
)
from app.db.database import get_session

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest) -> TokenResponse:
    """登录获取 JWT (DB 认证,降级内存字典)"""
    from app.auth.service import authenticate_user_async

    user = await authenticate_user_async(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    # DB 返回 role 为 str,内存字典返回 Role enum,统一处理
    role_val = user["role"].value if hasattr(user["role"], "value") else user["role"]
    token = create_access_token(user["username"], Role(role_val))
    return TokenResponse(
        access_token=token,
        role=role_val,
        username=user["username"],
    )


@router.get("/me", response_model=ApiResponse)
async def me(user=Depends(get_current_user)) -> ApiResponse:
    """当前用户信息"""
    return ApiResponse(
        success=True,
        data={"username": user.username, "role": user.role.value},
    )


@router.get("/users", response_model=ApiResponse)
async def list_all_users(
    user=Depends(require_permission("user:manage")),
    session=Depends(get_session),
) -> ApiResponse:
    """列出所有用户 (仅 admin, 从 DB 查)"""
    from app.db.repositories import UserRepository

    repo = UserRepository(session)
    users = await repo.list()
    return ApiResponse(success=True, data=users)


@router.get("/roles", response_model=ApiResponse)
async def list_roles() -> ApiResponse:
    """列出角色与权限"""
    from app.auth.service import PERMISSIONS

    return ApiResponse(
        success=True,
        data={
            r.value: list(perms) for r, perms in PERMISSIONS.items()
        },
    )
