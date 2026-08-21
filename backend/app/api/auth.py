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
    """登录获取 JWT"""
    from app.auth.service import authenticate_user

    user = authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    token = create_access_token(user["username"], user["role"])
    return TokenResponse(
        access_token=token,
        role=user["role"].value,
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
) -> ApiResponse:
    """列出所有用户 (仅 admin)"""
    return ApiResponse(success=True, data=list_users())


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
