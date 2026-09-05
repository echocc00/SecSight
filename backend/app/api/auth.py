"""认证 API"""
# 注意: 本模块不用 `from __future__ import annotations` —— slowapi 的 @limiter.limit
# 包装器丢失原函数 __globals__,字符串注解无法解析,FastAPI 会把 body 参数误判成 query。
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.api.schemas import ApiResponse
from app.auth.service import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    Role,
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    get_current_user,
    list_users,
    require_permission,
)
from app.core.security import LOGIN_LIMIT, limiter
from app.db.database import get_session

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str
    username: str


class RefreshRequest(BaseModel):
    refresh_token: str


class RefreshResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str
    username: str


async def _issue_tokens(session, username: str, role: Role) -> dict:
    """签发 access + refresh,refresh 落库 (存 hash)"""
    from app.db.repositories import RefreshTokenRepository

    refresh, token_id, expires_at = create_refresh_token(username)
    await RefreshTokenRepository(session).create(
        token_id=token_id, username=username, token=refresh, expires_at=expires_at
    )
    return {
        "access_token": create_access_token(username, role),
        "refresh_token": refresh,
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "role": role.value,
        "username": username,
    }


@router.post("/login", response_model=TokenResponse)
@limiter.limit(LOGIN_LIMIT)
async def login(
    request: Request,
    req: LoginRequest,
    session=Depends(get_session),
) -> TokenResponse:
    """登录获取 access + refresh token (DB 认证,降级内存字典)"""
    from app.auth.service import authenticate_user_async

    user = await authenticate_user_async(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    # DB 返回 role 为 str,内存字典返回 Role enum,统一处理
    role_val = user["role"].value if hasattr(user["role"], "value") else user["role"]
    tokens = await _issue_tokens(session, user["username"], Role(role_val))
    return TokenResponse(**tokens)


@router.post("/refresh", response_model=RefreshResponse)
async def refresh_token(
    req: RefreshRequest, session=Depends(get_session)
) -> RefreshResponse:
    """用 refresh token 换新 access token (轮换: 旧 refresh 立即吊销)

    轮换而非复用,是为了让 refresh 泄露可被检测 —— 攻击者用旧 token 时已被吊销。
    """
    from app.db.repositories import RefreshTokenRepository, UserRepository

    username, token_id = decode_refresh_token(req.refresh_token)

    repo = RefreshTokenRepository(session)
    record = await repo.get_valid(token_id, req.refresh_token)
    if not record or record["username"] != username:
        raise HTTPException(status_code=401, detail="refresh token 已失效或被吊销")

    user = await UserRepository(session).get_by_username(username)
    if not user or not user["is_active"]:
        raise HTTPException(status_code=401, detail="用户不存在或已禁用")

    await repo.revoke(token_id)
    tokens = await _issue_tokens(session, username, Role(user["role"]))
    return RefreshResponse(**tokens)


@router.post("/logout", response_model=ApiResponse)
async def logout(req: RefreshRequest, session=Depends(get_session)) -> ApiResponse:
    """登出: 吊销该 refresh token (access token 到期自然失效)"""
    from app.db.repositories import RefreshTokenRepository

    username, token_id = decode_refresh_token(req.refresh_token)
    await RefreshTokenRepository(session).revoke(token_id)
    return ApiResponse(success=True, data={"revoked": token_id, "username": username})


@router.post("/logout-all", response_model=ApiResponse)
async def logout_all(
    user=Depends(get_current_user), session=Depends(get_session)
) -> ApiResponse:
    """吊销当前用户全部 refresh token (改密/怀疑泄露时用)"""
    from app.db.repositories import RefreshTokenRepository

    count = await RefreshTokenRepository(session).revoke_all_for_user(user.username)
    return ApiResponse(success=True, data={"revoked_count": count})


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
