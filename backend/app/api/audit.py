"""审计日志 API — hash chain 完整性校验 (等保 2.0 三级留痕要求)"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import ApiResponse
from app.auth.service import require_permission
from app.db.database import get_session
from app.db.repositories import AuditLogRepository

router = APIRouter()


@router.get("/verify", response_model=ApiResponse)
async def verify_audit_chain(
    session: AsyncSession = Depends(get_session),
    _user=Depends(require_permission("case:read")),
) -> ApiResponse:
    """重算审计日志 hash chain,定位断链位置

    链断裂说明日志被删除或篡改 —— 合规检查必查项。valid=false 时
    broken_at_seq 指向第一条异常记录。
    """
    result = await AuditLogRepository(session).verify_chain()
    return ApiResponse(success=True, data=result)


@router.get("", response_model=ApiResponse)
async def list_audit_logs(
    case_id: str | None = None,
    limit: int = Query(100, le=1000),
    session: AsyncSession = Depends(get_session),
    _user=Depends(require_permission("case:read")),
) -> ApiResponse:
    """审计日志列表 (含 seq/hash,便于外部独立复核)"""
    repo = AuditLogRepository(session)
    if case_id:
        logs = await repo.list_by_case(case_id)
    else:
        logs = await repo.list_recent(limit=limit)
    return ApiResponse(success=True, data=logs)
