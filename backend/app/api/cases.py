"""Case API"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import ApiResponse
from app.db.database import get_session
from app.db.repositories import CaseRepository

router = APIRouter()


@router.get("", response_model=ApiResponse)
async def list_cases(
    limit: int = 50,
    status: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> ApiResponse:
    repo = CaseRepository(session)
    cases = await repo.list(limit=limit, status=status)
    return ApiResponse(
        success=True,
        data=[
            {
                "case_id": c.case_id,
                "status": c.status.value,
                "playbook_id": c.playbook_id,
                "severity": (c.judgment.severity.value if c.judgment else None),
                "alert_count": len(c.alerts),
                "pending_approvals": len(c.needs_approval()),
                "created_at": c.created_at.isoformat(),
                "tttr_seconds": c.tttr_seconds,
            }
            for c in cases
        ],
    )


@router.get("/{case_id}", response_model=ApiResponse)
async def get_case(
    case_id: str, session: AsyncSession = Depends(get_session)
) -> ApiResponse:
    repo = CaseRepository(session)
    case = await repo.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return ApiResponse(
        success=True,
        data=case.model_dump(mode="json"),
    )
