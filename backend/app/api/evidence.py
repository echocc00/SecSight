"""Evidence Pack API"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import ApiResponse
from app.db.database import get_session
from app.db.repositories import EvidencePackRepository

router = APIRouter()


@router.get("/{case_id}", response_model=ApiResponse)
async def get_evidence(
    case_id: str, session: AsyncSession = Depends(get_session)
) -> ApiResponse:
    repo = EvidencePackRepository(session)
    pack = await repo.get_by_case(case_id)
    if not pack:
        raise HTTPException(status_code=404, detail="Evidence pack not found")
    return ApiResponse(success=True, data=pack)
