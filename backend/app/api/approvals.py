"""审批 API"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.workflow import resume_workflow
from app.api.schemas import ApiResponse, ApprovalRequest
from app.approvals.service import ApprovalError, approval_service
from app.db.database import get_session

router = APIRouter()


@router.post("/{case_id}/actions/{action_id}/approve", response_model=ApiResponse)
async def approve_action(
    case_id: str,
    action_id: str,
    req: ApprovalRequest,
    session: AsyncSession = Depends(get_session),
) -> ApiResponse:
    """提交 L2 审批

    垂直切片: 单签 approved 即通过 (Phase2 改真正双签: incident_commander + approver 两个角色)。
    全部 L2 动作 approved 后自动恢复 workflow 执行。
    """
    try:
        result = await approval_service.submit_approval(
            case_id=case_id,
            action_id=action_id,
            approver_role=req.approver_role,
            approver_user=req.approver_user,
            decision=req.decision,
            comment=req.comment,
        )
    except ApprovalError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # 全部批准 → 恢复 workflow 执行
    if result.get("all_approved"):
        await resume_workflow(case_id)

    return ApiResponse(success=True, data=result)


@router.get("/{case_id}/pending", response_model=ApiResponse)
async def list_pending_approvals(
    case_id: str, session: AsyncSession = Depends(get_session)
) -> ApiResponse:
    """列出待审批的 L2 动作"""
    from app.db.repositories import CaseRepository

    repo = CaseRepository(session)
    case = await repo.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    pending = []
    for action in case.proposed_actions:
        if not action.approval_required:
            continue
        approval = case.approvals.get(action.action_id)
        pending.append(
            {
                "action_id": action.action_id,
                "action_type": action.action_type.value,
                "target": action.target,
                "autonomy_level": action.autonomy_level.value,
                "risk": action.risk.value,
                "requires_double_sign": action.requires_double_sign,
                "current_decision": approval.decision if approval else "pending",
                "approved_by": approval.approver_role if approval else None,
            }
        )
    return ApiResponse(success=True, data=pending)
