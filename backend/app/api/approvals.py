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
    """列出待审批的 L2 动作 (含双签进度)"""
    from app.db.repositories import ApprovalRecordRepository, CaseRepository

    repo = CaseRepository(session)
    case = await repo.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    record_repo = ApprovalRecordRepository(session)
    from app.approvals.service import CRITICAL_ACTIONS, DOUBLE_SIGN_ROLES, CRITICAL_TRIPLE_ROLES

    pending = []
    for action in case.proposed_actions:
        if not action.approval_required:
            continue
        records = await record_repo.list_by_action(case_id, action.action_id)
        approved_roles = {r["approver_role"] for r in records if r["decision"] == "approved"}
        required = (
            CRITICAL_TRIPLE_ROLES
            if action.action_type.value in CRITICAL_ACTIONS
            else DOUBLE_SIGN_ROLES
        )
        pending.append(
            {
                "action_id": action.action_id,
                "action_type": action.action_type.value,
                "target": action.target,
                "autonomy_level": action.autonomy_level.value,
                "risk": action.risk.value,
                "requires_double_sign": action.requires_double_sign,
                "required_roles": list(required),
                "approved_roles": list(approved_roles),
                "missing_roles": list(required - approved_roles),
                "records": records,
            }
        )
    return ApiResponse(success=True, data=pending)


@router.get("/{case_id}/records", response_model=ApiResponse)
async def list_approval_records(
    case_id: str, session: AsyncSession = Depends(get_session)
) -> ApiResponse:
    """列出 Case 的所有审批记录 (双签多记录)"""
    from app.db.repositories import ApprovalRecordRepository

    repo = ApprovalRecordRepository(session)
    records = await repo.list_by_case(case_id)
    return ApiResponse(success=True, data=records)


# ============ 飞书/钉钉回调 ============


@router.post("/callback/feishu", response_model=ApiResponse)
async def feishu_callback(
    payload: dict, session: AsyncSession = Depends(get_session)
) -> ApiResponse:
    """飞书审批按钮回调

    payload.value 含 case_id/action_id/decision (来自卡片按钮 value)
    """
    # 飞书回调格式: {"action": {"value": {...}, "tag": "button"}}
    action = payload.get("action", {})
    value = action.get("value", {})
    case_id = value.get("case_id")
    action_id = value.get("action_id")
    decision = value.get("decision")

    if not all([case_id, action_id, decision]):
        return ApiResponse(success=False, error="回调数据不完整")

    try:
        result = await approval_service.submit_approval(
            case_id=case_id,
            action_id=action_id,
            approver_role="incident_commander",
            approver_user="feishu-user",
            decision=decision,
            comment="via feishu",
        )
    except ApprovalError as e:
        return ApiResponse(success=False, error=str(e))

    if result.get("all_approved"):
        await resume_workflow(case_id)
    return ApiResponse(success=True, data=result)


@router.get("/callback/dingtalk", response_model=ApiResponse)
async def dingtalk_callback(
    case_id: str,
    action_id: str,
    decision: str,
    session: AsyncSession = Depends(get_session),
) -> ApiResponse:
    """钉钉审批按钮回调 (GET,参数在 URL)"""
    try:
        result = await approval_service.submit_approval(
            case_id=case_id,
            action_id=action_id,
            approver_role="incident_commander",
            approver_user="dingtalk-user",
            decision=decision,
            comment="via dingtalk",
        )
    except ApprovalError as e:
        return ApiResponse(success=False, error=str(e))

    if result.get("all_approved"):
        await resume_workflow(case_id)
    return ApiResponse(success=True, data=result)


@router.post("/{case_id}/actions/{action_id}/notify", response_model=ApiResponse)
async def notify_approval_endpoint(
    case_id: str, action_id: str, session: AsyncSession = Depends(get_session)
) -> ApiResponse:
    """手动触发审批通知推送 (飞书/钉钉)

    正常流程由 human_approve 节点自动触发,此端点供手动重推。
    """
    from app.db.repositories import CaseRepository
    from app.integrations.notify import notify_approval

    repo = CaseRepository(session)
    case = await repo.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    action = next((a for a in case.proposed_actions if a.action_id == action_id), None)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    severity = case.judgment.severity.value if case.judgment else "medium"
    import os

    callback_base = os.environ.get("SECSIGHT_CALLBACK_BASE", "http://localhost:8000")
    result = await notify_approval(
        case_id, action_id, action.action_type.value, severity, callback_base
    )
    return ApiResponse(success=True, data=result)
