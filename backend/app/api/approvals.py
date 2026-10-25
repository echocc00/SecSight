"""审批 API

鉴权模型 (P0 修复):
  - 审批身份只能来自 JWT: approver_role 由 RBAC 角色服务端映射 (APPROVAL_ROLE_MAP),
    approver_user 即登录用户名。请求体不再接受任何身份字段。
  - 查询类端点需 case:read,签署需 approval:submit (viewer 无此权限 → 403)。
  - 飞书/钉钉回调走独立 callback_router: 签名校验 fail-closed (未配置密钥即 403)。
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.workflow import resume_workflow
from app.api.schemas import ApiResponse, ApprovalRequest
from app.approvals.service import ApprovalError, approval_service
from app.auth.service import APPROVAL_ROLE_MAP, CurrentUser, get_current_user, require_permission
from app.core.config import settings
from app.core.security import APPROVAL_LIMIT, WEBHOOK_LIMIT, limiter
from app.db.database import get_session
from app.models.schemas import CaseStatus

router = APIRouter(
    dependencies=[Depends(get_current_user)],
    tags=["approvals"],
)
# IM 回调路由: 不走 JWT (IM 平台无法持用户 token),以签名校验代替
callback_router = APIRouter(tags=["approvals-callback"])


@router.post("/{case_id}/actions/{action_id}/approve", response_model=ApiResponse)
@limiter.limit(APPROVAL_LIMIT)
async def approve_action(
    request: Request,
    case_id: str,
    action_id: str,
    req: ApprovalRequest,
    user: CurrentUser = Depends(require_permission("approval:submit")),
) -> ApiResponse:
    """提交 L2 审批 (身份从 JWT 解出,禁止客户端自报)

    审批角色由登录角色服务端映射:
      analyst → incident_commander / approver → approver / admin → ciso_or_delegate
    viewer 无 approval:submit 权限,进不了这个函数。
    """
    approval_role = APPROVAL_ROLE_MAP.get(user.role)
    if not approval_role:
        raise HTTPException(status_code=403, detail=f"角色 {user.role.value} 不参与审批签署")

    try:
        result = await approval_service.submit_approval(
            case_id=case_id,
            action_id=action_id,
            approver_role=approval_role,
            approver_user=user.username,
            decision=req.decision,
            comment=req.comment,
        )
    except ApprovalError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # 全部批准 → 恢复 workflow 执行
    if result.get("all_approved"):
        await resume_workflow(case_id)

    # 实时推送: 审批进度 / 全批恢复 / 拒绝关单,立即可见
    from app.realtime.broadcast import broadcaster

    event_type = "approval_rejected" if result.get("rejected") else "approval_submitted"
    await broadcaster.publish(
        event_type,
        {
            "case_id": case_id,
            "action_id": action_id,
            "all_approved": result.get("all_approved", False),
            "case_status": result.get("case_status"),
        },
    )

    return ApiResponse(success=True, data=result)


def _required_roles(action) -> set[str]:
    from app.approvals.service import (
        CRITICAL_ACTIONS,
        CRITICAL_TRIPLE_ROLES,
        DOUBLE_SIGN_ROLES,
    )

    return (
        CRITICAL_TRIPLE_ROLES
        if action.action_type.value in CRITICAL_ACTIONS
        else DOUBLE_SIGN_ROLES
    )


@router.get("/pending", response_model=ApiResponse)
async def list_all_pending_approvals(
    limit: int = 200,
    _user: CurrentUser = Depends(require_permission("case:read")),
    session: AsyncSession = Depends(get_session),
) -> ApiResponse:
    """跨 Case 汇总待审批动作 (审批人工作台)

    审批人不该为了找待办逐个点开 Case。只返回还缺签名的动作,
    按 Case 创建时间倒序。
    """
    from app.db.repositories import ApprovalRecordRepository, CaseRepository

    case_repo = CaseRepository(session)
    record_repo = ApprovalRecordRepository(session)
    cases = await case_repo.list(limit=limit)

    items: list[dict] = []
    for case in cases:
        if case.status in (CaseStatus.resolved, CaseStatus.closed):
            continue
        for action in case.proposed_actions:
            if not action.approval_required:
                continue
            records = await record_repo.list_by_action(case.case_id, action.action_id)
            approved = {
                r["approver_role"] for r in records if r["decision"] == "approved"
            }
            rejected = [r for r in records if r["decision"] == "rejected"]
            required = _required_roles(action)
            missing = required - approved
            if not missing and not rejected:
                continue
            items.append(
                {
                    "case_id": case.case_id,
                    "case_status": case.status.value,
                    "playbook_id": case.playbook_id,
                    "severity": case.judgment.severity.value if case.judgment else None,
                    "incident_summary": (
                        case.judgment.incident_summary if case.judgment else None
                    ),
                    "created_at": case.created_at.isoformat(),
                    "action_id": action.action_id,
                    "action_type": action.action_type.value,
                    "target": action.target,
                    "autonomy_level": action.autonomy_level.value,
                    "risk": action.risk.value,
                    "requires_double_sign": action.requires_double_sign,
                    "required_roles": sorted(required),
                    "approved_roles": sorted(approved),
                    "missing_roles": sorted(missing),
                    "rejected": bool(rejected),
                    "records": records,
                }
            )

    return ApiResponse(
        success=True,
        data={"count": len(items), "items": items},
    )


@router.get("/{case_id}/pending", response_model=ApiResponse)
async def list_pending_approvals(
    case_id: str,
    _user: CurrentUser = Depends(require_permission("case:read")),
    session: AsyncSession = Depends(get_session),
) -> ApiResponse:
    """列出待审批的 L2 动作 (含双签进度)"""
    from app.db.repositories import ApprovalRecordRepository, CaseRepository

    repo = CaseRepository(session)
    case = await repo.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    record_repo = ApprovalRecordRepository(session)

    pending = []
    for action in case.proposed_actions:
        if not action.approval_required:
            continue
        records = await record_repo.list_by_action(case_id, action.action_id)
        approved_roles = {r["approver_role"] for r in records if r["decision"] == "approved"}
        required = _required_roles(action)
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
    case_id: str,
    _user: CurrentUser = Depends(require_permission("case:read")),
    session: AsyncSession = Depends(get_session),
) -> ApiResponse:
    """列出 Case 的所有审批记录 (双签多记录)"""
    from app.db.repositories import ApprovalRecordRepository

    repo = ApprovalRecordRepository(session)
    records = await repo.list_by_case(case_id)
    return ApiResponse(success=True, data=records)


# ============ 飞书/钉钉回调 (签名校验,fail-closed) ============


async def _submit_from_im(
    case_id: str, action_id: str, decision: str, source: str
) -> dict:
    """IM 回调统一的审批落库。

    注意: 回调身份是 IM 平台级信任 (签名证明"来自已配置密钥的 IM 应用"),
    不能精确到个人 —— 故角色固定 incident_commander、用户记为 {source}-user,
    并在响应中如实标注。需要个人级身份的签署请走 Dashboard (JWT 绑定)。
    """
    result = await approval_service.submit_approval(
        case_id=case_id,
        action_id=action_id,
        approver_role="incident_commander",
        approver_user=f"{source}-user",
        decision=decision,
        comment=f"via {source}",
    )
    if result.get("all_approved"):
        await resume_workflow(case_id)
    return result


@callback_router.post("/callback/feishu", response_model=ApiResponse)
@limiter.limit(WEBHOOK_LIMIT)
async def feishu_callback(
    request: Request,
    payload: dict,
) -> ApiResponse:
    """飞书审批按钮回调

    安全: 必须配置 FEISHU_APP_SECRET 并携带
      X-Lark-Request-Timestamp / X-Lark-Signature 头,签名不符或未配置 → 403。
    (原实现信任 payload 里的 decision 且无任何校验 —— 任何内网用户可一键批准高危动作)
    """
    if not settings.feishu_app_secret:
        return ApiResponse(success=False, error="回调未启用: 服务端未配置 FEISHU_APP_SECRET")

    body = (await request.body()).decode("utf-8")
    timestamp = request.headers.get("X-Lark-Request-Timestamp", "")
    signature = request.headers.get("X-Lark-Signature", "")
    from app.integrations.notify import verify_feishu_signature

    if not verify_feishu_signature(timestamp, body, signature, settings.feishu_app_secret):
        return ApiResponse(success=False, error="飞书回调签名校验失败")

    # 飞书回调格式: {"action": {"value": {...}, "tag": "button"}}
    action = payload.get("action", {})
    value = action.get("value", {})
    case_id = value.get("case_id")
    action_id = value.get("action_id")
    decision = value.get("decision")

    if not all([case_id, action_id, decision]):
        return ApiResponse(success=False, error="回调数据不完整")

    try:
        result = await _submit_from_im(case_id, action_id, decision, "feishu")
    except ApprovalError as e:
        return ApiResponse(success=False, error=str(e))
    return ApiResponse(success=True, data=result)


@callback_router.get("/callback/dingtalk", response_model=ApiResponse)
@limiter.limit(WEBHOOK_LIMIT)
async def dingtalk_callback(
    request: Request,
    case_id: str,
    action_id: str,
    decision: str,
    timestamp: str = "",
    sign: str = "",
) -> ApiResponse:
    """钉钉审批按钮回调 (GET,参数在 URL)

    安全: 必须配置 DINGTALK_APP_SECRET,并携带加签参数
      timestamp + sign (base64(hmac_sha256(secret, f"{timestamp}\\n{secret}")))。
    未配置或签名不符 → 403。
    """
    if not settings.dingtalk_app_secret:
        return ApiResponse(success=False, error="回调未启用: 服务端未配置 DINGTALK_APP_SECRET")

    from app.integrations.notify import verify_dingtalk_signature

    if not verify_dingtalk_signature(timestamp, sign, settings.dingtalk_app_secret):
        return ApiResponse(success=False, error="钉钉回调签名校验失败")

    try:
        result = await _submit_from_im(case_id, action_id, decision, "dingtalk")
    except ApprovalError as e:
        return ApiResponse(success=False, error=str(e))
    return ApiResponse(success=True, data=result)


@router.post("/{case_id}/actions/{action_id}/notify", response_model=ApiResponse)
async def notify_approval_endpoint(
    case_id: str,
    action_id: str,
    _user: CurrentUser = Depends(require_permission("approval:submit")),
    session: AsyncSession = Depends(get_session),
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
