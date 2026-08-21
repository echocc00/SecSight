"""告警 API + mock 注入"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.workflow import trigger_workflow
from app.api.schemas import AlertInjectRequest, ApiResponse
from app.db.database import get_session
from app.db.repositories import CaseRepository
from app.mock.alerts import MOCK_ALERTS
from app.models.schemas import CaseStatus
from app.playbooks.engine import engine as playbook_engine

router = APIRouter()


@router.post("/inject", response_model=ApiResponse)
async def inject_alert(
    req: AlertInjectRequest, session: AsyncSession = Depends(get_session)
) -> ApiResponse:
    """注入 mock 告警 → 自动建 Case + 匹配剧本 + 触发编排

    垂直切片入口: 调用此端点模拟 Wazuh/Suricata 上报告警。
    """
    builder = MOCK_ALERTS.get(req.alert_type)
    if not builder:
        return ApiResponse(success=False, error=f"未知告警类型: {req.alert_type}")

    alert = builder(
        hostname=req.hostname,
        src_ip=req.src_ip,
        dst_ip=req.dst_ip or "192.168.64.1",
        pid=req.pid or 28371,
    )

    repo = CaseRepository(session)
    case = await repo.create_from_alert(alert)

    # 匹配剧本
    playbook = playbook_engine.match(alert)
    playbook_id = None
    if playbook:
        playbook_id = playbook.id
        await repo.update_status(case.case_id, CaseStatus.investigating)
        # 写入 playbook_id (直接更新 model 字段)
        from app.db.models import CaseModel
        model = await session.get(CaseModel, case.case_id)
        if model:
            model.playbook_id = playbook.id
            await session.commit()

    # 触发 LangGraph 编排
    await trigger_workflow(case.case_id, playbook_id)

    return ApiResponse(
        success=True,
        data={
            "case_id": case.case_id,
            "playbook_id": playbook_id,
            "playbook_name": playbook.name if playbook else None,
            "alert_id": alert.alert_id,
            "severity": alert.severity.value,
        },
    )


@router.get("/types", response_model=ApiResponse)
async def list_alert_types() -> ApiResponse:
    """可用 mock 告警类型"""
    return ApiResponse(success=True, data={"types": list(MOCK_ALERTS.keys())})
