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


@router.post("/wazuh-webhook", response_model=ApiResponse)
async def wazuh_webhook(
    payload: dict, session: AsyncSession = Depends(get_session)
) -> ApiResponse:
    """接收 Wazuh 主动推送的告警 (webhook) → 转 Alert → 触发编排

    Wazuh 配置 custom integration 将告警 POST 到此端点。
    payload 格式 (Wazuh standard alert JSON):
      {"timestamp","rule":{"id","level","description","groups","mitre"},
       "data":{"srcip","dstip","srcuser"}, "agent":{"name","id"}, "full_log"}

    与 /wazuh/poll 相比:webhook 是实时推送,poll 是主动拉取。
    生产推荐 webhook (TTTR 更低)。
    """
    from app.integrations.wazuh import parse_wazuh_alert

    try:
        alert = parse_wazuh_alert(payload)
    except Exception as e:
        return ApiResponse(success=False, error=f"Wazuh 告警解析失败: {e}")

    repo = CaseRepository(session)
    case = await repo.create_from_alert(alert)

    playbook = playbook_engine.match(alert)
    playbook_id = None
    if playbook:
        playbook_id = playbook.id
        await repo.update_status(case.case_id, CaseStatus.investigating)
        from app.db.models import CaseModel

        model = await session.get(CaseModel, case.case_id)
        if model:
            model.playbook_id = playbook.id
            await session.commit()

    await trigger_workflow(case.case_id, playbook_id)

    return ApiResponse(
        success=True,
        data={
            "case_id": case.case_id,
            "playbook_id": playbook_id,
            "alert_id": alert.alert_id,
            "severity": alert.severity.value,
            "source": "wazuh_webhook",
        },
    )


@router.post("/wazuh/poll", response_model=ApiResponse)
async def poll_wazuh_alerts(
    limit: int = 20,
    session: AsyncSession = Depends(get_session),
) -> ApiResponse:
    """从 Wazuh 拉取最近告警 → 自动建 Case + 匹配剧本 + 触发编排

    两种模式:
      - 文件模式 (WAZUH_ALERTS_JSON 已设): 读 alerts.json
      - API 模式: 查 Wazuh Manager API /security/events
    """
    from app.core.config import settings

    alerts: list = []
    try:
        if settings.wazuh_alerts_json:
            from app.integrations.wazuh import read_alerts_json

            raw_alerts = read_alerts_json(settings.wazuh_alerts_json, max_alerts=limit)
            alerts = raw_alerts
        else:
            from app.integrations.wazuh import WazuhClient

            client = WazuhClient(
                base_url=settings.wazuh_api_url,
                username=settings.wazuh_api_user,
                password=settings.wazuh_api_password,
            )
            alerts = await client.query_alerts(limit=limit)
    except Exception as e:
        return ApiResponse(success=False, error=f"Wazuh 接入失败: {e}")

    if not alerts:
        return ApiResponse(success=True, data={"polled": 0, "cases": []})

    # 每条告警建 Case + 匹配剧本 + 触发编排
    from app.db.repositories import CaseRepository
    from app.models.schemas import CaseStatus
    from app.playbooks.engine import engine as playbook_engine
    from app.agents.workflow import trigger_workflow

    repo = CaseRepository(session)
    cases: list[dict] = []
    for alert in alerts:
        case = await repo.create_from_alert(alert)
        playbook = playbook_engine.match(alert)
        playbook_id = playbook.id if playbook else None
        if playbook:
            await repo.update_status(case.case_id, CaseStatus.investigating)
            from app.db.models import CaseModel
            model = await session.get(CaseModel, case.case_id)
            if model:
                model.playbook_id = playbook.id
                await session.commit()
        await trigger_workflow(case.case_id, playbook_id)
        cases.append(
            {
                "case_id": case.case_id,
                "playbook_id": playbook_id,
                "severity": alert.severity.value,
                "rule_id": alert.rule_id,
            }
        )

    return ApiResponse(
        success=True,
        data={"polled": len(alerts), "cases": cases},
    )
