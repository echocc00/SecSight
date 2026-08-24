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

    # 同步索引到 OpenSearch (可选,失败不阻塞)
    await _try_index_opensearch(alert)

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


async def _try_index_opensearch(alert) -> None:
    """同步索引告警到 OpenSearch (可选,失败不阻塞主流程)"""
    from app.core.config import settings

    if not settings.enable_opensearch:
        return
    try:
        from app.integrations.opensearch import get_opensearch

        client = get_opensearch()
        await client.index_alert(alert)
    except Exception as e:  # noqa: BLE001
        # OpenSearch 故障不影响主流程
        import structlog

        structlog.get_logger().warning("opensearch.index_failed", error=str(e))


@router.get("/search", response_model=ApiResponse)
async def search_alerts(
    q: str,
    size: int = 20,
    hours: int = 24,
    session: AsyncSession = Depends(get_session),
) -> ApiResponse:
    """全文检索告警 (OpenSearch 优先,未启用时降级查 PG)

    搜索进程名/IP/规则/消息内容。OpenSearch 启用走向量检索,
    否则降级扫描 Case.alerts JSON (dev/mock 模式可用)。
    """
    from app.core.config import settings

    if settings.enable_opensearch:
        try:
            from app.integrations.opensearch import get_opensearch

            client = get_opensearch()
            results = await client.search_alerts(query=q, size=size, time_range_hours=hours)
            return ApiResponse(
                success=True,
                data={"query": q, "source": "opensearch", "count": len(results), "hits": results},
            )
        except Exception as e:  # noqa: BLE001
            # OpenSearch 故障降级 PG,不阻断搜索
            import structlog

            structlog.get_logger().warning("alert.search.os_fallback", error=str(e))

    # PG fallback: 扫描近 N 小时 Case 的 alerts JSON
    from datetime import datetime, timedelta

    from sqlalchemy import select

    from app.db.models import CaseModel

    since = datetime.utcnow() - timedelta(hours=hours)
    needle = q.lower()
    stmt = (
        select(CaseModel)
        .where(CaseModel.created_at >= since)
        .order_by(CaseModel.created_at.desc())
        .limit(200)
    )
    result = await session.execute(stmt)
    hits: list[dict] = []
    for m in result.scalars():
        for a in (m.alerts or []):
            blob = " ".join(
                str(v)
                for v in [
                    a.get("message", ""),
                    a.get("src_ip", ""),
                    a.get("dst_ip", ""),
                    a.get("rule_id", ""),
                    (a.get("raw") or {}).get("process_name", ""),
                    a.get("source", ""),
                ]
            ).lower()
            if needle in blob:
                hits.append(
                    {
                        "case_id": m.case_id,
                        "case_status": m.status,
                        "playbook_id": m.playbook_id,
                        "alert": a,
                        "matched_at": m.created_at.isoformat(),
                    }
                )
                if len(hits) >= size:
                    break
        if len(hits) >= size:
            break
    return ApiResponse(
        success=True,
        data={"query": q, "source": "postgres_fallback", "count": len(hits), "hits": hits},
    )


@router.get("/devices/supported", response_model=ApiResponse)
async def list_supported_devices() -> ApiResponse:
    """列出支持的国产设备类型"""
    from app.integrations.domestic_devices import list_supported_devices as _list

    return ApiResponse(success=True, data={"devices": _list()})


@router.post("/devices/{device_type}/webhook", response_model=ApiResponse)
async def device_webhook(
    device_type: str,
    payload: dict,
    session: AsyncSession = Depends(get_session),
) -> ApiResponse:
    """接收国产设备告警推送 (奇安信/天融信/深信服/绿盟)

    device_type: qianxin | topsec | sangfor | nsfocus
    payload: 设备原始告警 JSON (各设备格式不同,由适配器归一化)
    """
    from app.integrations.domestic_devices import parse_device_alert, DeviceParseError

    try:
        alert = parse_device_alert(device_type, payload)
    except DeviceParseError as e:
        return ApiResponse(success=False, error=str(e))

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
    await _try_index_opensearch(alert)

    return ApiResponse(
        success=True,
        data={
            "case_id": case.case_id,
            "playbook_id": playbook_id,
            "alert_id": alert.alert_id,
            "severity": alert.severity.value,
            "source": alert.source,
        },
    )
