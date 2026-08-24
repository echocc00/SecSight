"""LangGraph 编排节点实现 (各节点真实逻辑,用 mock 服务)"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import uuid4

from app.db.database import async_session
from app.db.repositories import AuditLogRepository, CaseRepository, EvidencePackRepository
from app.llm_gateway.mock import get_llm
from app.models.schemas import (
    Action,
    ActionType,
    ApprovalRecord,
    AutonomyLevel,
    CaseStatus,
    ExecutionStep,
    JudgmentReport,
    Severity,
)
from app.retrieval.mock import get_retriever
from app.playbooks.engine import engine as playbook_engine
from app.playbooks.models import ContainmentActionConfig, Playbook

import structlog

log = structlog.get_logger()


async def _audit(action: str, actor: str, case_id: str, detail: dict | None = None) -> None:
    """写审计日志 (独立 session)"""
    async with async_session() as session:
        audit = AuditLogRepository(session)
        await audit.record(action=action, actor=actor, case_id=case_id, detail=detail)


def build_analysis_prompt(case_data: dict, knowledge: list[dict]) -> list[dict]:
    """构造研判 prompt (场景由告警内容推断,不硬编码)"""
    alerts = case_data.get("alerts", [])
    alerts_summary = json.dumps(alerts[:5], ensure_ascii=False)
    knowledge_ctx = json.dumps(knowledge, ensure_ascii=False)
    # 从首个告警提取场景线索 (message + MITRE 技术),供 LLM/场景检测使用
    scene_hint = ""
    if alerts:
        a0 = alerts[0]
        scene_hint = (
            f"告警消息: {a0.get('message','')}; "
            f"MITRE技术: {', '.join(a0.get('mitre_techniques',[]))}"
        )
    return [
        {
            "role": "system",
            "content": (
                "你是 SecSight 安全研判助手。基于告警和 ATT&CK 知识输出结构化研判报告。"
                "必须从检索到的 ATT&CK 知识中选 TTP,不得编造。"
            ),
        },
        {
            "role": "user",
            "content": (
                f"【告警】\n{alerts_summary}\n\n"
                f"【检索知识】\n{knowledge_ctx}\n\n"
                f"【场景线索】{scene_hint}"
            ),
        },
    ]


def _infer_action_type(action_id: str, explicit: str = "") -> ActionType:
    """从 action id 或显式字段推断 ActionType"""
    if explicit:
        try:
            return ActionType(explicit)
        except ValueError:
            pass
    aid = action_id.lower()
    for at in ActionType:
        if at.value in aid:
            return at
    return ActionType.notify


def build_action_from_config(
    cfg: ContainmentActionConfig, playbook_id: str
) -> Action:
    """剧本 Action 配置 → Action 域对象"""
    autonomy = AutonomyLevel(cfg.autonomy)
    return Action(
        action_id=str(uuid4()),
        action_type=_infer_action_type(cfg.id, cfg.action_type),
        target=cfg.parameters,
        autonomy_level=autonomy,
        risk=Severity(cfg.risk),
        approval_required=autonomy == AutonomyLevel.L2,
        requires_double_sign=cfg.approval == "double",
        timeout_seconds=300,
        rollback_action_id=cfg.rollback,
        playbook_id=playbook_id,
    )


async def ingest_alerts_node(state: dict) -> dict:
    """节点: Case 已建,标记 investigating"""
    case_id = state["case_id"]
    async with async_session() as session:
        repo = CaseRepository(session)
        await repo.update_status(case_id, CaseStatus.investigating)
        await _audit("case_ingested", "system", case_id, {"playbook": state.get("current_playbook_id")})
    log.info("node.ingest_alerts", case_id=case_id)
    return state


async def retrieve_knowledge_node(state: dict) -> dict:
    """节点: RAG 召回 ATT&CK / 历史案例"""
    retriever = get_retriever()
    alerts = state.get("raw_alerts", [])
    query = json.dumps(alerts[:3], ensure_ascii=False)
    chunks = await retriever.search(query, top_k=5)
    state["retrieved_knowledge"] = chunks
    log.info("node.retrieve_knowledge", case_id=state["case_id"], chunks=len(chunks))
    return state


async def enrich_ioc_node(state: dict) -> dict:
    """节点: 提取告警 IoC,多源情报富化,结果进 enriched_context

    真实模式 (enable_threat_intel=True): 查 AbuseIPDB+OTX,合成置信度
    mock 模式: 返回预设矿池/恶意 IP 结果
    单 IoC 失败不影响整体,全失败降级 mock
    """
    from app.threat_intel.service import get_threat_intel_service

    service = get_threat_intel_service()
    alerts = state.get("raw_alerts", [])
    enriched: dict = dict(state.get("enriched_context") or {})

    ioc_summary: list[dict] = []
    for alert in alerts[:3]:  # 取前 3 条告警的 IoC
        results = await service.enrich_alert(alert)
        for key, res in results.items():
            ioc_summary.append(
                {
                    "ioc": key,
                    "provider": res.provider,
                    "confidence": res.confidence,
                    "malicious": res.malicious,
                    "ttps": res.mitre_ttps,
                    "tags": res.tags,
                }
            )

    enriched["iocs"] = ioc_summary
    state["enriched_context"] = enriched

    # 持久化到 Case
    async with async_session() as session:
        repo = CaseRepository(session)
        await repo.update_enriched_context(state["case_id"], enriched)
        await _audit(
            "ioc_enriched",
            "threat_intel",
            state["case_id"],
            {"ioc_count": len(ioc_summary)},
        )

    log.info(
        "node.enrich_ioc",
        case_id=state["case_id"],
        iocs_enriched=len(ioc_summary),
    )
    return state


async def analyze_node(state: dict) -> dict:
    """节点: mock LLM 输出结构化研判报告"""
    from app.core.metrics import record_case_created, record_llm_call

    llm = get_llm()
    case_id = state["case_id"]

    async with async_session() as session:
        repo = CaseRepository(session)
        case = await repo.get(case_id)
        if not case:
            return state

        messages = build_analysis_prompt(
            case.model_dump(mode="json"), state.get("retrieved_knowledge", [])
        )
        report = await llm.tier2_structured(messages, JudgmentReport)
        await repo.update_judgment(case_id, report)
        state["judgment"] = report.model_dump(mode="json")
        await _audit("analysis_done", "llm", case_id, {"confidence": report.confidence})

        # 指标埋点: LLM 调用 (判断是否降级)
        used_real = getattr(llm, "last_used", "real") == "real"
        record_llm_call("tier2", success=used_real)

    log.info("node.analyze", case_id=case_id, severity=report.severity.value, confidence=report.confidence)
    return state


async def plan_actions_node(state: dict) -> dict:
    """节点: 从剧本提取 containment_actions → Action 列表"""
    playbook_id = state.get("current_playbook_id")
    if not playbook_id:
        return state

    playbook = playbook_engine.get_by_id(playbook_id)
    if not playbook:
        return state

    actions = [build_action_from_config(cfg, playbook_id) for cfg in playbook.containment_actions]
    state["proposed_actions"] = [a.model_dump(mode="json") for a in actions]

    async with async_session() as session:
        repo = CaseRepository(session)
        await repo.update_actions(state["case_id"], actions)
        # 初始化 approval_status
        approval_status = {}
        for a in actions:
            if a.approval_required:
                approval_status[a.action_id] = "pending"
        state["approval_status"] = approval_status

    log.info("node.plan_actions", case_id=state["case_id"], actions=len(actions))
    return state


async def human_approve_node(state: dict) -> dict:
    """节点: L2 审批 gate — 标记 pending_approval,推送飞书/钉钉通知,暂停等待人工"""
    case_id = state["case_id"]
    async with async_session() as session:
        repo = CaseRepository(session)
        await repo.update_status(case_id, CaseStatus.pending_approval)
        case = await repo.get(case_id)
        await _audit("awaiting_approval", "system", case_id, {})

        # 推送飞书/钉钉审批通知 (失败不阻塞)
        if case:
            from app.integrations.notify import notify_approval

            import os

            callback_base = os.environ.get("SECSIGHT_CALLBACK_BASE", "http://localhost:8000")
            severity = case.judgment.severity.value if case.judgment else "medium"
            for action in case.proposed_actions:
                if action.approval_required:
                    try:
                        await notify_approval(
                            case_id, action.action_id, action.action_type.value, severity, callback_base
                        )
                    except Exception as e:  # noqa: BLE001
                        log.warning("approval.notify_failed", error=str(e))
    log.info("node.human_approve", case_id=case_id, note="workflow paused for L2 approval")
    return state


async def execute_node(state: dict) -> dict:
    """节点: 执行已批准的 Action (mock executor)"""
    from app.core.metrics import record_execution
    from app.execution.mock import get_executor

    case_id = state["case_id"]
    executor = get_executor()

    async with async_session() as session:
        repo = CaseRepository(session)
        case = await repo.get(case_id)
        if not case:
            return state

        for action in case.proposed_actions:
            # L2 需审批通过才执行;L3/L4/L5 直接执行
            if action.autonomy_level == AutonomyLevel.L2:
                approval = case.approvals.get(action.action_id)
                if not approval or approval.decision != "approved":
                    continue  # 未批准跳过

            step = ExecutionStep(
                action_id=action.action_id,
                status="executing",
                started_at=datetime.utcnow(),
            )
            result = await executor.execute(action, case_id=case_id)
            step.status = "success" if result.get("success") else "failed"
            step.finished_at = datetime.utcnow()
            step.result = result
            await repo.append_execution(case_id, step)

            # 指标埋点
            record_execution(action.action_type.value, success=step.status == "success")

        await repo.update_status(case_id, CaseStatus.contained)

    log.info("node.execute", case_id=case_id)
    return state


async def escalate_node(state: dict) -> dict:
    """节点: 审批拒绝/超时 → 升级"""
    case_id = state["case_id"]
    async with async_session() as session:
        repo = CaseRepository(session)
        await _audit("escalated_to_soc_manager", "system", case_id, {})
    log.info("node.escalate", case_id=case_id)
    return state


async def update_case_node(state: dict) -> dict:
    """节点: 生成 Evidence Pack + 关闭 Case + L3 沉淀"""
    from app.core.metrics import record_case_created, record_tttr

    case_id = state["case_id"]

    async with async_session() as session:
        repo = CaseRepository(session)
        case = await repo.get(case_id)
        if not case:
            return state

        # 计算 TTTR
        tttr = int((datetime.utcnow() - case.created_at).total_seconds())
        record_tttr(tttr)

        # 构建 Evidence Pack
        evidence_repo = EvidencePackRepository(session)
        pack = {
            "case_id": case_id,
            "process_tree": case.enriched_context.get("process_tree", {}),
            "timeline": [
                {
                    "ts": e.started_at.isoformat() if e.started_at else None,
                    "action": e.action_id,
                    "status": e.status,
                }
                for e in case.execution_log
            ],
            "llm_reasoning_trace": [case.judgment.model_dump(mode="json")] if case.judgment else [],
            "iocs": case.enriched_context.get("iocs", {}),
            "mitre_mapping": {
                "tactics": case.alerts[0].mitre_tactics if case.alerts else [],
                "techniques": case.alerts[0].mitre_techniques if case.alerts else [],
            },
        }
        pack_id = await evidence_repo.create(pack)
        await repo.set_evidence_pack(case_id, pack_id)
        await repo.close(case_id, tttr)
        await _audit("case_closed", "system", case_id, {"tttr": tttr, "pack_id": pack_id})
        record_case_created("resolved", case.playbook_id or "")

    log.info("node.update_case", case_id=case_id, tttr=tttr)
    return state
