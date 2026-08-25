"""LangGraph 编排 (裁决 §4)

双模式:
  - SQLite/默认: 两段式 workflow (trigger 前半段 / resume 后半段)
  - Postgres + ENABLE_CHECKPOINTER: 单一 workflow + AsyncPostgresSaver
    + interrupt_before 真正中断恢复

5 级自主性路由: L2 动作 interrupt_before 人工审批 gate。
"""
from __future__ import annotations

from typing import TypedDict

from langgraph.graph import END, StateGraph

from app.agents.nodes import (
    analyze_node,
    enrich_ioc_node,
    escalate_node,
    execute_node,
    human_approve_node,
    ingest_alerts_node,
    plan_actions_node,
    retrieve_knowledge_node,
    update_case_node,
)
from app.db.database import async_session
from app.db.repositories import CaseRepository
from app.models.schemas import AutonomyLevel, CaseStatus

import structlog

log = structlog.get_logger()


class SecSightState(TypedDict, total=False):
    case_id: str
    raw_alerts: list[dict]
    enriched_context: dict
    retrieved_knowledge: list[dict]
    judgment: dict | None
    proposed_actions: list[dict]
    approval_status: dict
    execution_log: list[dict]
    current_playbook_id: str | None


# ============ 路由函数 ============


def route_after_plan(state: SecSightState) -> str:
    """plan_actions 后路由:

    有 L2 待审批动作 → human_approve (暂停等审批,走 resume)
    无 L2 动作 (全 L3/L4/L5) → execute (自动闭环)
    """
    actions = state.get("proposed_actions", [])
    has_l2 = any(a.get("autonomy_level") == AutonomyLevel.L2.value for a in actions)
    return "human_approve" if has_l2 else "execute"


# ============ 前半段 workflow: trigger ============


def build_trigger_workflow():
    """ingest → retrieve → analyze → plan → [路由]

    有 L2 → human_approve(标记pending) → END (等外部审批,走 resume)
    无 L2 → execute → update_case → END (自动闭环)
    """
    wf = StateGraph(SecSightState)
    wf.add_node("ingest_alerts", ingest_alerts_node)
    wf.add_node("retrieve_knowledge", retrieve_knowledge_node)
    wf.add_node("enrich_ioc", enrich_ioc_node)
    wf.add_node("analyze", analyze_node)
    wf.add_node("plan_actions", plan_actions_node)
    wf.add_node("human_approve", human_approve_node)
    wf.add_node("execute", execute_node)
    wf.add_node("update_case", update_case_node)

    wf.set_entry_point("ingest_alerts")
    wf.add_edge("ingest_alerts", "retrieve_knowledge")
    wf.add_edge("retrieve_knowledge", "enrich_ioc")
    wf.add_edge("enrich_ioc", "analyze")
    wf.add_edge("analyze", "plan_actions")
    wf.add_conditional_edges("plan_actions", route_after_plan)
    wf.add_edge("human_approve", END)  # L2 路径: 暂停等审批
    wf.add_edge("execute", "update_case")  # 无 L2 路径: 自动执行
    wf.add_edge("update_case", END)
    return wf.compile()


# ============ 后半段 workflow: resume ============


def build_resume_workflow():
    """execute → update_case → END

    审批通过后恢复执行。
    """
    wf = StateGraph(SecSightState)
    wf.add_node("execute", execute_node)
    wf.add_node("update_case", update_case_node)
    wf.set_entry_point("execute")
    wf.add_edge("execute", "update_case")
    wf.add_edge("update_case", END)
    return wf.compile()


_trigger_wf = None
_resume_wf = None


def get_trigger_workflow():
    global _trigger_wf
    if _trigger_wf is None:
        _trigger_wf = build_trigger_workflow()
    return _trigger_wf


def get_resume_workflow():
    global _resume_wf
    if _resume_wf is None:
        _resume_wf = build_resume_workflow()
    return _resume_wf


# ============ 触发入口 ============


async def trigger_workflow(case_id: str, playbook_id: str | None) -> None:
    """告警注入后触发

    checkpointer 模式 (Postgres + ENABLE_CHECKPOINTER): 跑到 human_approve 中断,状态持久化
    默认模式 (SQLite): 两段式 trigger 前半段
    """
    if _is_checkpointer_enabled():
        await trigger_workflow_checkpointer(case_id, playbook_id)
        return
    async with async_session() as session:
        repo = CaseRepository(session)
        case = await repo.get(case_id)
        if not case:
            return
        raw_alerts = [a.model_dump(mode="json") for a in case.alerts]

    initial_state: SecSightState = {
        "case_id": case_id,
        "raw_alerts": raw_alerts,
        "enriched_context": {},
        "retrieved_knowledge": [],
        "judgment": None,
        "proposed_actions": [],
        "approval_status": {},
        "execution_log": [],
        "current_playbook_id": playbook_id,
    }

    wf = get_trigger_workflow()
    await wf.ainvoke(initial_state)
    log.info("workflow.triggered", case_id=case_id, playbook_id=playbook_id)


async def resume_workflow(case_id: str) -> None:
    """审批通过后恢复

    checkpointer 模式: 从 checkpoint 恢复完整状态继续
    默认模式: 两段式 resume 后半段
    """
    if _is_checkpointer_enabled():
        await resume_workflow_checkpointer(case_id)
        return
    async with async_session() as session:
        repo = CaseRepository(session)
        case = await repo.get(case_id)
        if not case:
            return
        state: SecSightState = {
            "case_id": case_id,
            "raw_alerts": [a.model_dump(mode="json") for a in case.alerts],
            "enriched_context": case.enriched_context,
            "retrieved_knowledge": [],
            "judgment": case.judgment.model_dump(mode="json") if case.judgment else None,
            "proposed_actions": [a.model_dump(mode="json") for a in case.proposed_actions],
            "approval_status": {},
            "execution_log": [e.model_dump(mode="json") for e in case.execution_log],
            "current_playbook_id": case.playbook_id,
        }

    wf = get_resume_workflow()
    await wf.ainvoke(state)
    log.info("workflow.resumed", case_id=case_id)


# ============ Checkpointer 模式 (Postgres,真正中断恢复) ============


def _is_checkpointer_enabled() -> bool:
    from app.core.config import settings

    return (
        settings.enable_checkpointer
        and settings.database_url.startswith("postgresql")
    )


_checkpointer_wf = None
_checkpointer: object | None = None


async def _get_checkpointer():  # pragma: no cover - 需真实 Postgres
    """获取/初始化 Postgres checkpointer"""
    global _checkpointer
    if _checkpointer is None:
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

        from app.core.config import settings

        # 用同步 psycopg 连接字符串 (去掉 +asyncpg)
        sync_dsn = settings.database_url.replace("+asyncpg", "")
        _checkpointer = AsyncPostgresSaver.from_conn_string(sync_dsn)
        await _checkpointer.setup()  # 建检查点表
    return _checkpointer


def _build_checkpointer_workflow(checkpointer):  # pragma: no cover - 需真实 Postgres
    """单一 workflow + interrupt_before(human_approve) 真正中断恢复

    与两段式区别: 审批后从 checkpoint 恢复完整状态,而非重建 state。
    """
    wf = StateGraph(SecSightState)
    wf.add_node("ingest_alerts", ingest_alerts_node)
    wf.add_node("retrieve_knowledge", retrieve_knowledge_node)
    wf.add_node("enrich_ioc", enrich_ioc_node)
    wf.add_node("analyze", analyze_node)
    wf.add_node("plan_actions", plan_actions_node)
    wf.add_node("human_approve", human_approve_node)
    wf.add_node("execute", execute_node)
    wf.add_node("escalate", escalate_node)
    wf.add_node("update_case", update_case_node)

    wf.set_entry_point("ingest_alerts")
    wf.add_edge("ingest_alerts", "retrieve_knowledge")
    wf.add_edge("retrieve_knowledge", "enrich_ioc")
    wf.add_edge("enrich_ioc", "analyze")
    wf.add_edge("analyze", "plan_actions")
    wf.add_conditional_edges("plan_actions", route_after_plan)
    wf.add_conditional_edges("human_approve", route_approval)
    wf.add_edge("execute", "update_case")
    wf.add_edge("escalate", "update_case")
    wf.add_edge("update_case", END)

    return wf.compile(
        checkpointer=checkpointer,
        interrupt_before=["human_approve"],
    )


async def get_checkpointer_workflow():  # pragma: no cover - 需真实 Postgres
    global _checkpointer_wf
    if _checkpointer_wf is None:
        cp = await _get_checkpointer()
        _checkpointer_wf = _build_checkpointer_workflow(cp)
    return _checkpointer_wf


def route_approval(state: SecSightState) -> str:
    """审批后路由: 全批准 → execute,否则 → escalate"""
    approvals = state.get("approval_status", {})
    if not approvals:
        return "execute"
    if any(v == "rejected" for v in approvals.values()):
        return "escalate"
    all_approved = all(v == "approved" for v in approvals.values())
    return "execute" if all_approved else "escalate"


async def trigger_workflow_checkpointer(case_id: str, playbook_id: str | None) -> None:  # pragma: no cover - 需真实 Postgres
    """checkpointer 模式: 跑到 human_approve 前中断,状态持久化"""
    async with async_session() as session:
        repo = CaseRepository(session)
        case = await repo.get(case_id)
        if not case:
            return
        raw_alerts = [a.model_dump(mode="json") for a in case.alerts]

    initial_state: SecSightState = {
        "case_id": case_id,
        "raw_alerts": raw_alerts,
        "enriched_context": {},
        "retrieved_knowledge": [],
        "judgment": None,
        "proposed_actions": [],
        "approval_status": {},
        "execution_log": [],
        "current_playbook_id": playbook_id,
    }
    wf = await get_checkpointer_workflow()
    config = {"configurable": {"thread_id": case_id}}
    await wf.ainvoke(initial_state, config=config)
    log.info("workflow.triggered_cp", case_id=case_id, playbook_id=playbook_id)


async def resume_workflow_checkpointer(case_id: str) -> None:  # pragma: no cover - 需真实 Postgres
    """checkpointer 模式: 从 checkpoint 恢复,继续 execute → update_case"""
    # 同步 DB 的 approval_status 到 state
    async with async_session() as session:
        repo = CaseRepository(session)
        case = await repo.get(case_id)
        if not case:
            return
        approval_status = {}
        for action in case.proposed_actions:
            if action.approval_required:
                approval = case.approvals.get(action.action_id)
                approval_status[action.action_id] = (
                    approval.decision if approval else "pending"
                )

    wf = await get_checkpointer_workflow()
    config = {"configurable": {"thread_id": case_id}}
    # 更新 state 的 approval_status,然后从断点恢复
    await wf.aupdate_state(config, {"approval_status": approval_status})
    await wf.ainvoke(None, config=config)
    log.info("workflow.resumed_cp", case_id=case_id)
