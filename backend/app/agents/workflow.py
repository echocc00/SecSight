"""LangGraph 编排 (裁决 §4)

垂直切片采用两段式 (避免 interrupt_before + checkpoint 复杂性,Phase2 接 Postgres checkpointer 后改真正的中断恢复):

  trigger_workflow:  ingest → retrieve → analyze → plan → mark_pending → END
  resume_workflow:   execute → update_case → END

5 级自主性路由仍在 plan 阶段标注,L2 动作需双签批准后才 resume。
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
    """告警注入后触发: 跑前半段,到 pending_approval 停"""
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
    """审批通过后恢复: 跑后半段 (execute + update_case)"""
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
