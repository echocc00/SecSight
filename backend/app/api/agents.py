"""Agent 角色 API"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.proactive import (
    ProactiveContext,
    get_proactive_agent,
    list_proactive_agents,
)
from app.agents.roles import AgentContext, get_agent, list_agents
from app.api.schemas import ApiResponse
from app.db.database import get_session
from app.db.repositories import CaseRepository

router = APIRouter()


@router.get("", response_model=ApiResponse)
async def list_all_agents() -> ApiResponse:
    """列出所有 Agent 角色 (7 reactive + 4 proactive = 11)"""
    return ApiResponse(success=True, data=list_agents())


@router.get("/proactive", response_model=ApiResponse)
async def list_proactive() -> ApiResponse:
    """列出 Proactive Agent (4 个)"""
    return ApiResponse(success=True, data=list_proactive_agents())


@router.post("/proactive/{agent_name}", response_model=ApiResponse)
async def run_proactive_agent(
    agent_name: str,
    time_window_hours: int = 24,
    target_assets: list[str] | None = None,
) -> ApiResponse:
    """运行 Proactive Agent (主动防御,无具体 Case)"""
    agent = get_proactive_agent(agent_name)
    if not agent:
        raise HTTPException(status_code=404, detail=f"未知 Proactive Agent: {agent_name}")
    ctx = ProactiveContext(
        time_window_hours=time_window_hours,
        target_assets=target_assets,
    )
    result = await agent.run(ctx)
    return ApiResponse(success=True, data={"agent": agent_name, "result": result})


@router.post("/{case_id}/{agent_name}", response_model=ApiResponse)
async def run_agent(
    case_id: str,
    agent_name: str,
    session: AsyncSession = Depends(get_session),
) -> ApiResponse:
    """对指定 Case 运行单个 Agent

    agent_name: triage | investigation | containment | dfir | ir_lead | compliance | soc_manager
    """
    agent = get_agent(agent_name)
    if not agent:
        raise HTTPException(status_code=404, detail=f"未知 Agent: {agent_name}")

    repo = CaseRepository(session)
    case = await repo.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    ctx = AgentContext(
        case=case,
        retrieved_knowledge=[],
        enriched_context=case.enriched_context or {},
    )
    result = await agent.run(ctx)
    return ApiResponse(success=True, data={"agent": agent_name, "result": result})
