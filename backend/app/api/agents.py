"""Agent 角色 API"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.proactive import list_proactive_agents
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
    """列出 Proactive Agent (4 个) + 调度器状态"""
    from app.agents.scheduler import scheduler_status

    return ApiResponse(
        success=True,
        data={
            "agents": list_proactive_agents(),
            "scheduler": scheduler_status(),
        },
    )


@router.get("/proactive/runs", response_model=ApiResponse)
async def list_proactive_runs(
    limit: int = 50,
    agent_name: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> ApiResponse:
    """Proactive Agent 执行历史 (scheduled + manual)"""
    from app.db.repositories import ProactiveRunRepository

    runs = await ProactiveRunRepository(session).list(limit=limit, agent_name=agent_name)
    return ApiResponse(success=True, data=runs)


@router.get("/proactive/runs/{run_id}", response_model=ApiResponse)
async def get_proactive_run(
    run_id: str, session: AsyncSession = Depends(get_session)
) -> ApiResponse:
    """单次执行详情 (含完整 result)"""
    from app.db.repositories import ProactiveRunRepository

    run = await ProactiveRunRepository(session).get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return ApiResponse(success=True, data=run)


@router.post("/proactive/{agent_name}", response_model=ApiResponse)
async def run_proactive_agent(agent_name: str) -> ApiResponse:
    """手动触发 Proactive Agent

    与 cron 调度共用 run_proactive_with_record 入口,执行记录统一落库,
    高危 finding (critical/high 漏洞、confirmed 狩猎命中) 自动建 Case。
    """
    from app.agents.scheduler import run_proactive_with_record

    try:
        result = await run_proactive_with_record(agent_name, trigger="manual")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
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
