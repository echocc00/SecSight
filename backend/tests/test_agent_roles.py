"""Agent 角色测试 — 7 角色 + 优先级决策 + 合规判定"""
from __future__ import annotations

import pytest

from app.agents.roles import (
    AGENTS,
    ComplianceAgent,
    DFIRAgent,
    IRLeadAgent,
    InvestigationAgent,
    SOCManagerAgent,
    TriageAgent,
    get_agent,
    list_agents,
)
from app.db.repositories import CaseRepository
from app.mock.alerts import xmrig_process_alert


async def _build_ctx(db_session, severity_overrides=None):
    """建 Case + AgentContext"""
    repo = CaseRepository(db_session)
    case = await repo.create_from_alert(xmrig_process_alert())
    return case


class TestAgentRegistry:
    def test_seven_agents_registered(self):
        assert len(AGENTS) == 7
        assert set(AGENTS.keys()) == {
            "triage", "investigation", "containment",
            "dfir", "ir_lead", "compliance", "soc_manager",
        }

    def test_get_agent_returns_instance(self):
        agent = get_agent("dfir")
        assert isinstance(agent, DFIRAgent)

    def test_get_agent_returns_none_for_unknown(self):
        assert get_agent("nonexistent") is None

    def test_list_agents_returns_metadata(self):
        agents = list_agents()
        assert len(agents) == 7
        assert all("name" in a and "role" in a and "llm_tier" in a for a in agents)

    def test_each_agent_has_distinct_role(self):
        agents = list_agents()
        roles = [a["role"] for a in agents]
        assert len(set(roles)) == 7  # 无重复


class TestTriageAgent:
    @pytest.mark.asyncio
    async def test_returns_severity_and_count(self, db_session):
        case = await _build_ctx(db_session)
        agent = TriageAgent()
        from app.agents.roles import AgentContext

        result = await agent.run(AgentContext(case=case, retrieved_knowledge=[], enriched_context={}))
        assert result["agent"] == "triage"
        assert result["severity"] == "high"  # xmrig 告警
        assert result["alert_count"] == 1


class TestInvestigationAgent:
    @pytest.mark.asyncio
    async def test_returns_judgment_if_present(self, db_session):
        case = await _build_ctx(db_session)
        # 模拟有 judgment
        from app.models.schemas import JudgmentReport, Severity

        case.judgment = JudgmentReport(
            incident_summary="test", severity=Severity.high, ttps=["T1496"],
            confidence=0.9, rationale="足够长的推理依据内容用于测试结构化解析通过",
        )
        agent = InvestigationAgent()
        from app.agents.roles import AgentContext

        result = await agent.run(AgentContext(case=case, retrieved_knowledge=[], enriched_context={}))
        assert result["confidence"] == 0.9


class TestDFIRAgent:
    @pytest.mark.asyncio
    async def test_collects_forensic_evidence(self, db_session):
        case = await _build_ctx(db_session)
        agent = DFIRAgent()
        from app.agents.roles import AgentContext

        ctx = AgentContext(
            case=case,
            retrieved_knowledge=[],
            enriched_context={
                "process_tree": {"pid": 28371, "name": "xmrig", "parent": "bash"},
                "network_connections": [{"dst": "pool.supportxmr.com:3333"}],
            },
        )
        result = await agent.run(ctx)
        assert result["evidence"]["process_tree"]["name"] == "xmrig"
        assert result["forensic_ready"] is True

    @pytest.mark.asyncio
    async def test_forensic_not_ready_without_process_tree(self, db_session):
        case = await _build_ctx(db_session)
        agent = DFIRAgent()
        from app.agents.roles import AgentContext

        result = await agent.run(AgentContext(case=case, retrieved_knowledge=[], enriched_context={}))
        assert result["forensic_ready"] is False


class TestIRLeadAgent:
    @pytest.mark.asyncio
    async def test_critical_severity_yields_p0(self, db_session):
        case = await _build_ctx(db_session)
        from app.models.schemas import JudgmentReport, Severity

        case.judgment = JudgmentReport(
            incident_summary="x", severity=Severity.critical, ttps=["T1486"],
            confidence=0.95, rationale="足够长的推理依据内容用于测试结构化解析通过",
        )
        agent = IRLeadAgent()
        from app.agents.roles import AgentContext

        result = await agent.run(AgentContext(case=case, retrieved_knowledge=[], enriched_context={}))
        assert result["priority"] == "P0"
        assert "CISO" in result["coordination"][0] or "DFIR" in str(result["coordination"])

    @pytest.mark.asyncio
    async def test_high_severity_with_confidence_yields_p1(self, db_session):
        case = await _build_ctx(db_session)
        from app.models.schemas import JudgmentReport, Severity

        case.judgment = JudgmentReport(
            incident_summary="x", severity=Severity.high, ttps=["T1496"],
            confidence=0.85, rationale="足够长的推理依据内容用于测试结构化解析通过",
        )
        agent = IRLeadAgent()
        from app.agents.roles import AgentContext

        result = await agent.run(AgentContext(case=case, retrieved_knowledge=[], enriched_context={}))
        assert result["priority"] == "P1"

    def test_priority_matrix(self):
        agent = IRLeadAgent()
        assert agent._decide_priority("critical", 0.5, "low") == "P0"
        assert agent._decide_priority("high", 0.8, "medium") == "P1"
        assert agent._decide_priority("medium", 0.5, "low") == "P2"
        assert agent._decide_priority("low", 0.3, "low") == "P3"


class TestComplianceAgent:
    @pytest.mark.asyncio
    async def test_high_severity_needs_report(self, db_session):
        case = await _build_ctx(db_session)
        from app.models.schemas import JudgmentReport, Severity

        case.judgment = JudgmentReport(
            incident_summary="x", severity=Severity.high, ttps=["T1496"],
            confidence=0.9, rationale="足够长的推理依据内容用于测试结构化解析通过",
        )
        agent = ComplianceAgent()
        from app.agents.roles import AgentContext

        result = await agent.run(AgentContext(case=case, retrieved_knowledge=[], enriched_context={}))
        assert result["needs_regulatory_report"] is True
        assert result["deadline_hours"] == 24
        assert result["dengbao_level"] == 3

    @pytest.mark.asyncio
    async def test_low_severity_no_report(self, db_session):
        case = await _build_ctx(db_session)
        from app.models.schemas import JudgmentReport, Severity

        case.judgment = JudgmentReport(
            incident_summary="x", severity=Severity.low, ttps=["T1496"],
            confidence=0.5, rationale="足够长的推理依据内容用于测试结构化解析通过",
        )
        agent = ComplianceAgent()
        from app.agents.roles import AgentContext

        result = await agent.run(AgentContext(case=case, retrieved_knowledge=[], enriched_context={}))
        assert result["needs_regulatory_report"] is False
        assert result["deadline_hours"] == 0


class TestSOCManagerAgent:
    @pytest.mark.asyncio
    async def test_critical_escalates_to_ciso(self, db_session):
        case = await _build_ctx(db_session)
        from app.models.schemas import JudgmentReport, Severity

        case.judgment = JudgmentReport(
            incident_summary="x", severity=Severity.critical, ttps=["T1486"],
            confidence=0.95, rationale="足够长的推理依据内容用于测试结构化解析通过",
        )
        agent = SOCManagerAgent()
        from app.agents.roles import AgentContext

        result = await agent.run(AgentContext(case=case, retrieved_knowledge=[], enriched_context={}))
        assert result["escalate_to"] == "CISO"
        assert result["war_room"] is True
        assert "ciso" in result["notify"]

    @pytest.mark.asyncio
    async def test_high_escalates_to_soc_lead(self, db_session):
        case = await _build_ctx(db_session)
        from app.models.schemas import JudgmentReport, Severity

        case.judgment = JudgmentReport(
            incident_summary="x", severity=Severity.high, ttps=["T1496"],
            confidence=0.85, rationale="足够长的推理依据内容用于测试结构化解析通过",
        )
        agent = SOCManagerAgent()
        from app.agents.roles import AgentContext

        result = await agent.run(AgentContext(case=case, retrieved_knowledge=[], enriched_context={}))
        assert result["escalate_to"] == "SOC Lead"
        assert result["war_room"] is False

    def test_resource_allocation(self):
        agent = SOCManagerAgent()
        assert agent._allocate("critical")["analysts"] == 3
        assert agent._allocate("high")["analysts"] == 2
        assert agent._allocate("low")["analysts"] == 1
