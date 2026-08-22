"""Proactive Agent 测试 — 4 个主动防御 Agent"""
from __future__ import annotations

import pytest

from app.agents.proactive import (
    PROACTIVE_AGENTS,
    AssetHardeningAgent,
    DetectionEngineeringAgent,
    ThreatHuntingAgent,
    VulnerabilityScanAgent,
    get_proactive_agent,
    list_proactive_agents,
)
from app.agents.proactive import ProactiveContext
from app.db.repositories import CaseRepository
from app.mock.alerts import xmrig_process_alert


class TestProactiveRegistry:
    def test_four_proactive_agents(self):
        assert len(PROACTIVE_AGENTS) == 4

    def test_get_agent(self):
        assert isinstance(get_proactive_agent("threat_hunting"), ThreatHuntingAgent)

    def test_list_proactive(self):
        agents = list_proactive_agents()
        assert len(agents) == 4


class TestThreatHunting:
    @pytest.mark.asyncio
    async def test_hunt_returns_findings(self):
        agent = ThreatHuntingAgent()
        ctx = ProactiveContext(target_assets=["web-prod-01"])
        result = await agent.run(ctx)
        assert result["hypotheses_count"] > 0
        assert len(result["findings"]) > 0

    @pytest.mark.asyncio
    async def test_custom_hypotheses(self):
        agent = ThreatHuntingAgent()
        ctx = ProactiveContext(hunt_hypotheses=["custom hunt 1", "custom hunt 2"])
        result = await agent.run(ctx)
        assert result["hypotheses_count"] == 2


class TestVulnerabilityScan:
    @pytest.mark.asyncio
    async def test_scan_returns_vulns(self):
        agent = VulnerabilityScanAgent()
        result = await agent.run(ProactiveContext())
        assert result["total_vulns"] > 0
        assert result["high_priority"] > 0


class TestDetectionEngineering:
    @pytest.mark.asyncio
    async def test_learn_from_case(self, db_session):
        repo = CaseRepository(db_session)
        case = await repo.create_from_alert(xmrig_process_alert())
        # 加 judgment
        from app.models.schemas import JudgmentReport, Severity

        case.judgment = JudgmentReport(
            incident_summary="x", severity=Severity.high, ttps=["T1496", "T1071.001"],
            confidence=0.9, rationale="足够长的推理依据内容用于测试结构化解析通过",
        )
        agent = DetectionEngineeringAgent()
        result = await agent.run(case)
        assert result["source_case"] == case.case_id
        assert "T1496" in result["ttps_observed"]
        assert result["knowledge_injection"]["target_layer"] == "L1_tactic"

    @pytest.mark.asyncio
    async def test_global_optimization(self):
        agent = DetectionEngineeringAgent()
        result = await agent.run(ProactiveContext())
        assert "coverage_gaps" in result


class TestAssetHardening:
    @pytest.mark.asyncio
    async def test_baseline_check(self):
        agent = AssetHardeningAgent()
        result = await agent.run(ProactiveContext())
        assert result["total_controls"] > 0
        assert result["failures"] > 0
        assert len(result["hardening_suggestions"]) > 0


class TestProactiveAPI:
    @pytest.mark.asyncio
    async def test_list_proactive_endpoint(self, client):
        r = await client.get("/api/agents/proactive")
        data = r.json()["data"]
        assert len(data) == 4

    @pytest.mark.asyncio
    async def test_run_proactive_endpoint(self, client):
        r = await client.post("/api/agents/proactive/threat_hunting")
        assert r.status_code == 200
        assert r.json()["data"]["agent"] == "threat_hunting"

    @pytest.mark.asyncio
    async def test_run_unknown_proactive_404(self, client):
        r = await client.post("/api/agents/proactive/nonexistent")
        assert r.status_code == 404
