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
        assert len(data["agents"]) == 4
        assert "scheduler" in data
        assert "enabled" in data["scheduler"]

    @pytest.mark.asyncio
    async def test_run_proactive_endpoint(self, client):
        r = await client.post("/api/agents/proactive/threat_hunting")
        assert r.status_code == 200
        assert r.json()["data"]["agent"] == "threat_hunting"

    @pytest.mark.asyncio
    async def test_run_unknown_proactive_404(self, client):
        r = await client.post("/api/agents/proactive/nonexistent")
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_manual_run_recorded_in_history(self, client):
        """手动触发也落库 proactive_runs"""
        await client.post("/api/agents/proactive/vuln_scan")
        r = await client.get("/api/agents/proactive/runs")
        runs = r.json()["data"]
        assert len(runs) >= 1
        vuln_runs = [x for x in runs if x["agent_name"] == "vuln_scan"]
        assert vuln_runs
        assert vuln_runs[0]["trigger"] == "manual"
        assert vuln_runs[0]["status"] == "success"

    @pytest.mark.asyncio
    async def test_run_detail_includes_result(self, client):
        r = await client.post("/api/agents/proactive/asset_hardening")
        run_id = r.json()["data"]["result"]["run_id"]
        detail = (await client.get(f"/api/agents/proactive/runs/{run_id}")).json()["data"]
        assert detail["run_id"] == run_id
        assert detail["result"]["agent"] == "asset_hardening"

    @pytest.mark.asyncio
    async def test_run_detail_404(self, client):
        r = await client.get("/api/agents/proactive/runs/no-such-run")
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_runs_filter_by_agent(self, client):
        await client.post("/api/agents/proactive/threat_hunting")
        await client.post("/api/agents/proactive/vuln_scan")
        r = await client.get(
            "/api/agents/proactive/runs", params={"agent_name": "vuln_scan"}
        )
        runs = r.json()["data"]
        assert all(x["agent_name"] == "vuln_scan" for x in runs)


class TestProactiveCaseCreation:
    """Proactive → Reactive 衔接: 高危 finding 自动建 Case"""

    @pytest.mark.asyncio
    async def test_high_severity_vuln_creates_case(self, client):
        """vuln_scan 的 critical/high 漏洞自动建 Case"""
        r = await client.post("/api/agents/proactive/vuln_scan")
        result = r.json()["data"]["result"]
        # mock 数据含 1 个 high (CVE-2024-1234)
        assert result["cases_created"] >= 1

        # list API 不返回 alerts,逐个查详情确认来源
        cases = (await client.get("/api/cases")).json()["data"]
        found = False
        for c in cases:
            detail = (await client.get(f"/api/cases/{c['case_id']}")).json()["data"]
            if any(a.get("source") == "vuln_scan" for a in detail.get("alerts", [])):
                found = True
                alert = next(
                    a for a in detail["alerts"] if a.get("source") == "vuln_scan"
                )
                assert alert["severity"] in ("critical", "high")
                assert "CVE" in alert["message"]
                break
        assert found, "high 漏洞应建来源为 vuln_scan 的 Case"

    @pytest.mark.asyncio
    async def test_hunting_without_confirmed_creates_no_case(self, client):
        """狩猎中 (status=hunting) 不建 Case,仅 confirmed 才建"""
        r = await client.post("/api/agents/proactive/threat_hunting")
        result = r.json()["data"]["result"]
        assert result["cases_created"] == 0

    @pytest.mark.asyncio
    async def test_asset_hardening_creates_no_case(self, client):
        """基线失败不是安全事件,不建 Case"""
        r = await client.post("/api/agents/proactive/asset_hardening")
        assert r.json()["data"]["result"]["cases_created"] == 0


class TestSchedulerLifecycle:
    def test_no_jobs_disabled_scheduler(self, monkeypatch):
        """proactive 关 + retention 清关 → 调度器不启动"""
        from app.agents import scheduler as sched
        from app.core.config import settings

        monkeypatch.setattr(sched, "_scheduler", None)
        monkeypatch.setattr(settings, "enable_proactive_scheduler", False)
        monkeypatch.setattr(settings, "enable_audit_retention_purge", False)
        sched.start_scheduler()
        st = sched.scheduler_status()
        assert st["running"] is False
        assert st["jobs"] == []

    @pytest.mark.asyncio
    async def test_retention_job_runs_without_proactive(self, monkeypatch):
        """审计 retention 清理独立于 proactive 开关 —— 等保要求必须跑"""
        from app.agents import scheduler as sched
        from app.core.config import settings

        monkeypatch.setattr(sched, "_scheduler", None)
        monkeypatch.setattr(settings, "enable_proactive_scheduler", False)
        monkeypatch.setattr(settings, "enable_audit_retention_purge", True)
        monkeypatch.setattr(settings, "audit_log_retention_days", 180)
        sched.start_scheduler()
        st = sched.scheduler_status()
        assert st["running"] is True
        ids = {j["id"] for j in st["jobs"]}
        assert "audit_retention_purge" in ids
        # proactive 关时不注册 proactive job
        assert not any(j["agent"] for j in st["jobs"])
        await sched.shutdown_scheduler()

    @pytest.mark.asyncio
    async def test_scheduler_starts_when_enabled(self, monkeypatch):
        """AsyncIOScheduler 需运行中的 event loop,故用 async 测试"""
        from app.agents import scheduler as sched
        from app.core.config import settings

        monkeypatch.setattr(settings, "enable_proactive_scheduler", True)
        monkeypatch.setattr(sched, "_scheduler", None)
        sched.start_scheduler()
        st = sched.scheduler_status()
        assert st["running"] is True
        # 4 proactive + 1 audit retention job
        job_ids = {j["id"] for j in st["jobs"]}
        assert "audit_retention_purge" in job_ids
        agents = {j["agent"] for j in st["jobs"] if j["agent"]}
        assert agents == {
            "threat_hunting",
            "vuln_scan",
            "detection_engineering",
            "asset_hardening",
        }
        await sched.shutdown_scheduler()

    @pytest.mark.asyncio
    async def test_invalid_cron_skips_job(self, monkeypatch):
        from app.agents import scheduler as sched
        from app.core.config import settings

        monkeypatch.setattr(settings, "enable_proactive_scheduler", True)
        monkeypatch.setattr(sched, "_scheduler", None)
        monkeypatch.setenv("PROACTIVE_CRON_VULN_SCAN", "not a cron")
        sched.start_scheduler()
        st = sched.scheduler_status()
        agents = {j["agent"] for j in st["jobs"]}
        assert "vuln_scan" not in agents  # 无效 cron 被跳过
        assert "threat_hunting" in agents  # 其余正常
        await sched.shutdown_scheduler()

    @pytest.mark.asyncio
    async def test_failed_run_recorded(self, client, monkeypatch):
        """Agent 抛异常时记录 failed 状态"""
        from app.agents.proactive import ThreatHuntingAgent
        from app.agents.scheduler import run_proactive_with_record

        async def _boom(self, ctx):
            raise RuntimeError("scan exploded")

        monkeypatch.setattr(ThreatHuntingAgent, "run", _boom)
        with pytest.raises(RuntimeError, match="scan exploded"):
            await run_proactive_with_record("threat_hunting", "manual")

        runs = (await client.get("/api/agents/proactive/runs")).json()["data"]
        failed = [x for x in runs if x["status"] == "failed"]
        assert failed
        assert "scan exploded" in failed[0]["error"]
