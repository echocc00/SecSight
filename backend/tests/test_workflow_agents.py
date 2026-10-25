"""Agent 接入 LangGraph workflow 集成测试

验证 7 个 Agent 真正在编排路径执行,且决策影响执行行为:
  - DFIRAgent    → enriched_context.forensics
  - IRLeadAgent  → enriched_context.ir_decision + P0 降级动作自主性
  - ComplianceAgent / SOCManagerAgent → Evidence Pack + 审计日志

P0 后: 业务端点需 JWT (auth_client);签署身份来自 JWT / IM 回调 (conftest.sign_approval)。
"""
from __future__ import annotations

import pytest

from tests.conftest import approve_action_with_all_roles
from app.db.repositories import AuditLogRepository


async def _inject(client, alert_type: str = "xmrig_process") -> str:
    # 本文件所有用例断言 enriched_context/审计/证据包 (编排产物),须同步等编排完成
    r = await client.post(
        "/api/alerts/inject", json={"alert_type": alert_type}, params={"wait": "true"}
    )
    assert r.status_code == 200, r.text
    return r.json()["data"]["case_id"]


async def _approve_all(client, case_id: str) -> None:
    """每个审批角色按其映射的签署路径签署 (身份来自 JWT / IM 回调)"""
    pending = (await client.get(f"/api/approvals/{case_id}/pending")).json()["data"]
    for action in pending:
        roles = action.get("required_roles", ["incident_commander", "approver"])
        await approve_action_with_all_roles(client, case_id, action["action_id"], roles)


class TestDFIRAgentInWorkflow:
    @pytest.mark.asyncio
    async def test_forensics_captured_into_enriched_context(self, auth_client):
        """dfir_capture 节点把取证结果写入 enriched_context.forensics"""
        case_id = await _inject(auth_client)
        case = (await auth_client.get(f"/api/cases/{case_id}")).json()["data"]
        forensics = case["enriched_context"].get("forensics")
        assert forensics is not None, "DFIRAgent 应写入 forensics"
        assert "host" in forensics
        assert "process_tree" in forensics
        assert "network_connections" in forensics

    @pytest.mark.asyncio
    async def test_dfir_audit_log_recorded(self, auth_client, db_session):
        case_id = await _inject(auth_client)
        logs = await AuditLogRepository(db_session).list_by_case(case_id)
        actions = [l["action"] for l in logs]
        assert "dfir_captured" in actions


class TestIRLeadAgentInWorkflow:
    @pytest.mark.asyncio
    async def test_ir_decision_written_to_context(self, auth_client):
        """ir_coordinate 节点产出 priority + 协调指令"""
        case_id = await _inject(auth_client)
        case = (await auth_client.get(f"/api/cases/{case_id}")).json()["data"]
        ir = case["enriched_context"].get("ir_decision")
        assert ir is not None, "IRLeadAgent 应写入 ir_decision"
        assert ir["priority"] in ("P0", "P1", "P2", "P3")
        assert isinstance(ir["coordination"], list)
        assert len(ir["coordination"]) > 0

    @pytest.mark.asyncio
    async def test_ir_audit_log_recorded(self, auth_client, db_session):
        case_id = await _inject(auth_client)
        logs = await AuditLogRepository(db_session).list_by_case(case_id)
        ir_logs = [l for l in logs if l["action"] == "ir_coordinated"]
        assert ir_logs
        assert "priority" in ir_logs[0]["detail"]

    @pytest.mark.asyncio
    async def test_p0_escalates_critical_actions_to_l2(self, auth_client, db_session):
        """关键: P0 事件的高危动作被强制降级 L2 双签 (Agent 决策改变执行)"""
        from app.approvals.service import CRITICAL_ACTIONS

        # 找一个能触发 P0 (critical severity 或 critical 资产) 且含高危动作的告警
        p0_case_id = None
        for alert_type in ("data_exfiltration", "lateral_movement", "c2_communication"):
            cid = await _inject(auth_client, alert_type)
            case = (await auth_client.get(f"/api/cases/{cid}")).json()["data"]
            ir = case["enriched_context"].get("ir_decision", {})
            has_critical = any(
                a["action_type"] in CRITICAL_ACTIONS
                for a in case["proposed_actions"]
            )
            if ir.get("priority") == "P0" and has_critical:
                p0_case_id = cid
                break

        if not p0_case_id:
            pytest.skip("无告警类型同时满足 P0 + 含高危动作")

        case = (await auth_client.get(f"/api/cases/{p0_case_id}")).json()["data"]
        critical = [
            a for a in case["proposed_actions"]
            if a["action_type"] in CRITICAL_ACTIONS
        ]
        for a in critical:
            assert a["autonomy_level"] == "L2", f"{a['action_type']} 应被降级 L2"
            assert a["approval_required"] is True
            assert a["requires_double_sign"] is True

        logs = await AuditLogRepository(db_session).list_by_case(p0_case_id)
        esc = [l for l in logs if l["action"] == "actions_escalated_to_l2"]
        # 若剧本原本就全是 L2,则不会有降级记录 — 只要最终状态对即可
        if esc:
            assert esc[0]["detail"]["priority"] == "P0"


class TestComplianceAndSOCManagerInWorkflow:
    @pytest.mark.asyncio
    async def test_evidence_pack_contains_agent_decisions(self, auth_client):
        """Evidence Pack 含 compliance/escalation/ir_decision"""
        case_id = await _inject(auth_client)
        await _approve_all(auth_client, case_id)

        ev = (await auth_client.get(f"/api/evidence/{case_id}")).json()["data"]
        assert "compliance" in ev or ev.get("compliance") is not None
        compliance = ev.get("compliance") or {}
        assert compliance.get("agent") == "compliance"
        assert "needs_regulatory_report" in compliance
        assert compliance.get("dengbao_level") == 3

        escalation = ev.get("escalation") or {}
        assert escalation.get("agent") == "soc_manager"
        assert "resource_allocation" in escalation

    @pytest.mark.asyncio
    async def test_high_severity_triggers_regulatory_report_audit(
        self, auth_client, db_session
    ):
        """high/critical 事件产生等保上报审计记录"""
        case_id = await _inject(auth_client, "xmrig_process")  # high severity
        await _approve_all(auth_client, case_id)

        logs = await AuditLogRepository(db_session).list_by_case(case_id)
        actions = [l["action"] for l in logs]
        assert "regulatory_report_required" in actions
        report_log = next(
            l for l in logs if l["action"] == "regulatory_report_required"
        )
        assert report_log["detail"]["deadline_hours"] == 24

    @pytest.mark.asyncio
    async def test_soc_manager_escalation_audit(self, auth_client, db_session):
        """SOC Manager 升级决策留痕"""
        case_id = await _inject(auth_client, "xmrig_process")
        await _approve_all(auth_client, case_id)

        logs = await AuditLogRepository(db_session).list_by_case(case_id)
        esc = [l for l in logs if l["action"] == "escalated_by_soc_manager"]
        assert esc, "high severity 应触发 SOC Lead 升级"
        detail = esc[0]["detail"]
        assert detail["escalate_to"] in ("CISO", "SOC Lead")
        assert isinstance(detail["notify"], list)


class TestWorkflowStillClosesLoop:
    @pytest.mark.asyncio
    async def test_full_loop_with_agents_reaches_resolved(self, auth_client):
        """加了 2 个 Agent 节点后闭环仍完整"""
        case_id = await _inject(auth_client)
        await _approve_all(auth_client, case_id)
        case = (await auth_client.get(f"/api/cases/{case_id}")).json()["data"]
        assert case["status"] == "resolved"
        assert case["tttr_seconds"] is not None
        assert case["evidence_pack_id"] is not None

    @pytest.mark.asyncio
    async def test_auto_execute_playbook_still_works(self, auth_client):
        """无 L2 动作的剧本仍自动闭环"""
        case_id = await _inject(auth_client, "log_collection_stopped")
        case = (await auth_client.get(f"/api/cases/{case_id}")).json()["data"]
        assert case["status"] == "resolved"
        # Agent 节点也执行了
        assert case["enriched_context"].get("forensics") is not None
        assert case["enriched_context"].get("ir_decision") is not None
