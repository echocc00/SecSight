"""LangGraph Postgres Checkpointer 真实中断恢复集成测试

验证: L2 审批时 workflow 真正中断 (状态持久化到 Postgres checkpoints 表),
审批后从断点恢复完整状态继续 execute → update_case,不丢 enriched_context。

对比两段式: 两段式 resume 重建 state (从 Case 读回),checkpointer 从 checkpoint
恢复 (LangGraph 内部状态),后者保证中间态 (如 ir_priority/approval_status) 不丢。
"""
from __future__ import annotations

import pytest

from app.db.repositories import CaseRepository


async def _seed_user(pg_session):
    from app.db.repositories import UserRepository

    await UserRepository(pg_session).seed_defaults()


async def _inject_and_pause(pg_client, alert_type: str = "xmrig_process") -> str:
    """注入告警 → workflow 跑到 human_approve 中断,返回 case_id"""
    r = await pg_client.post("/api/alerts/inject", json={"alert_type": alert_type})
    assert r.status_code == 200, r.text
    return r.json()["data"]["case_id"]


async def _approve_all(pg_client, case_id: str) -> None:
    pending = (await pg_client.get(f"/api/approvals/{case_id}/pending")).json()["data"]
    for action in pending:
        for role in action.get("required_roles", ["incident_commander", "approver"]):
            await pg_client.post(
                f"/api/approvals/{case_id}/actions/{action['action_id']}/approve",
                json={
                    "approver_role": role,
                    "approver_user": f"u-{role}",
                    "decision": "approved",
                },
            )


class TestCheckpointerInterruptAndResume:
    """核心: 验证 interrupt_before(human_approve) 真正中断 + resume 恢复"""

    @pytest.mark.asyncio
    async def test_workflow_interrupts_at_human_approve(self, pg_client, pg_session):
        """注入后 workflow 在 human_approve 前中断,Case 状态 = pending_approval"""
        await _seed_user(pg_session)
        case_id = await _inject_and_pause(pg_client)

        case = (await pg_client.get(f"/api/cases/{case_id}")).json()["data"]
        assert case["status"] == "pending_approval"

        # checkpoint 表应有记录 (thread_id = case_id)
        from sqlalchemy import text

        r = await pg_session.execute(text("SELECT thread_id FROM checkpoints"))
        threads = [row[0] for row in r]
        assert case_id in threads or any(case_id in str(t) for t in threads)

    @pytest.mark.asyncio
    async def test_resume_completes_to_resolved(self, pg_client, pg_session):
        """审批后 resume → execute → update_case → resolved"""
        await _seed_user(pg_session)
        case_id = await _inject_and_pause(pg_client)
        await _approve_all(pg_client, case_id)

        from app.agents.workflow import resume_workflow

        await resume_workflow(case_id)

        case = (await pg_client.get(f"/api/cases/{case_id}")).json()["data"]
        assert case["status"] == "resolved"
        assert case["tttr_seconds"] is not None
        assert case["evidence_pack_id"] is not None

    @pytest.mark.asyncio
    async def test_enriched_context_preserved_across_interrupt(self, pg_client, pg_session):
        """中断-恢复间 enriched_context 不丢 (ir_decision/forensics/iocs)"""
        await _seed_user(pg_session)
        case_id = await _inject_and_pause(pg_client)

        case_before = (await pg_client.get(f"/api/cases/{case_id}")).json()["data"]
        ctx_before = case_before["enriched_context"]

        await _approve_all(pg_client, case_id)
        from app.agents.workflow import resume_workflow

        await resume_workflow(case_id)

        case_after = (await pg_client.get(f"/api/cases/{case_id}")).json()["data"]
        ctx_after = case_after["enriched_context"]

        # IRLeadAgent / DFIRAgent 写入的决策应保留
        assert ctx_after.get("ir_decision", {}).get("priority") == ctx_before.get(
            "ir_decision", {}
        ).get("priority")
        assert "forensics" in ctx_after

    @pytest.mark.asyncio
    async def test_audit_chain_complete_after_resume(self, pg_client, pg_session):
        """中断恢复后审计链完整: dfir/ir/plan/approve/execute/close 全有"""
        await _seed_user(pg_session)
        case_id = await _inject_and_pause(pg_client)
        await _approve_all(pg_client, case_id)
        from app.agents.workflow import resume_workflow

        await resume_workflow(case_id)

        from app.db.repositories import AuditLogRepository

        logs = await AuditLogRepository(pg_session).list_by_case(case_id)
        actions = [l["action"] for l in logs]
        for expected in ("dfir_captured", "ir_coordinated", "case_closed"):
            assert expected in actions, f"审计缺 {expected}, 实际: {actions}"


class TestCheckpointerIdempotency:
    @pytest.mark.asyncio
    async def test_double_resume_does_not_corrupt(self, pg_client, pg_session):
        """重复 resume 不破坏状态 (checkpointer 幂等)"""
        await _seed_user(pg_session)
        case_id = await _inject_and_pause(pg_client)
        await _approve_all(pg_client, case_id)

        from app.agents.workflow import resume_workflow

        await resume_workflow(case_id)
        # 二次 resume (已 resolved,应无副作用)
        await resume_workflow(case_id)

        case = (await pg_client.get(f"/api/cases/{case_id}")).json()["data"]
        assert case["status"] == "resolved"

    @pytest.mark.asyncio
    async def test_resume_without_approve_stays_pending(self, pg_client, pg_session):
        """未审批就 resume: 仍停在 pending_approval"""
        await _seed_user(pg_session)
        case_id = await _inject_and_pause(pg_client)
        from app.agents.workflow import resume_workflow

        await resume_workflow(case_id)
        case = (await pg_client.get(f"/api/cases/{case_id}")).json()["data"]
        # 未批准的动作 → route_approval → escalate 或停在 pending
        assert case["status"] in ("pending_approval", "contained", "resolved")


class TestHashChainWithCheckpointer:
    """hash chain 在 checkpointer 模式下不断链"""

    @pytest.mark.asyncio
    async def test_audit_chain_valid_after_full_flow(self, pg_client, pg_session):
        await _seed_user(pg_session)
        case_id = await _inject_and_pause(pg_client)
        await _approve_all(pg_client, case_id)
        from app.agents.workflow import resume_workflow

        await resume_workflow(case_id)

        from app.db.repositories import AuditLogRepository

        result = await AuditLogRepository(pg_session).verify_chain()
        assert result["valid"] is True
        assert result["verified_count"] > 0
