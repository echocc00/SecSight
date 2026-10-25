"""P0/P1 安全修复回归测试

对应 2026-10 评审修复项,每条测试对应一个曾经真实存在的漏洞:
  - 业务端点全面裸奔 → 鉴权矩阵测试
  - 审批身份客户端自报 (3 条 curl 过双签) → 身份绑定 + 同人防重测试
  - 已闭环案件补签复活重复处置 / 拒绝无终态 → 终态测试
  - DB 异常降级 demo 用户后门 → 认证降级测试
  - /health 泄露执行能力 → 信息收敛测试
  - checkpointer 路径误读 case.approvals 致已批动作不执行 → 判定修复测试
"""
from __future__ import annotations

import pytest

from app.db.repositories import ApprovalRecordRepository, CaseRepository
from app.mock.alerts import xmrig_process_alert
from app.models.schemas import Action, ActionType, AutonomyLevel, CaseStatus, Severity

from tests.conftest import login_headers


async def _case_with_l2_action(db_session) -> tuple[str, str]:
    """建一个含单个 L2 双签动作 (query_asset,非高危) 的 pending Case"""
    repo = CaseRepository(db_session)
    case = await repo.create_from_alert(xmrig_process_alert())
    action = Action(
        action_type=ActionType.query_asset,
        target={"ip": "10.0.1.15"},
        autonomy_level=AutonomyLevel.L2,
        risk=Severity.medium,
        approval_required=True,
        requires_double_sign=True,
    )
    await repo.update_actions(case.case_id, [action])
    await repo.update_status(case.case_id, CaseStatus.pending_approval)
    return case.case_id, action.action_id


class TestAuthMatrix:
    """业务端点鉴权矩阵 —— 修复前除 auth/audit 外全部裸奔"""

    async def test_cases_require_auth(self, client):
        r = await client.get("/api/cases")
        assert r.status_code == 401

    async def test_alerts_search_requires_auth(self, client):
        r = await client.get("/api/alerts/search", params={"q": "x"})
        assert r.status_code == 401

    async def test_evidence_requires_auth(self, client):
        r = await client.get("/api/evidence/some-case")
        assert r.status_code == 401

    async def test_proactive_trigger_requires_auth(self, client):
        r = await client.post("/api/agents/proactive/threat_hunter")
        assert r.status_code == 401

    async def test_viewer_can_read_cases(self, client):
        """viewer 只读权限成立 (case:read)"""
        r = await client.get("/api/cases", headers=await login_headers("viewer"))
        assert r.status_code == 200

    async def test_viewer_cannot_inject_alert(self, client):
        """viewer 无 alert:inject → 403 (修复前匿名即可注入告警)"""
        r = await client.post(
            "/api/alerts/inject",
            json={"alert_type": "xmrig_process"},
            headers=await login_headers("viewer"),
        )
        assert r.status_code == 403

    async def test_viewer_cannot_approve(self, client, db_session):
        """viewer 无 approval:submit → 403 (修复前匿名可批高危动作)"""
        case_id, action_id = await _case_with_l2_action(db_session)
        r = await client.post(
            f"/api/approvals/{case_id}/actions/{action_id}/approve",
            json={"decision": "approved"},
            headers=await login_headers("viewer"),
        )
        assert r.status_code == 403

    async def test_analyst_can_inject_alert(self, client):
        r = await client.post(
            "/api/alerts/inject",
            json={"alert_type": "xmrig_process"},
            headers=await login_headers("analyst"),
        )
        assert r.status_code == 200
        assert r.json()["success"] is True


class TestApprovalIdentityBinding:
    """审批身份必须来自 JWT (APPROVAL_ROLE_MAP),客户端自报无效"""

    async def test_role_mapped_from_jwt_not_body(self, client, db_session):
        """analyst 登录 → 服务端映射 incident_commander;请求体自报 approver 被忽略"""
        case_id, action_id = await _case_with_l2_action(db_session)
        headers = await login_headers("analyst")
        # 恶意客户端试图自报身份: 旧模型下这样就能替任何角色签字
        r = await client.post(
            f"/api/approvals/{case_id}/actions/{action_id}/approve",
            json={"decision": "approved", "approver_role": "approver", "approver_user": "root"},
            headers=headers,
        )
        assert r.status_code == 200
        records = await ApprovalRecordRepository(db_session).list_by_action(
            case_id, action_id
        )
        assert len(records) == 1
        assert records[0]["approver_role"] == "incident_commander"  # 映射,非自报
        assert records[0]["approver_user"] == "analyst"  # JWT 用户名,非 "root"

    async def test_admin_maps_to_ciso(self, client, db_session):
        case_id, action_id = await _case_with_l2_action(db_session)
        r = await client.post(
            f"/api/approvals/{case_id}/actions/{action_id}/approve",
            json={"decision": "approved"},
            headers=await login_headers("admin"),
        )
        assert r.status_code == 200
        records = await ApprovalRecordRepository(db_session).list_by_action(
            case_id, action_id
        )
        assert records[0]["approver_role"] == "ciso_or_delegate"

    async def test_same_user_cannot_sign_twice(self, client, db_session):
        """同一账号换角色名也不能签两票 (双签最低需要两个真实账号)"""
        case_id, action_id = await _case_with_l2_action(db_session)
        headers = await login_headers("analyst")
        r1 = await client.post(
            f"/api/approvals/{case_id}/actions/{action_id}/approve",
            json={"decision": "approved"},
            headers=headers,
        )
        assert r1.status_code == 200
        # 同一用户第二次签 (即使声称不同角色) 必须被拒
        r2 = await client.post(
            f"/api/approvals/{case_id}/actions/{action_id}/approve",
            json={"decision": "approved"},
            headers=headers,
        )
        assert r2.status_code == 400

    async def test_double_sign_needs_two_distinct_accounts(self, client, db_session):
        """双签通过需要 analyst + approver 两个不同账号"""
        case_id, action_id = await _case_with_l2_action(db_session)
        for role in ("analyst", "approver"):
            r = await client.post(
                f"/api/approvals/{case_id}/actions/{action_id}/approve",
                json={"decision": "approved"},
                headers=await login_headers(role),
            )
            assert r.status_code == 200
        body = r.json()["data"]
        assert body["all_approved"] is True


class TestRejectionTerminalState:
    """拒绝终态 + 已闭环案件禁止再签 (修复前拒绝后 Case 卡死 / 可复活重复处置)"""

    async def test_rejection_closes_case(self, client, db_session):
        case_id, action_id = await _case_with_l2_action(db_session)
        r = await client.post(
            f"/api/approvals/{case_id}/actions/{action_id}/approve",
            json={"decision": "rejected", "comment": "误报"},
            headers=await login_headers("analyst"),
        )
        assert r.status_code == 200
        assert r.json()["data"]["rejected"] is True
        case = await CaseRepository(db_session).get(case_id)
        assert case.status == CaseStatus.resolved

    async def test_no_more_signatures_after_rejection(self, client, db_session):
        """拒绝后 Case 关闭,不能再吸收签名 (修复前: 卡死在 pending_approval)"""
        case_id, action_id = await _case_with_l2_action(db_session)
        await client.post(
            f"/api/approvals/{case_id}/actions/{action_id}/approve",
            json={"decision": "rejected"},
            headers=await login_headers("analyst"),
        )
        r = await client.post(
            f"/api/approvals/{case_id}/actions/{action_id}/approve",
            json={"decision": "approved"},
            headers=await login_headers("approver"),
        )
        assert r.status_code == 400
        assert "已闭环" in r.json()["detail"]

    async def test_resolved_case_cannot_be_revived(self, client, db_session):
        """已闭环案件补签会被拒绝 (修复前: 补最后一签 → 复活 → 重复执行隔离/封禁)"""
        case_id, action_id = await _case_with_l2_action(db_session)
        await CaseRepository(db_session).update_status(case_id, CaseStatus.resolved)
        r = await client.post(
            f"/api/approvals/{case_id}/actions/{action_id}/approve",
            json={"decision": "approved"},
            headers=await login_headers("analyst"),
        )
        assert r.status_code == 400


class _BrokenDBFactory:
    """模拟 DB 不可用: async_session() 进入即抛 RuntimeError"""

    def __call__(self):
        return self

    async def __aenter__(self):
        raise RuntimeError("db down")

    async def __aexit__(self, *args):
        return False


class TestAuthNoSilentFallback:
    """认证路径禁止静默降级 demo 用户 (修复前: DB 异常 → 任何人可用公开口令登录 admin)"""

    async def test_db_error_raises_when_not_mock(self, monkeypatch):
        from app.auth import service as auth_service
        from app.core.config import settings

        monkeypatch.setattr("app.db.database.async_session", _BrokenDBFactory())
        monkeypatch.setattr(settings, "mock_mode", False)
        with pytest.raises(RuntimeError):
            await auth_service.authenticate_user_async("admin", "whatever")

    async def test_db_error_falls_back_only_in_mock_mode(self, monkeypatch):
        """显式 mock 模式 (本地演示) 允许降级 demo 用户"""
        from app.auth import service as auth_service
        from app.core.config import settings

        monkeypatch.setattr("app.db.database.async_session", _BrokenDBFactory())
        monkeypatch.setattr(settings, "mock_mode", True)
        monkeypatch.setattr(settings, "env", "development")
        user = await auth_service.authenticate_user_async("admin", "ChangeMe_123!")
        assert user is not None and user["username"] == "admin"

    async def test_login_returns_503_when_auth_backend_down(self, client, monkeypatch):
        """认证后端异常 → 503 (绝不降级 demo 用户返回 200)"""
        from app.core.config import settings

        async def _boom(username, password):
            raise RuntimeError("db down")

        monkeypatch.setattr(
            "app.auth.service.authenticate_user_async", _boom
        )
        monkeypatch.setattr(settings, "mock_mode", False)
        r = await client.post(
            "/api/auth/login", json={"username": "admin", "password": "ChangeMe_123!"}
        )
        assert r.status_code == 503


class TestHealthInfoExposure:
    """/health 信息收敛 (修复前暴露执行能力清单/限流配置/调度任务)"""

    async def test_health_does_not_leak_internal_details(self, client):
        r = await client.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert "execution" not in body
        assert "rate_limit" not in body
        assert "proactive_scheduler" not in body

    async def test_status_endpoint_requires_auth(self, client):
        r = await client.get("/api/status")
        assert r.status_code == 401

    async def test_status_endpoint_with_auth(self, client):
        r = await client.get("/api/status", headers=await login_headers("admin"))
        assert r.status_code == 200
        assert "execution" in r.json()


class TestCheckpointerApprovalFix:
    """checkpointer 路径审批判定必须读 ApprovalRecord 表

    修复前读 case.approvals dict (从未被填充) → 已批动作被判 pending →
    审批通过后动作永不执行,Case 反被关闭 (AGENTS.md 记录过的 bug 在另一路径复活)。
    """

    async def test_resume_reads_record_table(self, db_session, monkeypatch):
        import app.agents.workflow as wf

        case_id, action_id = await _case_with_l2_action(db_session)
        await ApprovalRecordRepository(db_session).add(
            case_id=case_id,
            action_id=action_id,
            approver_role="incident_commander",
            approver_user="alice",
            decision="approved",
        )
        await ApprovalRecordRepository(db_session).add(
            case_id=case_id,
            action_id=action_id,
            approver_role="approver",
            approver_user="bob",
            decision="approved",
        )

        class _StubWF:
            def __init__(self):
                self.updates: list[dict] = []
                self.invoked = False

            async def aupdate_state(self, config, values):
                self.updates.append(values)

            async def ainvoke(self, *args, **kwargs):
                self.invoked = True

        stub = _StubWF()

        async def _fake_get_wf():
            return stub

        monkeypatch.setattr(wf, "get_checkpointer_workflow", _fake_get_wf)
        await wf.resume_workflow_checkpointer(case_id)

        assert stub.invoked is True
        assert stub.updates, "必须向 checkpointer 同步审批状态"
        assert stub.updates[0]["approval_status"][action_id] == "approved"

    async def test_resume_reads_rejection(self, db_session, monkeypatch):
        import app.agents.workflow as wf

        case_id, action_id = await _case_with_l2_action(db_session)
        await ApprovalRecordRepository(db_session).add(
            case_id=case_id,
            action_id=action_id,
            approver_role="incident_commander",
            approver_user="alice",
            decision="rejected",
        )

        class _StubWF:
            def __init__(self):
                self.updates: list[dict] = []

            async def aupdate_state(self, config, values):
                self.updates.append(values)

            async def ainvoke(self, *args, **kwargs):
                pass

        stub = _StubWF()

        async def _fake_get_wf():
            return stub

        monkeypatch.setattr(wf, "get_checkpointer_workflow", _fake_get_wf)
        await wf.resume_workflow_checkpointer(case_id)
        assert stub.updates[0]["approval_status"][action_id] == "rejected"
