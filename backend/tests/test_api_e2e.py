"""API 端到端集成测试 — 注入→匹配→研判→审批→执行→resolved

P0 鉴权修复后: 业务端点需 JWT,默认用 auth_client (admin);
审批身份由 JWT 服务端映射 / IM 回调签名,见 conftest.sign_approval。
"""
from __future__ import annotations

import pytest

from tests.conftest import approve_action_with_all_roles


async def _inject(client, alert_type: str) -> dict:
    r = await client.post("/api/alerts/inject", json={"alert_type": alert_type})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is True
    return body["data"]


async def _approve_all(client, case_id: str) -> None:
    """多签: 每个审批角色按其映射的签署路径逐一签署 (身份不再客户端自报)"""
    r = await client.get(f"/api/approvals/{case_id}/pending")
    pending = r.json()["data"]
    for action in pending:
        # 高危动作需三签 (ciso_or_delegate)
        roles = action.get("required_roles", ["incident_commander", "approver"])
        await approve_action_with_all_roles(client, case_id, action["action_id"], roles)


class TestHealthAndDiscovery:
    @pytest.mark.asyncio
    async def test_health_returns_ok(self, client):
        r = await client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
        assert r.json()["mock_mode"] is True

    @pytest.mark.asyncio
    async def test_list_playbooks_returns_twenty_two(self, auth_client):
        r = await auth_client.get("/api/playbooks")
        data = r.json()["data"]
        assert len(data) == 22  # 12 → 22 剧本补齐

    @pytest.mark.asyncio
    async def test_list_alert_types(self, auth_client):
        r = await auth_client.get("/api/alerts/types")
        types = r.json()["data"]["types"]
        assert "xmrig_process" in types
        assert "ssh_bruteforce" in types

    @pytest.mark.asyncio
    async def test_inject_unknown_type_fails(self, auth_client):
        r = await auth_client.post("/api/alerts/inject", json={"alert_type": "nonexistent"})
        assert r.json()["success"] is False


class TestCryptominerApprovalFlow:
    """L2 审批路径: 注入→pending→批准→resolved"""

    @pytest.mark.asyncio
    async def test_inject_creates_case_and_matches_playbook(self, auth_client):
        data = await _inject(auth_client, "xmrig_process")
        assert data["playbook_id"] == "pb_cryptominer_v1"
        assert data["severity"] == "high"

    @pytest.mark.asyncio
    async def test_case_reaches_pending_approval_with_judgment(self, auth_client):
        data = await _inject(auth_client, "xmrig_process")
        r = await auth_client.get(f"/api/cases/{data['case_id']}")
        case = r.json()["data"]
        assert case["status"] == "pending_approval"
        assert case["judgment"]["severity"] == "high"
        assert "T1496" in case["judgment"]["ttps"]
        assert len(case["proposed_actions"]) > 0

    @pytest.mark.asyncio
    async def test_full_approval_flow_resolves_case(self, auth_client):
        data = await _inject(auth_client, "xmrig_process")
        case_id = data["case_id"]
        await _approve_all(auth_client, case_id)

        r = await auth_client.get(f"/api/cases/{case_id}")
        case = r.json()["data"]
        assert case["status"] == "resolved"
        assert case["tttr_seconds"] is not None
        assert all(e["status"] == "success" for e in case["execution_log"])
        assert case["evidence_pack_id"] is not None

    @pytest.mark.asyncio
    async def test_evidence_pack_has_timeline_and_mitre(self, auth_client):
        data = await _inject(auth_client, "xmrig_process")
        case_id = data["case_id"]
        await _approve_all(auth_client, case_id)

        r = await auth_client.get(f"/api/evidence/{case_id}")
        assert r.status_code == 200
        ev = r.json()["data"]
        assert len(ev["timeline"]) > 0
        assert "T1496" in str(ev["mitre_mapping"])


class TestAutoExecuteFlow:
    """无 L2 动作的剧本自动执行 (log_compliance)"""

    @pytest.mark.asyncio
    async def test_log_compliance_auto_resolves_without_approval(self, auth_client):
        data = await _inject(auth_client, "log_collection_stopped")
        assert data["playbook_id"] == "pb_log_compliance_v1"

        r = await auth_client.get(f"/api/cases/{data['case_id']}")
        case = r.json()["data"]
        # 无 L2 → 直接执行到 resolved,不停在 pending_approval
        assert case["status"] == "resolved"
        assert all(e["status"] == "success" for e in case["execution_log"])


class TestApprovalValidation:
    @pytest.mark.asyncio
    async def test_approve_nonexistent_case_returns_400(self, auth_client):
        r = await auth_client.post(
            "/api/approvals/no-such-case/actions/x/approve",
            json={"decision": "approved"},
        )
        assert r.status_code == 400

    @pytest.mark.asyncio
    async def test_pending_approvals_lists_only_l2(self, auth_client):
        data = await _inject(auth_client, "xmrig_process")
        r = await auth_client.get(f"/api/approvals/{data['case_id']}/pending")
        pending = r.json()["data"]
        assert len(pending) > 0
        assert all(a["autonomy_level"] == "L2" for a in pending)

    @pytest.mark.asyncio
    async def test_get_nonexistent_case_returns_404(self, auth_client):
        r = await auth_client.get("/api/cases/does-not-exist")
        assert r.status_code == 404


class TestCaseListing:
    @pytest.mark.asyncio
    async def test_list_cases_returns_injected(self, auth_client):
        await _inject(auth_client, "xmrig_process")
        await _inject(auth_client, "ssh_bruteforce")
        r = await auth_client.get("/api/cases")
        cases = r.json()["data"]
        assert len(cases) >= 2

    @pytest.mark.asyncio
    async def test_list_cases_filter_by_status(self, auth_client):
        await _inject(auth_client, "xmrig_process")  # → pending_approval
        r = await auth_client.get("/api/cases", params={"status": "pending_approval"})
        cases = r.json()["data"]
        assert all(c["status"] == "pending_approval" for c in cases)
