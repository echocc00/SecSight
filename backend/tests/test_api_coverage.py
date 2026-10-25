"""API 路由覆盖率补充: alerts search/poll/devices + approvals records + workflow resume

P0 鉴权修复后: 业务端点需 JWT (auth_client),webhook 端点走共享密钥头。
"""
from __future__ import annotations

import json

import pytest

from tests.conftest import WEBHOOK_TOKEN, approve_action_with_all_roles


async def _inject(client, alert_type: str = "xmrig_process", wait: bool = False) -> dict:
    """wait=True: 同步等编排完成 (断言 approvals/records 等编排产物时必须)"""
    params = {"wait": "true"} if wait else None
    r = await client.post("/api/alerts/inject", json={"alert_type": alert_type}, params=params)
    assert r.status_code == 200, r.text
    return r.json()["data"]


class TestAlertSearch:
    @pytest.mark.asyncio
    async def test_search_pg_fallback_finds_injected_alert(self, auth_client):
        """PG fallback 搜索: OpenSearch 未启用时扫描 Case.alerts"""
        await _inject(auth_client, "xmrig_process")
        r = await auth_client.get("/api/alerts/search", params={"q": "xmrig", "size": 10})
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["source"] == "postgres_fallback"
        assert data["count"] >= 1
        hit = data["hits"][0]
        assert "case_id" in hit
        assert "alert" in hit

    @pytest.mark.asyncio
    async def test_search_pg_fallback_by_ip(self, auth_client):
        await _inject(auth_client, "xmrig_process")
        r = await auth_client.get("/api/alerts/search", params={"q": "192.168"})
        data = r.json()["data"]
        assert data["source"] == "postgres_fallback"

    @pytest.mark.asyncio
    async def test_search_pg_fallback_no_match(self, auth_client):
        await _inject(auth_client, "xmrig_process")
        r = await auth_client.get("/api/alerts/search", params={"q": "nonexistent_term_xyz"})
        data = r.json()["data"]
        assert data["count"] == 0

    @pytest.mark.asyncio
    async def test_search_pg_fallback_respects_size(self, auth_client):
        for _ in range(3):
            await _inject(auth_client, "xmrig_process")
        r = await auth_client.get("/api/alerts/search", params={"q": "xmrig", "size": 2})
        data = r.json()["data"]
        assert data["count"] <= 2

    @pytest.mark.asyncio
    async def test_search_opensearch_path_when_enabled(self, auth_client, monkeypatch):
        """OpenSearch 启用时走 opensearch 路径 (mock client)"""
        from app.core.config import settings
        from unittest.mock import AsyncMock, MagicMock

        monkeypatch.setattr(settings, "enable_opensearch", True)
        mock_client = MagicMock()
        mock_client.search_alerts = AsyncMock(
            return_value=[{"alert_id": "a1", "message": "xmrig hit"}]
        )
        import app.integrations.opensearch as os_mod

        monkeypatch.setattr(os_mod, "get_opensearch", lambda: mock_client)
        r = await auth_client.get("/api/alerts/search", params={"q": "xmrig"})
        data = r.json()["data"]
        assert data["source"] == "opensearch"
        assert data["count"] == 1

    @pytest.mark.asyncio
    async def test_search_opensearch_failure_falls_back_to_pg(self, auth_client, monkeypatch):
        """OpenSearch 启用但调用失败 → 降级 PG"""
        from app.core.config import settings
        from unittest.mock import AsyncMock, MagicMock

        monkeypatch.setattr(settings, "enable_opensearch", True)
        mock_client = MagicMock()
        mock_client.search_alerts = AsyncMock(side_effect=Exception("OS down"))
        import app.integrations.opensearch as os_mod

        monkeypatch.setattr(os_mod, "get_opensearch", lambda: mock_client)
        await _inject(auth_client, "xmrig_process")
        r = await auth_client.get("/api/alerts/search", params={"q": "xmrig"})
        data = r.json()["data"]
        assert data["source"] == "postgres_fallback"


class TestWazuhPoll:
    @pytest.mark.asyncio
    async def test_wazuh_webhook_invalid_payload_returns_error(self, client):
        """webhook 收到无法解析的 payload → 返回 error (webhook 走共享密钥,不走 JWT)"""
        r = await client.post(
            "/api/alerts/wazuh-webhook",
            json={"rule": {"level": "not-a-number"}},
            headers={"X-SecSight-Webhook-Token": WEBHOOK_TOKEN},
        )
        data = r.json()
        assert data["success"] is False
        assert "解析失败" in data["error"]

    @pytest.mark.asyncio
    async def test_poll_file_mode_reads_alerts_json(self, auth_client, tmp_path, monkeypatch):
        """文件模式: WAZUH_ALERTS_JSON 指向测试 JSON"""
        alerts_file = tmp_path / "alerts.json"
        sample = {
            "timestamp": "2026-08-24T12:00:00Z",
            "rule": {"id": "100001", "level": 12, "description": "xmrig",
                     "mitre": {"tactic": ["TA0040"], "id": ["T1496"]}},
            "data": {"srcip": "10.0.0.1", "dstip": "pool.minexmr.com"},
            "agent": {"name": "web-01", "id": "001"},
        }
        alerts_file.write_text(json.dumps(sample), encoding="utf-8")
        from app.core.config import settings

        monkeypatch.setattr(settings, "wazuh_alerts_json", str(alerts_file))
        r = await auth_client.post("/api/alerts/wazuh/poll", params={"limit": 5})
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["polled"] == 1
        assert len(data["cases"]) == 1
        assert data["cases"][0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_poll_api_mode_failure_returns_error(self, auth_client, monkeypatch):
        """API 模式: 无 WAZUH_ALERTS_JSON,连接失败返回 error"""
        from app.core.config import settings

        monkeypatch.setattr(settings, "wazuh_alerts_json", None)
        monkeypatch.setattr(settings, "wazuh_api_url", "http://nonexistent-wazuh:55000")
        r = await auth_client.post("/api/alerts/wazuh/poll")
        data = r.json()
        assert data["success"] is False
        assert "Wazuh" in data["error"]


class TestDevicesWebhook:
    @pytest.mark.asyncio
    async def test_list_supported_devices(self, auth_client):
        r = await auth_client.get("/api/alerts/devices/supported")
        assert r.status_code == 200
        devices = r.json()["data"]["devices"]
        assert len(devices) > 0
        assert "qianxin" in devices
        assert "topsec" in devices

    @pytest.mark.asyncio
    async def test_device_webhook_qianxin_creates_case(self, client):
        """奇安信设备告警 webhook → Case 建立 (webhook 走共享密钥,不走 JWT)"""
        payload = {
            "device_type": "qianxin",
            "alert": {
                "src_ip": "10.0.0.99",
                "dst_ip": "192.168.1.1",
                "rule_name": "可疑挖矿连接",
                "severity": "high",
                "raw": {"process": "xmrig"},
            },
        }
        r = await client.post(
            "/api/alerts/devices/qianxin/webhook",
            json=payload,
            headers={"X-SecSight-Webhook-Token": WEBHOOK_TOKEN},
        )
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["source"] == "qianxin"
        assert data["case_id"]

    @pytest.mark.asyncio
    async def test_device_webhook_unsupported_type_returns_error(self, client):
        r = await client.post(
            "/api/alerts/devices/unknown_vendor/webhook",
            json={},
            headers={"X-SecSight-Webhook-Token": WEBHOOK_TOKEN},
        )
        data = r.json()
        assert data["success"] is False


class TestApprovalRecords:
    @pytest.mark.asyncio
    async def test_list_approval_records_empty(self, auth_client):
        data = await _inject(auth_client, "xmrig_process", wait=True)
        case_id = data["case_id"]
        r = await auth_client.get(f"/api/approvals/{case_id}/records")
        assert r.status_code == 200
        assert r.json()["data"] == []

    @pytest.mark.asyncio
    async def test_list_approval_records_after_approval(self, auth_client):
        data = await _inject(auth_client, "xmrig_process", wait=True)
        case_id = data["case_id"]
        pending = (await auth_client.get(f"/api/approvals/{case_id}/pending")).json()["data"]
        aid = pending[0]["action_id"]
        # admin 登录签出 ciso_or_delegate (身份来自 JWT)
        r = await auth_client.post(
            f"/api/approvals/{case_id}/actions/{aid}/approve",
            json={"decision": "approved", "comment": "ok"},
        )
        assert r.status_code == 200, r.text
        r = await auth_client.get(f"/api/approvals/{case_id}/records")
        records = r.json()["data"]
        assert len(records) >= 1
        assert records[0]["decision"] == "approved"

    @pytest.mark.asyncio
    async def test_pending_shows_missing_roles(self, auth_client):
        """pending 端点返回 required/approved/missing roles"""
        data = await _inject(auth_client, "xmrig_process", wait=True)
        case_id = data["case_id"]
        pending = (await auth_client.get(f"/api/approvals/{case_id}/pending")).json()["data"]
        assert len(pending) > 0
        item = pending[0]
        assert "required_roles" in item
        assert "approved_roles" in item
        assert "missing_roles" in item
        assert len(item["missing_roles"]) > 0  # 未审批时应有缺失

    @pytest.mark.asyncio
    async def test_pending_nonexistent_case_404(self, auth_client):
        r = await auth_client.get("/api/approvals/no-such-case/pending")
        assert r.status_code == 404


class TestWorkflowResume:
    @pytest.mark.asyncio
    async def test_resume_workflow_advances_to_resolved(self, auth_client):
        """resume_workflow: 全部审批角色签批后恢复 → resolved (身份来自 JWT/IM 回调)"""
        from app.agents.workflow import resume_workflow

        data = await _inject(auth_client, "xmrig_process", wait=True)
        case_id = data["case_id"]
        pending = (await auth_client.get(f"/api/approvals/{case_id}/pending")).json()["data"]
        for action in pending:
            roles = action.get("required_roles", ["incident_commander", "approver"])
            await approve_action_with_all_roles(auth_client, case_id, action["action_id"], roles)
        await resume_workflow(case_id)
        case = (await auth_client.get(f"/api/cases/{case_id}")).json()["data"]
        assert case["status"] == "resolved"

    @pytest.mark.asyncio
    async def test_resume_nonexistent_case_returns_silently(self):
        from app.agents.workflow import resume_workflow

        await resume_workflow("nonexistent-case-id")
