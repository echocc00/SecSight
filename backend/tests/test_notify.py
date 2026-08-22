"""飞书/钉钉通知 + 回调测试"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.integrations.notify import (
    DingtalkNotifier,
    FeishuNotifier,
    notify_approval,
)


class TestFeishuNotifier:
    @pytest.mark.asyncio
    async def test_skips_when_no_webhook(self):
        n = FeishuNotifier(webhook_url="")
        result = await n.send_approval_card("c1", "a1", "isolate_host", "high", "http://x")
        assert result["skipped"] is True

    @pytest.mark.asyncio
    async def test_sends_card(self):
        n = FeishuNotifier(webhook_url="https://open.feishu.cn/open-apis/bot/v2/hook/xxx")
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"code": 0}
        with patch("httpx.AsyncClient") as MockClient:
            instance = MockClient.return_value
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=None)
            instance.post = AsyncMock(return_value=mock_resp)
            result = await n.send_approval_card("c1", "a1", "isolate_host", "high", "http://x")
        assert result["sent"] is True

    def test_build_card_contains_buttons(self):
        n = FeishuNotifier(webhook_url="x")
        card = n._build_card("c1", "a1", "isolate_host", "high", "http://x")
        elements = card["elements"]
        action_el = next(e for e in elements if e["tag"] == "action")
        buttons = action_el["actions"]
        assert len(buttons) == 2  # 批准 + 拒绝
        assert buttons[0]["value"]["decision"] == "approved"
        assert buttons[1]["value"]["decision"] == "rejected"


class TestDingtalkNotifier:
    @pytest.mark.asyncio
    async def test_skips_when_no_webhook(self):
        n = DingtalkNotifier(webhook_url="")
        result = await n.send_approval_card("c1", "a1", "isolate_host", "high", "http://x")
        assert result["skipped"] is True

    @pytest.mark.asyncio
    async def test_sends_card(self):
        n = DingtalkNotifier(webhook_url="https://oapi.dingtalk.com/robot/send?access_token=xxx")
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"errcode": 0}
        with patch("httpx.AsyncClient") as MockClient:
            instance = MockClient.return_value
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=None)
            instance.post = AsyncMock(return_value=mock_resp)
            result = await n.send_approval_card("c1", "a1", "isolate_host", "high", "http://x")
        assert result["sent"] is True


class TestNotifyApproval:
    @pytest.mark.asyncio
    async def test_returns_skipped_when_no_channels(self, monkeypatch):
        monkeypatch.delenv("FEISHU_WEBHOOK_URL", raising=False)
        monkeypatch.delenv("DINGTALK_WEBHOOK_URL", raising=False)
        result = await notify_approval("c1", "a1", "isolate_host", "high", "http://x")
        assert "skipped" in result

    @pytest.mark.asyncio
    async def test_sends_to_feishu_when_configured(self, monkeypatch):
        monkeypatch.setenv("FEISHU_WEBHOOK_URL", "https://open.feishu.cn/hook/x")
        monkeypatch.delenv("DINGTALK_WEBHOOK_URL", raising=False)
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"code": 0}
        with patch("httpx.AsyncClient") as MockClient:
            instance = MockClient.return_value
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=None)
            instance.post = AsyncMock(return_value=mock_resp)
            result = await notify_approval("c1", "a1", "isolate_host", "high", "http://x")
        assert "feishu" in result


class TestNotifyAPI:
    @pytest.mark.asyncio
    async def test_notify_endpoint(self, client, monkeypatch):
        # 建一个待审批 Case
        r = await client.post("/api/alerts/inject", json={"alert_type": "xmrig_process"})
        case_id = r.json()["data"]["case_id"]
        pending = (await client.get(f"/api/approvals/{case_id}/pending")).json()["data"]
        action_id = pending[0]["action_id"]

        monkeypatch.delenv("FEISHU_WEBHOOK_URL", raising=False)
        monkeypatch.delenv("DINGTALK_WEBHOOK_URL", raising=False)
        r = await client.post(f"/api/approvals/{case_id}/actions/{action_id}/notify")
        assert r.status_code == 200
        assert r.json()["success"] is True

    @pytest.mark.asyncio
    async def test_notify_unknown_case_404(self, client):
        r = await client.post("/api/approvals/no-case/actions/no-action/notify")
        assert r.status_code == 404


class TestCallbacks:
    @pytest.mark.asyncio
    async def test_dingtalk_callback_approves(self, client):
        """钉钉 GET 回调: ?case_id=&action_id=&decision=approved"""
        r = await client.post("/api/alerts/inject", json={"alert_type": "xmrig_process"})
        case_id = r.json()["data"]["case_id"]
        pending = (await client.get(f"/api/approvals/{case_id}/pending")).json()["data"]
        action_id = pending[0]["action_id"]

        r = await client.get(
            f"/api/approvals/callback/dingtalk?case_id={case_id}&action_id={action_id}&decision=approved"
        )
        assert r.status_code == 200
        assert r.json()["success"] is True

    @pytest.mark.asyncio
    async def test_feishu_callback_approves(self, client):
        """飞书 POST 回调: {action:{value:{case_id,action_id,decision}}}"""
        r = await client.post("/api/alerts/inject", json={"alert_type": "xmrig_process"})
        case_id = r.json()["data"]["case_id"]
        pending = (await client.get(f"/api/approvals/{case_id}/pending")).json()["data"]
        action_id = pending[0]["action_id"]

        payload = {
            "action": {
                "value": {
                    "case_id": case_id,
                    "action_id": action_id,
                    "decision": "approved",
                }
            }
        }
        r = await client.post("/api/approvals/callback/feishu", json=payload)
        assert r.status_code == 200
        assert r.json()["success"] is True

    @pytest.mark.asyncio
    async def test_feishu_callback_incomplete_data(self, client):
        r = await client.post("/api/approvals/callback/feishu", json={"action": {"value": {}}})
        assert r.json()["success"] is False
