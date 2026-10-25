"""飞书/钉钉通知 + 回调测试

P0 后回调走签名校验 (fail-closed):
  - 飞书: headers X-Lark-Request-Timestamp / X-Lark-Signature,
    签名 = base64(hmac_sha256(key=FEISHU_APP_SECRET, msg=f"{ts}\n{raw_body}"))
  - 钉钉: query 参数 timestamp + sign,
    sign = base64(hmac_sha256(key=DINGTALK_APP_SECRET, msg=f"{ts}\n{secret}"))
"""
from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.integrations.notify import (
    DingtalkNotifier,
    FeishuNotifier,
    compute_callback_signature,
    notify_approval,
)
from tests.conftest import DINGTALK_APP_SECRET, FEISHU_APP_SECRET


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
    async def test_notify_endpoint(self, auth_client, monkeypatch):
        # 建一个待审批 Case (业务端点需 JWT)
        r = await auth_client.post("/api/alerts/inject", json={"alert_type": "xmrig_process"})
        case_id = r.json()["data"]["case_id"]
        pending = (await auth_client.get(f"/api/approvals/{case_id}/pending")).json()["data"]
        action_id = pending[0]["action_id"]

        monkeypatch.delenv("FEISHU_WEBHOOK_URL", raising=False)
        monkeypatch.delenv("DINGTALK_WEBHOOK_URL", raising=False)
        r = await auth_client.post(f"/api/approvals/{case_id}/actions/{action_id}/notify")
        assert r.status_code == 200
        assert r.json()["success"] is True

    @pytest.mark.asyncio
    async def test_notify_unknown_case_404(self, auth_client):
        r = await auth_client.post("/api/approvals/no-case/actions/no-action/notify")
        assert r.status_code == 404


def _dingtalk_params() -> dict:
    """钉钉加签 query 参数 (签名内容 = timestamp + 换行 + secret 自身)"""
    ts = str(int(time.time()))
    return {"timestamp": ts, "sign": compute_callback_signature(ts, DINGTALK_APP_SECRET, DINGTALK_APP_SECRET)}


def _feishu_headers(raw_body: str) -> dict:
    """飞书加签 headers (签名内容 = timestamp + 换行 + 原始请求体)"""
    ts = str(int(time.time()))
    return {
        "X-Lark-Request-Timestamp": ts,
        "X-Lark-Signature": compute_callback_signature(ts, raw_body, FEISHU_APP_SECRET),
        "Content-Type": "application/json",
    }


class TestCallbacks:
    @pytest.mark.asyncio
    async def test_dingtalk_callback_approves(self, auth_client, client):
        """钉钉 GET 回调: 合法加签参数 → 签批成功 (身份固定 incident_commander)"""
        r = await auth_client.post("/api/alerts/inject", json={"alert_type": "xmrig_process"})
        case_id = r.json()["data"]["case_id"]
        pending = (await auth_client.get(f"/api/approvals/{case_id}/pending")).json()["data"]
        action_id = pending[0]["action_id"]

        r = await client.get(
            "/api/approvals/callback/dingtalk",
            params={
                "case_id": case_id,
                "action_id": action_id,
                "decision": "approved",
                **_dingtalk_params(),
            },
        )
        assert r.status_code == 200
        assert r.json()["success"] is True

    @pytest.mark.asyncio
    async def test_dingtalk_callback_bad_sign_rejected(self, auth_client, client):
        """签名不符 → success=false (fail-closed,不放行)"""
        r = await auth_client.post("/api/alerts/inject", json={"alert_type": "xmrig_process"})
        case_id = r.json()["data"]["case_id"]
        pending = (await auth_client.get(f"/api/approvals/{case_id}/pending")).json()["data"]
        action_id = pending[0]["action_id"]

        r = await client.get(
            "/api/approvals/callback/dingtalk",
            params={
                "case_id": case_id,
                "action_id": action_id,
                "decision": "approved",
                "timestamp": str(int(time.time())),
                "sign": "forged-signature",
            },
        )
        assert r.json()["success"] is False

    @pytest.mark.asyncio
    async def test_feishu_callback_approves(self, auth_client, client):
        """飞书 POST 回调: 合法签名头 → 签批成功 (签名覆盖原始请求体)"""
        r = await auth_client.post("/api/alerts/inject", json={"alert_type": "xmrig_process"})
        case_id = r.json()["data"]["case_id"]
        pending = (await auth_client.get(f"/api/approvals/{case_id}/pending")).json()["data"]
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
        raw = json.dumps(payload)
        r = await client.post(
            "/api/approvals/callback/feishu", content=raw, headers=_feishu_headers(raw)
        )
        assert r.status_code == 200
        assert r.json()["success"] is True

    @pytest.mark.asyncio
    async def test_feishu_callback_bad_sign_rejected(self, auth_client, client):
        """签名不符 → success=false"""
        payload = {"action": {"value": {}}}
        raw = json.dumps(payload)
        ts = str(int(time.time()))
        r = await client.post(
            "/api/approvals/callback/feishu",
            content=raw,
            headers={
                "X-Lark-Request-Timestamp": ts,
                "X-Lark-Signature": "forged-signature",
                "Content-Type": "application/json",
            },
        )
        assert r.json()["success"] is False

    @pytest.mark.asyncio
    async def test_feishu_callback_incomplete_data(self, auth_client, client):
        """签名合法但回调数据不完整 → success=false"""
        raw = json.dumps({"action": {"value": {}}})
        r = await client.post(
            "/api/approvals/callback/feishu", content=raw, headers=_feishu_headers(raw)
        )
        assert r.json()["success"] is False
